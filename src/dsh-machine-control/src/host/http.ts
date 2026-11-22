/**
 * The loopback panel API: same-origin JSON routes under `/machine-control/api` that the browser panels read, plus the
 * quit-plan-file write the overview page's session control uses. Every route answers only a same-origin request from this
 * page, because it reports the machine's state and starts a quit.
 */
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Context } from '@deepseek-ai/cordis'
import type { PanelData, PageId } from '../types.ts'
import { PAGES } from '../types.ts'
import type { Executor } from './exec.ts'
import { collectPage } from './queries.ts'
import { PANEL_OPERATIONS } from './actions.ts'
import { PLAN_ACTIONS, parsePlan } from './plan.ts'

/** The Web server face this module needs; typed structurally so the bundle carries no dependency on its package. */
interface WebServerFace {
  getOrigin(): string
  register(route: {
    kind: 'prefix'
    path: string
    auth?: 'anonymous' | 'required' | 'deny'
    handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>
  }): () => void
}

/** What the API serves. */
export interface ApiOptions {
  readonly ctx: Context
  readonly webServer: WebServerFace
  readonly exec: Executor
  /** Largest rows kept per table. */
  readonly rowCap: number
  /** Largest accepted request body, in bytes. */
  readonly maxBodyBytes: number
  /** Largest output a panel action reports back, in characters. */
  readonly maxOutputChars: number
  /** Default deadline for a panel action. */
  readonly timeoutMs: number
}

/** The answer to one panel action. */
interface ActionReport {
  readonly op: string
  readonly title: string
  readonly exitCode: number | null
  readonly stdout: string
  readonly stderr: string
  readonly truncated: boolean
}

/** A client-facing failure with its HTTP status. */
class ApiError extends Error {
  constructor(readonly status: 400 | 403 | 404 | 405, message: string) {
    super(message)
  }
}

/** Write one JSON answer. */
function json(res: ServerResponse, status: number, value: unknown): void {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  })
  res.end(JSON.stringify(value))
}

/** Read a JSON request body no larger than the limit. */
async function readBody(req: IncomingMessage, maxBytes: number): Promise<unknown> {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of req) {
    const bytes = Buffer.from(chunk as Uint8Array)
    size += bytes.length
    if (size > maxBytes) throw new ApiError(400, `The request body exceeds ${String(maxBytes)} bytes.`)
    chunks.push(bytes)
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown
  } catch {
    throw new ApiError(400, 'The request body is not JSON.')
  }
}

/**
 * Check that a request comes from this page: the Host header names the listening address and the request is not
 * cross-site. A same-origin fetch from the page sends either no Origin or the page's own origin.
 * @param req - the incoming request.
 * @param port - the listening port.
 * @returns whether the request may be served.
 */
function sameOrigin(req: IncomingMessage, port: number): boolean {
  const host = req.headers.host
  if (host !== `127.0.0.1:${String(port)}` && host !== `localhost:${String(port)}`) return false
  const origin = req.headers.origin
  return origin === undefined || origin === `http://${host}`
}

/** Resolve the listening port from the Web server origin. */
function portOf(webServer: WebServerFace): number | undefined {
  try {
    return Number(new URL(webServer.getOrigin()).port) || undefined
  } catch {
    return undefined
  }
}

/** Map a thrown error to an answer. */
function failure(error: unknown): [number, { error: string }] {
  if (error instanceof ApiError) return [error.status, { error: error.message }]
  return [500, { error: error instanceof Error ? error.message : String(error) }]
}

/**
 * Absolute path of the quit plan file. The Host owns it: a page-supplied path is never trusted, and the location must be a
 * real directory rather than an unexpanded `%LOCALAPPDATA%` token.
 * @returns the plan file's absolute path.
 */
export function quitPlanPath(): string {
  const base = process.env.LOCALAPPDATA ?? process.env.USERPROFILE ?? process.cwd()
  return `${base}\\dsh-machine-control-quit.json`
}

/** Write the quit plan file from the plan fields the page chose. */
async function writeQuitPlan(options: ApiOptions, body: unknown): Promise<{ readonly saved: true; readonly path: string; readonly plan: unknown }> {
  const input = typeof body === 'object' && body !== null ? body as { action?: unknown; name?: unknown } : {}
  if (typeof input.action !== 'string' || input.action.trim() === '') throw new ApiError(400, 'An action is required.')
  if (!(PLAN_ACTIONS as readonly string[]).includes(input.action)) {
    throw new ApiError(400, `The action must be one of: ${PLAN_ACTIONS.join(', ')}.`)
  }
  if (input.name !== undefined && typeof input.name !== 'string') throw new ApiError(400, 'The name must be a string.')
  const name = typeof input.name === 'string' && input.name.trim() !== '' ? input.name.trim() : undefined
  const plan = parsePlan({ kind: name ?? input.action, ...name === undefined ? {} : { name }, action: input.action, delaySeconds: 30 })
  const path = quitPlanPath()
  const { mkdir, writeFile } = await import('node:fs/promises')
  const { dirname } = await import('node:path')
  await mkdir(dirname(path), { recursive: true })
  await writeFile(path, JSON.stringify(plan, undefined, 2), 'utf8')
  options.ctx.logger.info('machine-control: wrote the quit plan to %s', path)
  return { saved: true, path, plan }
}

/**
 * Run one whitelisted panel operation: the same command the matching agent tool runs.
 * @param options - the executor and its limits.
 * @param body - the request body, holding `op` and its `params`.
 * @returns the exit status and the trimmed output.
 * @throws ApiError when the operation is unknown or its arguments are unusable.
 */
async function runAction(options: ApiOptions, body: unknown): Promise<ActionReport> {
  const input = typeof body === 'object' && body !== null ? body as { op?: unknown; params?: unknown } : {}
  const op = typeof input.op === 'string' ? input.op : ''
  const operation = Object.prototype.hasOwnProperty.call(PANEL_OPERATIONS, op) ? PANEL_OPERATIONS[op] : undefined
  if (operation === undefined) throw new ApiError(400, `Unknown operation: ${op === '' ? '(none)' : op}.`)
  const params = typeof input.params === 'object' && input.params !== null ? input.params as Record<string, unknown> : {}
  let command: string
  try {
    command = operation.command(params)
  } catch (error) {
    throw new ApiError(400, error instanceof Error ? error.message : String(error))
  }
  const outcome = await options.exec.run({ command, timeoutMs: options.timeoutMs })
  const trim = (value: string): string => value.length <= options.maxOutputChars ? value : value.slice(0, options.maxOutputChars)
  options.ctx.logger.info('machine-control: the panel ran %s (exit %s)', op, String(outcome.exitCode))
  return {
    op,
    title: operation.title,
    exitCode: outcome.exitCode,
    stdout: trim(outcome.stdout),
    stderr: trim(outcome.stderr),
    truncated: outcome.stdout.length > options.maxOutputChars || outcome.stderr.length > options.maxOutputChars,
  }
}

/** Route table: `METHOD path` to a handler. */
type Routes = Record<string, (input: { readonly params: Record<string, string>; readonly query: URLSearchParams; readonly req: IncomingMessage }) => Promise<unknown>>

function routes(options: ApiOptions): Routes {
  return {
    'GET status': async () => ({ sandbox: options.exec.sandbox, cwd: options.exec.cwd, pages: PAGES, quitPlanPath: quitPlanPath() }),
    'GET page/:page': async ({ params }) => {
      const page = PAGES.find(candidate => candidate === params.page)
      if (page === undefined) throw new ApiError(404, `Unknown page: ${String(params.page)}`)
      const data: PanelData = await collectPage(options.exec, page as PageId, options.rowCap)
      return data
    },
    'POST quit-plan': async ({ req }) => writeQuitPlan(options, await readBody(req, options.maxBodyBytes)),
    'POST action': async ({ req }) => runAction(options, await readBody(req, options.maxBodyBytes)),
  }
}

/**
 * Register the panel API.
 * @param options - the executor, limits, and context.
 * @returns the disposer removing the route.
 */
export function registerApi(options: ApiOptions): () => void {
  const table = routes(options)
  return options.webServer.register({
    kind: 'prefix',
    path: '/machine-control',
    auth: 'required',
    handler: async (req, res) => {
      const url = new URL(req.url ?? '/', 'http://localhost')
      const prefix = '/machine-control/api/'
      if (!url.pathname.startsWith(prefix)) {
        res.writeHead(404)
        res.end()
        return
      }
      const port = portOf(options.webServer)
      if (port === undefined || !sameOrigin(req, port)) {
        json(res, 403, { error: 'A same-origin request is required.' })
        return
      }
      const verb = (req.method ?? 'GET').toUpperCase()
      const segments = url.pathname.slice(prefix.length).split('/').filter(segment => segment !== '')
      try {
        for (const [route, run] of Object.entries(table)) {
          const [method, path] = route.split(' ') as [string, string]
          const pattern = path.split('/')
          if (method !== verb || pattern.length !== segments.length) continue
          const params: Record<string, string> = {}
          let matched = true
          for (const [index, part] of pattern.entries()) {
            const segment = segments[index] ?? ''
            if (part.startsWith(':')) {
              try {
                params[part.slice(1)] = decodeURIComponent(segment)
              } catch {
                matched = false
                break
              }
            } else if (part !== segment) {
              matched = false
              break
            }
          }
          if (!matched) continue
          json(res, 200, await run({ params, query: url.searchParams, req }))
          return
        }
        throw new ApiError(404, `Unknown operation: ${verb} /${segments.join('/')}`)
      } catch (error) {
        json(res, ...failure(error))
      }
    },
  })
}
