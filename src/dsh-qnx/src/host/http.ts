/**
 * The panel API under `/qnx/api`: same-origin JSON routes the sidebar pages read and act through. The route is owner-only
 * (`auth: 'required'`) and also refuses a request whose Host or Origin does not name this page. The operation set is
 * closed: there is no general command route. Running a program from the page goes through exactly the same gate, audit
 * chain and limits as the agent's qnx_execute, recorded under the `operator` seat.
 */
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Context } from '@deepseek-ai/cordis'
import type { Engine } from './engine.ts'

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

/** What the API needs. */
export interface ApiOptions {
  readonly ctx: Context
  readonly webServer: WebServerFace
  /** The running engine, or the reason it is not running. */
  readonly engine: () => Engine | undefined
  readonly engineError: () => string | undefined
  readonly target: 'standin' | 'qnx'
  readonly mcpUrl: () => string | undefined
  readonly maxBodyBytes: number
}

/** The seat the sidebar pages act as. */
const PANEL_SEAT = 'operator'

class ApiError extends Error {
  constructor(readonly status: 400 | 403 | 404 | 409 | 503, message: string) {
    super(message)
  }
}

function json(res: ServerResponse, status: number, value: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' })
  res.end(JSON.stringify(value))
}

async function readBody(req: IncomingMessage, maxBytes: number): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of req) {
    const bytes = Buffer.from(chunk as Uint8Array)
    size += bytes.length
    if (size > maxBytes) throw new ApiError(400, `The request body exceeds ${String(maxBytes)} bytes.`)
    chunks.push(bytes)
  }
  const text = Buffer.concat(chunks).toString('utf8')
  if (text.trim() === '') return {}
  try {
    const value = JSON.parse(text) as unknown
    return typeof value === 'object' && value !== null ? value as Record<string, unknown> : {}
  } catch {
    throw new ApiError(400, 'The request body is not JSON.')
  }
}

function sameOrigin(req: IncomingMessage, port: number): boolean {
  const host = req.headers.host
  if (host !== `127.0.0.1:${String(port)}` && host !== `localhost:${String(port)}`) return false
  const origin = req.headers.origin
  return origin === undefined || origin === `http://${host}`
}

function portOf(webServer: WebServerFace): number | undefined {
  try { return Number(new URL(webServer.getOrigin()).port) || undefined } catch { return undefined }
}

/**
 * Claims the page can add to the board to show the verifier refusing to be fooled. They are planted on purpose and named
 * so: a phantom listener, a phantom process, and a claim that cites a receipt the chain never issued.
 */
function plantedClaims(evidence: unknown): unknown[] {
  return [
    { id: 'planted-false-listener-5555', severity: 'high', title: 'Planted false claim: something listens on tcp/5555', evidence, reproduce: { tool: 'netstat', args: ['-an'], expect: { type: 'listener', proto: 'tcp', port: 5555 } } },
    { id: 'planted-false-ghostd', severity: 'medium', title: 'Planted false claim: ghostd is running', evidence, reproduce: { tool: 'ps', args: ['-A', '-o', 'pid=', '-o', 'comm='], expect: { type: 'process', name: 'ghostd' } } },
    { id: 'planted-false-forged-receipt', severity: 'high', title: 'Planted false claim: cites a receipt that was never issued', evidence: [{ receipt: 'f'.repeat(64), tool: 'netstat', args: ['-an'], excerpt: '' }], reproduce: { tool: 'netstat', args: ['-an'], expect: { type: 'listener', proto: 'tcp', port: 4444 } } },
  ]
}

type Handler = (input: { query: URLSearchParams; req: IncomingMessage; res: ServerResponse; engine: Engine }) => Promise<unknown>

function routes(options: ApiOptions): Record<string, Handler> {
  let lastScan: { findings: Array<{ evidence?: unknown }> } | undefined
  return {
    'GET state': async ({ engine }) => ({ ...engine.state(PANEL_SEAT), bundle: { target: options.target, mcp: options.mcpUrl() } }),
    'GET audit': async ({ engine, query }) => ({ entries: engine.audit.since(Number(query.get('after') ?? 0), Math.min(2000, Number(query.get('limit') ?? 500))) }),
    'GET search': async ({ engine, query }) => engine.search({ query: query.get('q') ?? '', limit: 20 }),
    'POST execute': async ({ engine, req }) => {
      const body = await readBody(req, options.maxBodyBytes)
      if (typeof body.program !== 'string') throw new ApiError(400, 'program must be a string.')
      const r = await engine.execute(PANEL_SEAT, body.program, typeof body.timeout_ms === 'number' ? body.timeout_ms : 60000)
      if (r.invalid !== undefined) throw new ApiError(400, r.invalid)
      return r
    },
    'POST checks': async ({ engine }) => {
      const report = await engine.runChecks(PANEL_SEAT)
      lastScan = report as unknown as typeof lastScan
      return report
    },
    'GET board': async ({ engine }) => engine.board.read(),
    'POST board/post': async ({ engine }) => {
      if (lastScan === undefined) throw new ApiError(409, 'Run the checks first: there are no findings to post.')
      const r = engine.board.post(lastScan, PANEL_SEAT)
      engine.audit.append({ kind: 'board_post', seat: PANEL_SEAT, added: r.added })
      return r
    },
    'POST board/plant': async ({ engine }) => {
      const evidence = lastScan?.findings[0]?.evidence ?? []
      const r = engine.board.postClaims(plantedClaims(evidence), PANEL_SEAT, 'planted-false')
      engine.audit.append({ kind: 'board_post', seat: PANEL_SEAT, added: r.added, planted: true })
      return r
    },
    'POST board/reset': async ({ engine }) => {
      engine.board.write({ claims: [] })
      engine.audit.append({ kind: 'board_reset', seat: PANEL_SEAT })
      return { ok: true }
    },
    'POST smith': async ({ engine }) => {
      engine.startSmith(PANEL_SEAT, options.mcpUrl())
      return { started: true }
    },
    'POST report/verified': async ({ engine }) => engine.verifiedReport(PANEL_SEAT),
    'GET seal': async ({ engine }) => engine.seal(),
    'POST engagements/add': async ({ engine, req }) => {
      const b = await readBody(req, options.maxBodyBytes)
      const targets = Array.isArray(b.targets) ? b.targets.filter((t): t is string => typeof t === 'string') : []
      try { return engine.addEngagement(PANEL_SEAT, { id: String(b.id ?? ''), targets, hours: typeof b.hours === 'number' ? b.hours : 24 }) } catch (error) { throw new ApiError(400, (error as Error).message) }
    },
    'POST engagements/revoke': async ({ engine, req }) => {
      const b = await readBody(req, options.maxBodyBytes)
      if (typeof b.id !== 'string') throw new ApiError(400, 'id is required.')
      return engine.revokeEngagement(PANEL_SEAT, b.id)
    },
    'POST catalog/refresh': async ({ engine }) => {
      try { return await engine.refreshCatalog(PANEL_SEAT) } catch (error) { throw new ApiError(409, (error as Error).message) }
    },
  }
}

/** Stream the audit chain as NDJSON: everything after `after`, then each new line as it is appended. */
function stream(engine: Engine, req: IncomingMessage, res: ServerResponse, after: number): void {
  res.writeHead(200, { 'content-type': 'application/x-ndjson', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' })
  for (const entry of engine.audit.since(after, 5000)) res.write(JSON.stringify(entry) + '\n')
  const on = (entry: Record<string, unknown>): void => { res.write(JSON.stringify(entry) + '\n') }
  engine.audit.on('entry', on)
  const keepalive = setInterval(() => { res.write('{"kind":"keepalive"}\n') }, 15000)
  req.on('close', () => { engine.audit.off('entry', on); clearInterval(keepalive) })
}

/**
 * Register the panel API.
 * @param options - the engine and limits.
 * @returns the disposer removing the route.
 */
export function registerApi(options: ApiOptions): () => void {
  const table = routes(options)
  return options.webServer.register({
    kind: 'prefix',
    path: '/qnx',
    auth: 'required',
    handler: async (req, res) => {
      const url = new URL(req.url ?? '/', 'http://localhost')
      const prefix = '/qnx/api/'
      if (!url.pathname.startsWith(prefix)) { res.writeHead(404); res.end(); return }
      const port = portOf(options.webServer)
      if (port === undefined || !sameOrigin(req, port)) { json(res, 403, { error: 'A same-origin request is required.' }); return }
      const path = url.pathname.slice(prefix.length).replace(/\/+$/, '')
      const verb = (req.method ?? 'GET').toUpperCase()
      const engine = options.engine()
      if (verb === 'GET' && path === 'health') { json(res, 200, { running: engine !== undefined, error: options.engineError() ?? null, target: options.target }); return }
      if (engine === undefined) { json(res, 503, { error: options.engineError() ?? 'The QNX engine is starting.' }); return }
      if (verb === 'GET' && path === 'audit/stream') { stream(engine, req, res, Number(url.searchParams.get('after') ?? 0)); return }
      const report = /^report\/(scan|verified)\.html$/.exec(path)
      if (verb === 'GET' && report !== null) {
        let html: string
        try { html = engine.reportHtml(report[1] as 'scan' | 'verified') } catch { json(res, 404, { error: report[1] === 'scan' ? 'No scan report yet: run the checks.' : 'No verified report yet: sign one on the Scan & verify page.' }); return }
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'self'" })
        res.end(html)
        return
      }
      const handler = table[`${verb} ${path}`]
      if (handler === undefined) { json(res, 404, { error: `No route ${verb} ${path}.` }); return }
      try {
        json(res, 200, await handler({ query: url.searchParams, req, res, engine }))
      } catch (error) {
        if (error instanceof ApiError) json(res, error.status, { error: error.message })
        else json(res, 500, { error: error instanceof Error ? error.message : String(error) })
      }
    },
  })
}
