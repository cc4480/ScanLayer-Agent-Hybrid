/**
 * Host half of the QNX bundle: the DeepSeek Harness, built for a QNX 8.0 target. One engine — gate, audit chain, checks,
 * verification board — serves the agent tools (qnx_search, qnx_execute) and the sidebar pages, so whatever the model does
 * on the target and whatever the operator does from the page land in the same receipted chain.
 */
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import type {} from '@deepseek-ai/dsh-tools'
import type {} from '@deepseek-ai/dsh-system-prompt'
import type {} from '@deepseek-ai/dsh-host-webserver'
import { startEngine, type Engine, type Running } from './host/engine.ts'
import { registerApi } from './host/http.ts'
import { AUDIT_SKILL, registerGuide, registerTools, running as runningCall } from './host/tools.ts'

/** Plugin configuration, editable from the profile patch. */
export const Config = z.object({
  /** `standin` runs a Linux stand-in target on this machine; `qnx` attaches to the QNX 8.0 QEMU guest. */
  target: z.union([z.const('standin'), z.const('qnx')]).default('standin'),
  /** Engine config file; defaults to the bundle's engine/standin/config.json or engine/qnx/config.json. */
  engineConfig: z.string().default(''),
  /** Destructive tools (slay, kill, shutdown, drivers...): off, ask (each call shows the user an approval prompt), or on. */
  destructive: z.union([z.const('off'), z.const('ask'), z.const('on')]).default('off'),
  /** Whether the agent tools are registered. */
  tools: z.boolean().default(true),
  /** Whether the system prompt gains the QNX section. */
  guide: z.boolean().default(true),
  /** Largest accepted panel API request body, in bytes. */
  maxBodyBytes: z.number().default(256 * 1024),
})

/** The resolved configuration. */
export interface QnxConfig {
  readonly target: 'standin' | 'qnx'
  readonly engineConfig: string
  readonly destructive: 'off' | 'ask' | 'on'
  readonly tools: boolean
  readonly guide: boolean
  readonly maxBodyBytes: number
}

/** Tool names this bundle contributes. */
export const TOOL_NAMES = ['qnx_search', 'qnx_execute'] as const

/** Services the Host half requires; the Web server and skills are read with `ctx.inject` when the profile provides them. */
export const inject = ['tools', 'systemPrompt']

/** The approval service face this bundle uses (the same one dsh-machine-control asks for elevation). */
interface ApprovalFace {
  request(input: { agent: unknown; toolName: string; reason: string }): Promise<string>
}

/**
 * Approve one destructive call. A run from the operator's own page is the operator's action. The agent's call asks the
 * user through the Harness approval prompt; with no prompt available, the answer is no (fail closed).
 */
function approver(ctx: Context): (request: { seat: string; tool: string; argv: string[] }) => Promise<{ approved: boolean; by?: string; reason?: string }> {
  return async ({ seat, tool, argv }) => {
    if (seat === 'operator') return { approved: true, by: 'operator (QNX page)' }
    const approval = ctx.get('approval') as ApprovalFace | undefined
    const agents = ctx.get('agents') as { list(): unknown[] } | undefined
    const agent = runningCall.agent ?? agents?.list()[0]
    if (approval === undefined || agent === undefined) return { approved: false, reason: 'no approval prompt is available' }
    const outcome = await approval.request({ agent, toolName: `qnx: ${tool}`, reason: `The agent wants to run a destructive command on the QNX target:\n\n${argv.join(' ')}\n\nIt runs once, and the decision is recorded in the audit chain.` })
    return outcome === 'allowed-once' ? { approved: true, by: 'user (approval prompt)' } : { approved: false, reason: `the user answered ${outcome}` }
  }
}

/**
 * Apply the Host half.
 * @param ctx - the plugin context.
 * @param config - the plugin configuration.
 */
export function apply(ctx: Context, config: QnxConfig): void {
  let running: Running | undefined
  let failure: string | undefined
  const engine = (): Engine | undefined => running?.engine

  ctx.effect(() => {
    let disposed = false
    startEngine({ target: config.target, config: config.engineConfig === '' ? undefined : config.engineConfig, destructive: config.destructive, approve: approver(ctx), logger: ctx.logger }).then(
      r => {
        if (disposed) { void r.stop(); return }
        running = r
      },
      error => {
        failure = error instanceof Error ? error.message : String(error)
        ctx.logger.warn('qnx: engine did not start: %s', failure)
      },
    )
    return () => {
      disposed = true
      const r = running
      running = undefined
      void r?.stop()
    }
  }, 'qnx: engine')

  ctx.inject(['webServer'], child => {
    child.effect(
      () => registerApi({
        ctx,
        webServer: child.webServer,
        engine,
        engineError: () => failure,
        target: config.target,
        mcpUrl: () => running?.mcpUrl,
        maxBodyBytes: config.maxBodyBytes,
      }),
      'qnx: panel API',
    )
  })

  if (config.tools) {
    ctx.effect(() => {
      const disposers = registerTools(ctx, engine)
      return () => { for (const dispose of disposers) dispose() }
    }, 'qnx: tools')
    if (config.guide) ctx.effect(() => registerGuide(ctx), 'qnx: guide')
    ctx.inject(['skills'], child => {
      const skills = (child as unknown as { skills: { register(skill: typeof AUDIT_SKILL & { source: 'runtime' }): () => void } }).skills
      child.effect(() => skills.register({ ...AUDIT_SKILL, source: 'runtime' }), 'qnx: audit skill')
    })
  }
  ctx.logger.info('qnx bundle applied: %d tools, three sidebar pages, %s target', TOOL_NAMES.length, config.target)
}
