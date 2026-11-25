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
import { registerGuide, registerTools } from './host/tools.ts'

/** Plugin configuration, editable from the profile patch. */
export const Config = z.object({
  /** `standin` runs a Linux stand-in target on this machine; `qnx` attaches to the QNX 8.0 QEMU guest. */
  target: z.union([z.const('standin'), z.const('qnx')]).default('standin'),
  /** Engine config file; defaults to the bundle's engine/standin/config.json or engine/qnx/config.json. */
  engineConfig: z.string().default(''),
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
  readonly tools: boolean
  readonly guide: boolean
  readonly maxBodyBytes: number
}

/** Tool names this bundle contributes. */
export const TOOL_NAMES = ['qnx_search', 'qnx_execute'] as const

/** Services the Host half requires; the Web server is read with `ctx.inject` when a Web profile provides it. */
export const inject = ['tools', 'systemPrompt']

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
    startEngine({ target: config.target, config: config.engineConfig === '' ? undefined : config.engineConfig, logger: ctx.logger }).then(
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
  }
  ctx.logger.info('qnx bundle applied: %d tools, three sidebar pages, %s target', TOOL_NAMES.length, config.target)
}
