/**
 * Host half of the machine control bundle: one executor and one set of queries serve the two sidebar panels and the agent
 * tools, so the same command or change is reachable from the UI and from the model.
 */
import { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import type { SandboxMode } from '@deepseek-ai/dsh-sandbox'
import type {} from '@deepseek-ai/dsh-tools'
import type {} from '@deepseek-ai/dsh-system-prompt'
import type {} from '@deepseek-ai/dsh-host-webserver'
import { machineExecutor, type Executor } from './host/exec.ts'
import { registerApi } from './host/http.ts'
import { registerGuide, registerTools } from './host/tools.ts'
import { applyPlanFile } from './host/apply-plan.ts'

/** Plugin configuration, editable from the profile patch. */
export const Config = z.object({
  /** Sandbox mode reported to callers and used for the panels' own queries. */
  sandbox: z.union([z.const('read-only'), z.const('workspace-write'), z.const('danger-full-access')]).default('danger-full-access'),
  /** Directory the panel queries and commands without their own working directory run in. */
  cwd: z.string().default(process.cwd()),
  /** Default command deadline in milliseconds. */
  timeoutMs: z.number().default(60_000),
  /** Largest deadline a tool call may ask for, in milliseconds. */
  maxTimeoutMs: z.number().default(1_800_000),
  /** Largest output a tool reports, in characters. */
  maxOutputChars: z.number().default(60_000),
  /** Largest number of rows a panel or table keeps. */
  rowCap: z.number().default(300),
  /** Largest accepted panel API request body, in bytes. */
  maxBodyBytes: z.number().default(256 * 1024),
  /** Whether the agent tools are registered. */
  tools: z.boolean().default(true),
  /** Whether the system prompt gains the machine administration catalog. */
  guide: z.boolean().default(true),
})

/** The resolved configuration. */
export interface ControlConfig {
  readonly sandbox: 'read-only' | 'workspace-write' | 'danger-full-access'
  readonly cwd: string
  readonly timeoutMs: number
  readonly maxTimeoutMs: number
  readonly maxOutputChars: number
  readonly rowCap: number
  readonly maxBodyBytes: number
  readonly tools: boolean
  readonly guide: boolean
}

/** Tool names this bundle contributes. */
export const TOOL_NAMES = [
  'machine_shell',
  'machine_sysinfo',
  'machine_process',
  'machine_service',
  'machine_scheduled_task',
  'machine_network',
  'machine_security',
  'machine_packages',
  'machine_disk',
  'machine_maintenance',
  'machine_event-logs',
] as const

/** Services the Host half requires; the Web server and approval service are optional and read with `ctx.get`. */
export const inject = ['tools', 'systemPrompt', 'subprocess']

/**
 * Apply the Host half.
 * @param ctx - the plugin context.
 * @param config - the plugin configuration.
 */
export function apply(ctx: Context, config: ControlConfig): void {
  const exec: Executor = machineExecutor(ctx, config.sandbox as SandboxMode, config.cwd)
  const webServer = ctx.get('webServer')
  if (webServer !== undefined) {
    ctx.effect(() => registerApi({ webServer, ctx, exec, rowCap: config.rowCap, maxBodyBytes: config.maxBodyBytes, maxOutputChars: config.maxOutputChars, timeoutMs: config.timeoutMs }), 'machine-control: panel API')
  }
  if (config.tools) {
    const limits = {
      timeoutMs: config.timeoutMs,
      maxTimeoutMs: config.maxTimeoutMs,
      maxOutputChars: config.maxOutputChars,
      rowCap: config.rowCap,
      guide: config.guide,
    }
    ctx.effect(() => {
      const disposers = registerTools(ctx, exec, limits)
      return () => { for (const dispose of disposers) dispose() }
    }, 'machine-control: tools')
    ctx.effect(() => registerGuide(ctx, limits), 'machine-control: guide')
  }
  // `dsh-machine-control apply-plan <plan>` runs one approved plan after the one-shot plugin that wrote it ended.
  if (process.argv[2] === 'apply-plan' || process.argv.includes('apply-plan')) {
    const index = process.argv.indexOf('apply-plan')
    const planPath = process.argv[index + 1]
    if (planPath !== undefined) {
      void applyPlanFile(exec, planPath).then(
        result => { ctx.logger.info('machine-control: applied %s (%s)', result.plan.action, String(result.outcome.exitCode)) },
        error => { ctx.logger.error('machine-control: plan failed: %s', String(error)) },
      )
    }
  }
  ctx.logger.info('machine control ready: %d tools, two sidebar panels', TOOL_NAMES.length)
}

export { applyPlanFile }
