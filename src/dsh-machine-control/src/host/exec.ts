/**
 * Run commands on this machine. Each command runs through a PowerShell process started by the Harness subprocess seam, so
 * the same execution world, sandbox reporting, and teardown that own the shell tool also own these processes.
 */
import type { Context } from '@deepseek-ai/cordis'
import type { SandboxMode } from '@deepseek-ai/dsh-sandbox'
import type {} from '@deepseek-ai/dsh-subprocess'

/** One command request. */
export interface MachineCommand {
  readonly command: string
  /** Deadline in milliseconds, capped by the plugin's `maxTimeoutMs`. */
  readonly timeoutMs?: number | undefined
  /** Working directory for the command. */
  readonly workdir?: string | undefined
  /** Cancellation; kills the command. */
  readonly signal?: AbortSignal | undefined
}

/** Exit status and split streams of one command. */
export interface CommandOutcome {
  readonly exitCode: number | null
  readonly stdout: string
  /** Standard error, plus the reason when the command timed out or was stopped. */
  readonly stderr: string
  readonly timedOut: boolean
}

/** Runs machine commands for the panels and tools. */
export interface Executor {
  /**
   * Run one command to completion.
   * @param input - the command, its deadline, working directory, and cancellation.
   * @returns the captured streams; failures are reported in the outcome, never thrown.
   */
  run(input: MachineCommand): Promise<CommandOutcome>
  /** The sandbox mode every command reports. */
  readonly sandbox: SandboxMode
  /** The working directory a command without its own runs in. */
  readonly cwd: string
}

/** Largest captured stream kept per command, in bytes. */
const MAX_OUTPUT_BYTES = 4 * 1024 * 1024

/** Encode PowerShell text for `-EncodedCommand`, which needs UTF-16LE base64. */
function encoded(command: string): string {
  return Buffer.from(command, 'utf16le').toString('base64')
}

/**
 * Quiet prelude prepended to every command: module auto-loading writes CLIXML progress records to stderr, which would
 * otherwise appear as noise beside real errors.
 */
const PRELUDE = "$ProgressPreference = 'SilentlyContinue'; "

/**
 * Drop CLIXML progress envelopes from captured stderr, keeping anything else.
 * @param stderr - the captured standard error.
 * @returns the error text with progress records removed.
 */
function withoutProgress(stderr: string): string {
  const start = stderr.indexOf('#< CLIXML')
  if (start < 0) return stderr
  const before = stderr.slice(0, start).trim()
  const envelope = stderr.slice(start)
  const payloads = [...envelope.matchAll(/<AV>([^<]*)<\/AV>/gu)].map(match => match[1]).filter(part => part !== undefined)
  const meaningful = payloads.filter(part => part !== '' && !/^Preparing modules for first use\.?$/iu.test(part))
  return [before, ...meaningful].filter(part => part !== '').join('\n')
}

/**
 * Create the executor.
 * @param ctx - the plugin context; `ctx.subprocess` starts the PowerShell process.
 * @param sandbox - the sandbox mode callers see.
 * @param cwd - the default working directory.
 * @returns the executor.
 */
export function machineExecutor(ctx: Context, sandbox: SandboxMode, cwd: string): Executor {
  return {
    sandbox,
    cwd,
    async run(input) {
      const timeoutMs = input.timeoutMs ?? 30_000
      const deadline = new AbortController()
      const timer = setTimeout(() => { deadline.abort(new Error('timeout')) }, timeoutMs)
      const signal = input.signal === undefined ? deadline.signal : AbortSignal.any([input.signal, deadline.signal])
      const handle = ctx.subprocess.spawn({
        argv: ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded(`${PRELUDE}${input.command}`)],
        cwd: input.workdir ?? cwd,
        stdio: {
          stdin: 'ignore',
          stdout: { maxBytes: MAX_OUTPUT_BYTES },
          stderr: { maxBytes: MAX_OUTPUT_BYTES },
        },
        graceMs: 2_000,
        signal,
      })
      let outcome: { exitCode: number | null } = { exitCode: null }
      try {
        outcome = await handle.done
      } finally {
        clearTimeout(timer)
      }
      const read = (reader: { readFrom(fromByte: number): { text: string } } | undefined): string =>
        reader === undefined ? '' : reader.readFrom(0).text
      const timedOut = deadline.signal.aborted && !(input.signal?.aborted ?? false)
      const stopped = timedOut ? `\n[stopped after ${String(timeoutMs)} ms]` : ''
      return {
        exitCode: outcome.exitCode,
        stdout: read(handle.collected.stdout),
        stderr: `${withoutProgress(read(handle.collected.stderr))}${stopped}`,
        timedOut,
      }
    },
  }
}
