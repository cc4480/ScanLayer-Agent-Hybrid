/**
 * Boots the QNX agent engine inside the Harness Host: the gate, the audit chain, the checks and the verification board
 * all run in this process, and the agent tools and sidebar pages call them directly. The engine also listens on a loopback
 * MCP port so Agent Smith's seat (its own process, its own token) and outside MCP clients reach the same chain.
 *
 * `target: standin` brings up a Linux stand-in target on this machine (builds and starts the runner, takes the inventory,
 * writes a baseline manifest) so the whole flow runs before the QNX SDP is installed. `target: qnx` expects the runner in
 * the QNX 8.0 QEMU guest, forwarded to `runner.port` on this host (see engine/image/run-qemu.sh).
 */
import { createRequire } from 'node:module'
import { spawn, spawnSync, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Server } from 'node:http'

const here = dirname(fileURLToPath(import.meta.url))
/** The engine directory shipped next to `lib/` in this package. */
export const ENGINE_DIR = resolve(here, '..', 'engine')

/** The engine's public face, as `engine/gateway/server.js` returns it. */
export interface Engine {
  readonly server: Server
  readonly destructiveMode: 'off' | 'ask' | 'on'
  catalog(): { allowlist(extra?: string[]): string }
  addEngagement(seat: string, input: { id: string; targets: string[]; hours?: number }): { id: string; targets: string[]; expires_at: string }
  revokeEngagement(seat: string, id: string): { removed: boolean }
  reportHtml(kind: 'scan' | 'verified'): string
  refreshCatalog(seat: string): Promise<{ tools: number; callable: number; hash: string }>
  readonly cfg: { state_dir: string; listen: { host: string; port: number }; catalog: string; runner: Record<string, unknown>; inventory_path?: string }
  execute(seat: string, program: string, timeoutMs?: number): Promise<ExecuteResult>
  search(query: { query?: string; names?: string[]; limit?: number }): SearchResult
  runChecks(seat: string, only?: string[]): Promise<Record<string, unknown> & { findings: unknown[]; signature: { sig: string; key_id: string } }>
  verifiedReport(seat: string): Record<string, unknown>
  state(seat: string): Record<string, unknown>
  seal(): Record<string, unknown>
  startSmith(seat: string, url?: string): void
  readonly board: {
    read(): { claims: unknown[] }
    write(doc: { claims: unknown[] }): void
    post(report: unknown, seat: string): { added: number; total: number }
    postClaims(findings: unknown[], seat: string, tag?: string): { added: number }
  }
  readonly audit: {
    since(seq?: number, limit?: number): Array<Record<string, unknown>>
    append(entry: Record<string, unknown>): Record<string, unknown>
    on(event: 'entry', listener: (entry: Record<string, unknown>) => void): void
    off(event: 'entry', listener: (entry: Record<string, unknown>) => void): void
  }
}

export interface ExecuteResult {
  readonly ok?: boolean
  readonly invalid?: string
  readonly value?: unknown
  readonly truncated?: boolean
  readonly calls?: number
  readonly run_id?: string
  readonly receipt?: string
  readonly error?: { kind: string; code?: string; message: string; tool?: string; call_index?: number; receipt?: string }
}

export interface SearchResult {
  readonly matches: ReadonlyArray<{ name: string; call: string; stub: string; summary: string; class: string; callable: boolean; why_not?: string }>
  readonly catalog_size: number
  readonly visible_size: number
}

/** What the bundle configuration decides about the engine. */
/** An approver for destructive calls in `ask` mode: says yes or no to one exact call. */
export type Approver = (request: { seat: string; tool: string; argv: string[]; run_id: string | null }) => Promise<{ approved: boolean; by?: string; reason?: string }>

export interface EngineOptions {
  readonly target: 'standin' | 'qnx'
  /** Destructive tools: off (default), ask (each call needs the approver's yes), on. */
  readonly destructive: 'off' | 'ask' | 'on'
  readonly approve: Approver
  /** Engine config file; defaults to engine/standin/config.json or engine/qnx/config.json by target. */
  readonly config?: string | undefined
  readonly logger: { info(format: string, ...args: unknown[]): void; warn(format: string, ...args: unknown[]): void }
}

/** A running engine and whatever this bundle started for it. */
export interface Running {
  readonly engine: Engine
  readonly mcpUrl: string
  stop(): Promise<void>
}

const require = createRequire(import.meta.url)

function run(cmd: string, args: string[], cwd: string): string {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8' })
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} failed: ${(r.stderr || r.stdout || '').trim().slice(0, 400)}`)
  return r.stdout
}

/** Prepare the Linux stand-in target and start its runner; returns the runner process. */
function prepareStandin(configFile: string, log: EngineOptions['logger']): ChildProcess {
  const node = process.execPath
  const engineCli = join(ENGINE_DIR, 'gateway', 'cli.js')
  const cfg = JSON.parse(readFileSync(configFile, 'utf8')) as { state_dir: string; catalog: string; manifest: string; runner: { port: number } }
  const base = dirname(configFile)
  const stateDir = resolve(base, cfg.state_dir)
  const runnerBin = join(ENGINE_DIR, 'node-runtime', 'qnx-runner')
  if (!existsSync(runnerBin)) run('make', ['-s'], join(ENGINE_DIR, 'node-runtime'))
  if (!existsSync(join(stateDir, 'seats.json'))) run(node, [engineCli, 'init', stateDir], base)
  mkdirSync(stateDir, { recursive: true })
  run('sh', [join(ENGINE_DIR, 'node-runtime', 'inventory-qnx.sh'), resolve(base, cfg.catalog)], base)
  const manifest = resolve(base, cfg.manifest)
  if (!existsSync(manifest)) run(node, [join(ENGINE_DIR, 'scripts', 'standin-baseline.js'), resolve(base, cfg.catalog), manifest], base)
  writeFileSync(join(stateDir, 'runner.allow'), run(node, [engineCli, 'allowlist', configFile], base))
  const child = spawn(runnerBin, [
    '--listen', String(cfg.runner.port), '--bind', '127.0.0.1',
    '--token-file', join(stateDir, 'runner.token'),
    '--allow-file', join(stateDir, 'runner.allow'),
    '--spawn-log', join(stateDir, 'spawn.log'),
  ], { stdio: 'ignore' })
  // The runner must not outlive the Harness: stop it whenever this process ends, however it ends.
  const stop = (): void => { if (child.exitCode === null) child.kill() }
  process.once('exit', stop)
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) process.once(signal, () => { stop(); process.kill(process.pid, signal) })
  log.info('qnx: stand-in runner started on 127.0.0.1:%d (pid %d)', cfg.runner.port, child.pid ?? -1)
  return child
}

/**
 * Start the engine for this bundle.
 * @param options - target and logger.
 * @returns the running engine.
 */
export async function startEngine(options: EngineOptions): Promise<Running> {
  const configFile = resolve(options.config ?? join(ENGINE_DIR, options.target === 'qnx' ? 'qnx' : 'standin', 'config.json'))
  if (!existsSync(configFile)) {
    throw new Error(options.target === 'qnx'
      ? `No QNX engine config at ${configFile}. Run engine/scripts/phase0.sh after installing the QNX SDP; it writes this file.`
      : `No engine config at ${configFile}.`)
  }
  if (options.target === 'standin' && process.platform === 'win32') {
    throw new Error('The stand-in target needs Linux (it runs the target on this machine). On Windows, set the dsh-qnx row to target: qnx and run Phase 0 in WSL2, or run the app itself in WSL2 with start-qnx.sh.')
  }
  const runner = options.target === 'standin' ? prepareStandin(configFile, options.logger) : undefined
  if (runner !== undefined) await new Promise(r => setTimeout(r, 250))
  const { createGateway, loadConfig } = require(join(ENGINE_DIR, 'gateway', 'server.js')) as {
    createGateway(cfg: unknown): Engine
    loadConfig(file: string): Engine['cfg']
  }
  const cfg = loadConfig(configFile) as Engine['cfg'] & { destructive?: string; approve?: Approver }
  cfg.destructive = options.destructive
  cfg.approve = options.approve
  const engine = createGateway(cfg)
  // The stand-in's runner allowlist follows the live catalog and destructive mode (the runner re-reads it per request).
  if (options.target === 'standin') {
    writeFileSync(join(cfg.state_dir, 'runner.allow'), engine.catalog().allowlist(cfg.inventory_path ? [cfg.inventory_path] : []))
  }
  const { host, port } = cfg.listen
  await new Promise<void>((ok, fail) => {
    engine.server.once('error', fail)
    engine.server.listen(port, host, () => { ok() })
  })
  const mcpUrl = `http://${host}:${String(port)}`
  options.logger.info('qnx: engine ready, %s target, loopback MCP for verifier seats at %s/mcp', options.target, mcpUrl)
  return {
    engine,
    mcpUrl,
    stop: async () => {
      await new Promise<void>(r => { engine.server.close(() => { r() }) })
      runner?.kill()
    },
  }
}
