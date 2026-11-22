import { execFile } from 'node:child_process'
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { delimiter, join, sep } from 'node:path'
import { promisify } from 'node:util'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Config, executable, machineOf, resolveDeployment, resolveFeishuBot, type Machine, type Probe } from '../src/deployment.ts'
import { gitEnv } from './fixtures/git.ts'

const exec = promisify(execFile)
let dir: string
let path: string
/**
 * Writes a stand-in CLI whose logic is JavaScript on every platform: a `#!/bin/sh` launcher on POSIX, and a `.cmd` launcher
 * on Windows, which runs no extensionless file. Both hand their arguments to the same script.
 */
const program = (file: string, body: string): string => {
  writeFileSync(`${file}.js`, body)
  if (process.platform !== 'win32') {
    writeFileSync(file, `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(`${file}.js`)} "$@"\n`)
    chmodSync(file, 0o755)
    return file
  }
  writeFileSync(`${file}.cmd`, `@echo off\r\n"${process.execPath}" "${file}.js" %*\r\n`)
  return `${file}.cmd`
}
/** The path `executable` finds for a stand-in written under `name`, which carries the launcher's extension on Windows. */
const launcher = (name: string): string => join(dir, 'bin', process.platform === 'win32' ? `${name}.CMD` : name)
/** Fake gh CLI signed in as `login` with configurable push access to acme/widgets (including its former name acme/gadgets). */
const gh = (file: string, login: string, push = true): string => program(file, [
  "const args = process.argv.slice(2).join(' ')",
  `if (args === 'api user') console.log(JSON.stringify({ login: ${JSON.stringify(login)}, id: 7 }))`,
  `else if (args.startsWith('api repos/acme/')) console.log(JSON.stringify({ name: 'acme/widgets', push: ${push} }))`,
  'else process.exit(1)',
].join('\n'))
/** Fake lark-cli script body returning canned auth, strict-mode, and bot info responses. */
const lark = (status: object, mode = 'bot', bot: object = { bot: { open_id: 'ou_bot', app_name: 'Widgets Bot' }, code: 0 }): string =>
  ["const args = process.argv.slice(2).join(' ')",
    `if (args === 'auth status') console.log(${JSON.stringify(JSON.stringify(status))})`,
    `else if (args === 'config strict-mode') console.log(${JSON.stringify(`strict-mode: ${mode} (source: profile)`)})`,
    `else if (args === 'api GET /open-apis/bot/v3/info --as bot --format ndjson') console.log(${JSON.stringify(JSON.stringify(bot))})`,
  ].join('\n')
const minimal = (overrides: Record<string, unknown> = {}) => ({ stateDir: join(dir, 'state'), ...overrides })
const machine = (overrides: Partial<Machine> = {}): Machine => ({ ...machineOf(Config(minimal())), ...overrides })
/**
 * Runs commands like worker shells do, but locally: the stand-ins first on PATH, then the system's git. A `.cmd` launcher
 * needs cmd to run it, as it does for workers.
 */
const probe: Probe = async input => {
  // Probes may carry an `env` prefix with assignments, which Windows has no binary for; apply it to the child instead.
  const argv = [...input]
  const extra: Record<string, string> = {}
  if (argv[0] === 'env') {
    argv.shift()
    for (let word = argv[0]; word !== undefined && /^[A-Za-z_][A-Za-z0-9_]*=/.test(word); word = argv[0]) {
      const [name, ...rest] = argv.shift()!.split('=')
      extra[name!] = rest.join('=')
    }
  }
  const env = { PATH: path, HOME: dir, ...extra }
  const [file, ...args] = argv
  const verbose = process.env.DSH_TEST_VERBOSE === '1'
  if (process.platform === 'win32' && /\.cmd$/i.test(file!)) {
    // A `.cmd` launcher needs cmd, which execFile only arranges through `shell`, and Node would otherwise escape its quotes.
    const line = [file!, ...args].map(part => `"${part}"`).join(' ')
    const result = await exec(line, { env, shell: true })
    if (verbose) console.error('probe:', line, result.stdout)
    return result.stdout
  }
  return (await exec(file!, args, { env })).stdout
}
const setupError = (place: string, code: string, values: Record<string, unknown> = {}) => expect.objectContaining({ place, code, values: expect.objectContaining(values) })

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), 'deployment-'))
  mkdirSync(join(dir, 'bin')); mkdirSync(join(dir, 'state', 'worker-bin'), { recursive: true }); mkdirSync(join(dir, 'widgets', 'src'), { recursive: true })
  // A trailing separator and a linked path spell the worker shim directory in ways the product must still recognise.
  path = [join(dir, 'state-link', 'worker-bin'), join(dir, 'state', 'worker-bin') + sep, join(dir, 'bin'),
    ...process.platform === 'win32' ? [] : ['/usr/bin', '/bin']].join(delimiter)
  gh(join(dir, 'bin', 'gh'), 'Agent-Bot')
  program(join(dir, 'bin', 'lark-cli'), lark({ appId: 'cli_bot', brand: 'lark', identities: { bot: { status: 'ready' } } }))
  // Stale worker shims with the same binary name must be skipped regardless of PATH normalization or symlinks.
  program(join(dir, 'state', 'worker-bin', 'gh'), 'process.exit(9)')
  // A junction links directories on Windows without the elevation a symbolic link needs.
  symlinkSync(join(dir, 'state'), join(dir, 'state-link'), process.platform === 'win32' ? 'junction' : 'dir')
  await exec('git', ['init', '-q', join(dir, 'widgets')], { env: gitEnv() })
  await exec('git', ['-C', join(dir, 'widgets'), 'remote', 'add', 'origin', 'git@github.com:acme/widgets.git'], { env: gitEnv() })
})
afterEach(() => { rmSync(dir, { recursive: true, force: true }) })

// Setup spawns CLI subprocesses that can take several seconds when tests run in parallel.
vi.setConfig({ testTimeout: 30_000 })

describe('configuration schema', () => {
  it('requires only the state directory and reads the editable fields through references', () => {
    expect(() => Config({})).toThrow('stateDir')
    const read = machineOf(Config({ stateDir: join(dir, 'state') }))
    // Limits are volatile references that the loader updates in place and callers read when used.
    expect({ ...read, promptMaxChars: read.promptMaxChars.get(), admissionContextMaxPages: read.admissionContextMaxPages.get(),
      admissionContextTimeoutMs: read.admissionContextTimeoutMs.get() })
      .toEqual({ stateDir: join(dir, 'state'), promptMaxChars: 100000, admissionContextMaxPages: 10, admissionContextTimeoutMs: 15000 })
    expect(() => Config(minimal({ stateDir: 'relative/dir' }))).toThrow()
    expect(() => Config(minimal({ stateDir: '~/dir' }))).toThrow()
  })
  it('names keys the configuration does not define, and where the values of older keys live now', () => {
    const raw = minimal({ repository: 'acme/widgets', repositoryPath: '/srv/widgets', blockedCommands: [], author: { name: 'Alice' }, extra: 1 })
    expect(() => machineOf(Config(raw))).toThrow('keys it does not use: repository (now on the GitHub Source), repositoryPath (now in the prepare command of the Execution settings), blockedCommands (now in the Execution settings), author (now prompt text), extra;')
  })
})

describe('setup', () => {
  it('reads the repository from the GitHub Source and the accounts from their CLIs, skipping the worker shims', async () => {
    const deployment = await resolveDeployment(machine(), { repository: 'acme/widgets', cli: 'gh' }, probe, path)
    expect(deployment).toMatchObject({ repository: 'acme/widgets', github: { cli: launcher('gh'), login: 'Agent-Bot', noreply: '7+Agent-Bot@users.noreply.github.com' } })
    expect(deployment.github).toEqual({ cli: launcher('gh'), login: 'Agent-Bot', noreply: '7+Agent-Bot@users.noreply.github.com' })
    expect(deployment).not.toHaveProperty('feishu')
    // A renamed repository is still resolved by its old name; notifications carry GitHub's current full_name.
    expect((await resolveDeployment(machine(), { repository: 'acme/gadgets', cli: 'gh' }, probe, path)).repository).toBe('acme/widgets')
  })
  it('names what setup needs and where it is set', async () => {
    const needs = (place: string, code: string, values: Record<string, unknown>, github: unknown) =>
      expect(resolveDeployment(machine(), github, probe, path)).rejects.toEqual(setupError(place, code, values))
    const repository = 'acme/widgets'
    await needs('github', 'repositoryUnset', {}, { cli: 'gh' })
    await needs('github', 'agentCliUnset', {}, { repository })
    await needs('github', 'agentCliMissing', { output: `${join(dir, 'missing')} is not an executable file` }, { repository, cli: join(dir, 'missing') })
    await needs('github', 'agentCliMissing', { output: 'bin/gh must be a command name or an absolute path' }, { repository, cli: 'bin/gh' })
    await needs('github', 'agentCliSignedOut', {}, { repository, cli: program(join(dir, 'bin', 'gh-broken'), 'process.exit(1)') })
    await needs('github', 'repositoryReadOnly', { account: 'Agent-Bot', repository: 'acme/widgets' }, { repository, cli: gh(join(dir, 'bin', 'gh-reader'), 'Agent-Bot', false) })
    // Signed in, but the account cannot read the repository, or the CLI names no account.
    const unreadable = program(join(dir, 'bin', 'gh-outsider'), [
      "const args = process.argv.slice(2).join(' ')",
      `if (args === 'api user') console.log(JSON.stringify({ login: 'Agent-Bot', id: 7 }))`,
      "else { console.error('HTTP 404'); process.exit(1) }",
    ].join('\n'))
    const output = expect.stringContaining('HTTP 404') as unknown
    await needs('github', 'repositoryUnreadable', { account: 'Agent-Bot', repository: 'acme/widgets', output }, { repository, cli: unreadable })
    await needs('github', 'agentCliNoAccount', {}, { repository, cli: program(join(dir, 'bin', 'gh-anonymous'), "console.log('{}')") })
    expect(() => executable('nothing-here', join(dir, 'bin'))).toThrow('nothing-here is not an executable file on PATH')
  })
  it('resolves a bare command name through PATHEXT on Windows, which runs no extensionless file', () => {
    if (process.platform !== 'win32') return
    const bin = join(dir, 'pathext')
    mkdirSync(bin, { recursive: true })
    writeFileSync(join(bin, 'agent-cli.EXE'), '')
    expect(executable('agent-cli', bin)).toBe(join(bin, 'agent-cli.EXE'))
    // A name that already has an extension is used as written, without another one appended.
    writeFileSync(join(bin, 'with-ext.cmd'), '')
    expect(executable('with-ext.cmd', bin)).toBe(join(bin, 'with-ext.cmd'))
    expect(() => executable('absent-cli', bin)).toThrow('absent-cli is not an executable file on PATH')
    // An absolute path is used as written, extension or not.
    expect(executable(join(bin, 'agent-cli.EXE'), join(dir, 'nowhere'))).toBe(join(bin, 'agent-cli.EXE'))
  })
  it('reads the Feishu bot from a bot-only lark-cli, or finds none when the Feishu Source names no CLI', async () => {
    expect(await resolveFeishuBot(machine(), {}, probe, path)).toBeUndefined()
    expect(await resolveFeishuBot(machine(), { cli: 'lark-cli' }, probe, path)).toEqual({ cli: launcher('lark-cli'), appId: 'cli_bot', brand: 'lark', botId: 'ou_bot', name: 'Widgets Bot' })
    const refuses = async (code: string, values: Record<string, unknown> = {}) => expect(resolveFeishuBot(machine(), { cli: 'lark-cli' }, probe, path)).rejects.toEqual(setupError('feishu', code, values))
    program(join(dir, 'bin', 'lark-cli'), lark({ identities: { bot: { status: 'ready' } } }))
    await refuses('feishuNoApp')
    program(join(dir, 'bin', 'lark-cli'), lark({ appId: 'cli_bot', identities: { bot: { status: 'missing' } } }))
    await refuses('feishuBotNotReady', { app: 'cli_bot', status: 'missing' })
    program(join(dir, 'bin', 'lark-cli'), lark({ appId: 'cli_bot', identities: { bot: { status: 'ready' } } }, 'off'))
    await refuses('feishuUserIdentity', { mode: 'off' })
    program(join(dir, 'bin', 'lark-cli'), lark({ appId: 'cli_bot', identities: { bot: { status: 'ready' } } }, 'bot', { code: 0, data: {} }))
    await refuses('feishuNoBot')
    program(join(dir, 'bin', 'lark-cli'), "console.error('not configured'); process.exit(1)")
    await refuses('feishuCliFailed', { output: expect.stringContaining('not configured') })
  })
})