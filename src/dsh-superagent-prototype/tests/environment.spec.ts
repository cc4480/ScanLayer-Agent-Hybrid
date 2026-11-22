import { execFile, execFileSync, spawn } from 'node:child_process'
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { SENSITIVE_ENV_PATTERN, type SubprocessRuntime } from '@deepseek-ai/dsh-subprocess'
import { GIT_LOCATION, agentVariables, cmdFailShim, cmdRunShim, credentialHelper, runAsWorker, shellArgv, verifyDirectory, withoutDirectory, workerBin, workerGitConfig, writeEnvironment }
  from '../src/infra/environment.ts'
import { CliError } from '../src/infra/commands.ts'
import { testDeployment } from './fixtures/deployment.ts'
import { gitEnv } from './fixtures/git.ts'

// Git and shell subprocesses can exceed the 5s default timeout when the test suite runs in parallel.
vi.setConfig({ testTimeout: 30_000 })
const exec = promisify(execFile)
let dir: string
const program = (path: string, body: string): string => { writeFileSync(path, `#!/bin/sh\n${body}\n`); chmodSync(path, 0o755); return path }
/** Worker shell environment after DSH strips credential-shaped variables. */
const workerEnv = (env: Record<string, string | undefined>): Record<string, string> =>
  Object.fromEntries(Object.entries(env).filter((entry): entry is [string, string] => entry[1] !== undefined && !SENSITIVE_ENV_PATTERN.test(entry[0])))
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'environment-')); mkdirSync(join(dir, 'real')) })
afterEach(() => { rmSync(dir, { recursive: true, force: true }) })

describe('worker shims', () => {
  it('run a wrapper that calls `gh` by name without reaching the shim again, and keep the caller\'s other PATH entries', async () => {
    program(join(dir, 'real', 'gh'), 'echo "{\\"login\\":\\"agent-bot\\",\\"config\\":\\"$GH_CONFIG_DIR\\",\\"path\\":\\"$PATH\\"}"')
    const wrapper = program(join(dir, 'gh-agent'), `GH_CONFIG_DIR=${dir}/agent-config exec gh "$@"`)
    await writeEnvironment(testDeployment({ stateDir: dir, github: { ...testDeployment().github, cli: wrapper }, feishu: undefined }), [])
    const bin = workerBin(dir)
    const path = [bin, join(dir, 'venv'), join(dir, 'real'), '/usr/bin', '/bin'].join(':')
    const { stdout } = await exec('gh', ['api', 'user'], { env: { PATH: path }, timeout: 10_000 })
    expect(JSON.parse(stdout)).toEqual({ login: 'agent-bot', config: `${dir}/agent-config`, path: [join(dir, 'venv'), join(dir, 'real'), '/usr/bin', '/bin'].join(':') })
  })
  it('make `lark-cli` fail without a Feishu bot and each blocked command fail with the agent\'s login', async () => {
    await writeEnvironment(testDeployment({ stateDir: dir, feishu: undefined }), ['personal-gh'])
    const bin = workerBin(dir)
    await expect(exec(join(bin, 'lark-cli'), ['im', '+chat-list'])).rejects.toMatchObject({ code: 1, stderr: 'lark-cli is unavailable: this installation has no Feishu bot.\n' })
    await expect(exec(join(bin, 'personal-gh'), [])).rejects.toMatchObject({ code: 1, stderr: 'personal-gh is blocked in this installation; use gh, which acts as agent-bot.\n' })
  })
  it('keep `gh` and `lark-cli` working, and shim no `git`, when the blocked commands name the commands workers need', async () => {
    const gh = program(join(dir, 'gh-agent'), 'echo gh "$@"'), lark = program(join(dir, 'lark-bot'), 'echo lark "$@"')
    const base = testDeployment()
    await writeEnvironment(testDeployment({ stateDir: dir, github: { ...base.github, cli: gh }, feishu: { ...base.feishu!, cli: lark } }), ['gh', 'git', 'lark-cli'])
    const bin = workerBin(dir)
    expect([(await exec(join(bin, 'gh'), ['api', 'user'])).stdout, (await exec(join(bin, 'lark-cli'), ['im'])).stdout]).toEqual(['gh api user\n', 'lark im\n'])
    expect(readdirSync(bin)).not.toContain('git')
  })
  // These two tests check the `sh` shims alone, so they name the platform: on win32 the default also writes the `.cmd` twins, which the
  // 'Windows command shims' tests below cover.
  it('replace only what dsh-superagent wrote and refuse anything else in its places', async () => {
    await writeEnvironment(testDeployment({ stateDir: dir }), ['old-cli'], 'linux')
    await writeEnvironment(testDeployment({ stateDir: dir }), [], 'linux')
    expect(readdirSync(workerBin(dir)).sort()).toEqual(['gh', 'lark-cli'])
    // A file that merely contains the marker on a later line, a symlink to a shim, and a foreign gitconfig are all rejected.
    writeFileSync(join(workerBin(dir), 'notes'), `notes\nmore\n${readFileSync(join(workerBin(dir), 'gh'), 'utf8').split('\n')[1]}\n`)
    await expect(writeEnvironment(testDeployment({ stateDir: dir }), [], 'linux')).rejects.toThrow(`${join(workerBin(dir), 'notes')} was not written by dsh-superagent`)
    rmSync(join(workerBin(dir), 'notes'))
    symlinkSync(join(workerBin(dir), 'gh'), join(workerBin(dir), 'link'))
    await expect(writeEnvironment(testDeployment({ stateDir: dir }), [], 'linux')).rejects.toThrow('link was not written by dsh-superagent')
    rmSync(join(workerBin(dir), 'link'))
    writeFileSync(workerGitConfig(dir), '[user]\n\tname = someone\n')
    await expect(writeEnvironment(testDeployment({ stateDir: dir }), [], 'linux')).rejects.toThrow(`${workerGitConfig(dir)} was not written by dsh-superagent`)
    expect(readFileSync(workerGitConfig(dir), 'utf8')).toBe('[user]\n\tname = someone\n')
  })
  it('replaces the files it wrote under the project\'s earlier names', async () => {
    await writeEnvironment(testDeployment({ stateDir: dir }), ['old-cli', 'older-cli'], 'linux')
    const legacy = (file: string, name: string) => writeFileSync(file, readFileSync(file, 'utf8').replace('Written by dsh-superagent', `Written by ${name}`))
    legacy(join(workerBin(dir), 'old-cli'), 'dsh-tag'); legacy(join(workerBin(dir), 'older-cli'), 'dsh-freelancer'); legacy(workerGitConfig(dir), 'dsh-go')
    await writeEnvironment(testDeployment({ stateDir: dir }), [], 'linux')
    expect(readdirSync(workerBin(dir)).sort()).toEqual(['gh', 'lark-cli'])
    expect(readFileSync(workerGitConfig(dir), 'utf8')).toContain('Written by dsh-superagent')
  })
})

/** A `.cmd` shim as `cmdRunShim` and `cmdFailShim` write it: batch lines end in CRLF, and the marker is a comment on line 2. */
const batch = (...lines: string[]): string => ['@echo off', 'REM # Written by dsh-superagent on every start; edits are lost.', ...lines].join('\r\n') + '\r\n'

describe('Windows command shims: text', () => {
  const bin = String.raw`C:\state\worker-bin`
  it('runs an .exe target directly, strips the shim directory from PATH first, and returns its exit code', () => {
    expect(cmdRunShim(bin, String.raw`C:\Program Files\GitHub CLI\gh.exe`)).toBe(batch(
      'setlocal DisableDelayedExpansion',
      String.raw`set "PATH=%PATH:C:\state\worker-bin;=%"`,
      String.raw`set "PATH=%PATH:;C:\state\worker-bin=%"`,
      String.raw`"C:\Program Files\GitHub CLI\gh.exe" %*`,
      'exit /b %ERRORLEVEL%'))
  })
  it('runs a .cmd or .bat wrapper through `call`, which a batch file needs to get control back', () => {
    for (const wrapper of [String.raw`C:\tools\gh-agent.cmd`, String.raw`C:\tools\gh-agent.BAT`]) {
      expect(cmdRunShim(bin, wrapper)).toContain(`\r\ncall "${wrapper}" %*\r\nexit /b %ERRORLEVEL%\r\n`)
    }
    expect(cmdRunShim(bin, String.raw`C:\tools\gh.EXE`)).not.toContain('call ')
  })
  it('doubles a % in the target path and leaves spaces alone', () => {
    expect(cmdRunShim(bin, String.raw`C:\100%\my tools\gh.exe`)).toContain(String.raw`"C:\100%%\my tools\gh.exe" %*`)
  })
  it('skips the PATH edit, not the run, for a shim directory %PATH:from=to% cannot name', () => {
    for (const odd of [String.raw`C:\100%\worker-bin`, String.raw`C:\a=b\worker-bin`, '*\\worker-bin']) {
      const text = cmdRunShim(odd, String.raw`C:\tools\gh.exe`)
      expect(text).not.toContain('set "PATH=')
      expect(text).toContain(String.raw`"C:\tools\gh.exe" %*`)
    }
    expect(cmdRunShim(String.raw`C:\My State\worker-bin`, String.raw`C:\tools\gh.exe`)).toContain(String.raw`set "PATH=%PATH:C:\My State\worker-bin;=%"`)
  })
  it('works on a copy of the environment, so running the shim in an interactive cmd leaves its PATH alone', () => {
    for (const text of [cmdRunShim(bin, String.raw`C:\tools\gh.exe`), cmdFailShim('no')]) {
      expect(text.indexOf('setlocal')).toBeGreaterThan(-1)
      expect(text.indexOf('setlocal')).toBeLessThan(Math.max(text.indexOf('set "PATH'), text.indexOf('exit /b')))
    }
  })
  it('prints a blocked command\'s message to stderr with cmd\'s special characters escaped, and exits 1', () => {
    expect(cmdFailShim('curl is blocked in this installation; use gh, which acts as agent-bot.')).toBe(batch(
      'setlocal DisableDelayedExpansion',
      '>&2 echo(curl is blocked in this installation; use gh, which acts as agent-bot.',
      'exit /b 1'))
    expect(cmdFailShim('a&b|c<d>e^f(g)h!i%j"k')).toBe(batch('setlocal DisableDelayedExpansion', ">&2 echo(a^&b^|c^<d^>e^^f^(g^)h^!i%%j'k", 'exit /b 1'))
  })
})

describe('Windows command shims: files', () => {
  const lines = (file: string): string[] => readFileSync(file, 'utf8').split('\r\n')
  it('writes a .cmd twin beside every sh shim on win32, and none elsewhere', async () => {
    const base = testDeployment({ stateDir: dir }), bin = workerBin(dir)
    await writeEnvironment(base, ['personal-gh'], 'win32')
    expect(readdirSync(bin).sort()).toEqual(['gh', 'gh.cmd', 'lark-cli', 'lark-cli.cmd', 'personal-gh', 'personal-gh.cmd'])
    expect(readFileSync(join(bin, 'gh.cmd'), 'utf8')).toBe(cmdRunShim(bin, base.github.cli))
    expect(readFileSync(join(bin, 'lark-cli.cmd'), 'utf8')).toBe(cmdRunShim(bin, base.feishu!.cli))
    expect(readFileSync(join(bin, 'personal-gh.cmd'), 'utf8')).toBe(cmdFailShim('personal-gh is blocked in this installation; use gh, which acts as agent-bot.'))
    expect(lines(join(bin, 'gh.cmd')).slice(0, 2)).toEqual(['@echo off', 'REM # Written by dsh-superagent on every start; edits are lost.'])
    expect(readFileSync(join(bin, 'gh'), 'utf8').startsWith('#!/bin/sh\n')).toBe(true)
    for (const platform of ['linux', 'darwin'] as const) {
      rmSync(bin, { recursive: true })
      await writeEnvironment(base, ['personal-gh'], platform)
      expect(readdirSync(bin).sort()).toEqual(['gh', 'lark-cli', 'personal-gh'])
    }
  })
  it('writes the Feishu shim as a failure without a bot, as the sh shim does', async () => {
    await writeEnvironment(testDeployment({ stateDir: dir, feishu: undefined }), [], 'win32')
    expect(readFileSync(join(workerBin(dir), 'lark-cli.cmd'), 'utf8')).toBe(cmdFailShim('lark-cli is unavailable: this installation has no Feishu bot.'))
  })
  it('rewrites the same files on a second start and removes the twins of a shim that is no longer wanted', async () => {
    const bin = workerBin(dir), read = () => Object.fromEntries(readdirSync(bin).map(name => [name, readFileSync(join(bin, name), 'utf8')]))
    await writeEnvironment(testDeployment({ stateDir: dir }), ['old-cli'], 'win32')
    expect(readdirSync(bin)).toContain('old-cli.cmd')
    await writeEnvironment(testDeployment({ stateDir: dir }), [], 'win32')
    const first = read()
    expect(Object.keys(first).sort()).toEqual(['gh', 'gh.cmd', 'lark-cli', 'lark-cli.cmd'])
    await writeEnvironment(testDeployment({ stateDir: dir }), [], 'win32')
    expect(read()).toEqual(first)
  })
  it('refuses a .cmd file it did not write and keeps it', async () => {
    await writeEnvironment(testDeployment({ stateDir: dir }), [], 'win32')
    const stray = join(workerBin(dir), 'stray.cmd')
    writeFileSync(stray, '@echo off\r\necho mine\r\n')
    await expect(writeEnvironment(testDeployment({ stateDir: dir }), [], 'win32')).rejects.toThrow(`${stray} was not written by dsh-superagent`)
    // The marker on a later line does not count, with CRLF endings either.
    writeFileSync(stray, `@echo off\r\necho mine\r\nREM # Written by dsh-superagent on every start; edits are lost.\r\n`)
    await expect(writeEnvironment(testDeployment({ stateDir: dir }), [], 'win32')).rejects.toThrow('stray.cmd was not written by dsh-superagent')
    expect(readFileSync(stray, 'utf8')).toContain('echo mine')
  })
  it('replaces a .cmd shim written under the project\'s earlier names, and one left half-written by a crash', async () => {
    await writeEnvironment(testDeployment({ stateDir: dir }), [], 'win32')
    const bin = workerBin(dir)
    writeFileSync(join(bin, 'legacy.cmd'), '@echo off\r\nREM # Written by dsh-tag on every start; edits are lost.\r\nexit /b 1\r\n')
    writeFileSync(join(bin, '.gh.cmd.123.tmp'), '@echo off\r\nREM # Written by dsh-superagent on every start; edits are lost.\r\n')
    await writeEnvironment(testDeployment({ stateDir: dir }), [], 'win32')
    expect(readdirSync(bin).sort()).toEqual(['gh', 'gh.cmd', 'lark-cli', 'lark-cli.cmd'])
  })
})

/** The shims run by the shells workers use. Only meaningful where cmd.exe and PowerShell exist. */
describe.skipIf(process.platform !== 'win32')('Windows command shims: run by cmd and PowerShell', () => {
  // Starting a shell can take seconds on a loaded machine.
  const SHELL_TIMEOUT = 90_000
  const system32 = join(process.env.SystemRoot ?? String.raw`C:\Windows`, 'System32')
  const windowsPowerShell = join(system32, 'WindowsPowerShell', 'v1.0', 'powershell.exe')
  const pwsh = ((): string | undefined => { try { return execFileSync('where', ['pwsh'], { encoding: 'utf8' }).split(/\r?\n/)[0] || undefined } catch { return undefined } })()
  type Outcome = { code: number; stdout: string; stderr: string }
  /** `verbatim` hands cmd its command line unchanged: Node would otherwise re-quote the embedded double quotes. */
  const run = (file: string, args: string[], path: string, verbatim: boolean): Promise<Outcome> =>
    exec(file, args, { env: { ...process.env, PATH: path }, timeout: 80_000, windowsVerbatimArguments: verbatim }).then(
      ({ stdout, stderr }) => ({ code: 0, stdout, stderr }),
      (error: { code?: number; stdout?: string; stderr?: string }) => ({ code: error.code ?? -1, stdout: error.stdout ?? '', stderr: error.stderr ?? '' }))
  /** A worker shell's PATH: the shim directory first, then the directory of the real `gh`, then only what the shells themselves need. */
  const workerPath = (): string => [workerBin(dir), join(dir, 'real'), system32, join(system32, 'WindowsPowerShell', 'v1.0'), ...(pwsh ? [join(pwsh, '..')] : [])].join(';')
  const powershell = (command: string): string[] => ['-NoProfile', '-NonInteractive', '-Command', `${command}; exit $LASTEXITCODE`]
  /** name, executable, argv for a command line, and whether cmd must get it verbatim (`/s` drops the outer quotes added here). */
  const shells: Array<[string, string, (command: string) => string[], boolean]> = [
    ['cmd', process.env.ComSpec ?? join(system32, 'cmd.exe'), command => ['/d', '/s', '/c', `"${command}"`], true],
    ['Windows PowerShell 5.1', windowsPowerShell, powershell, false],
  ]
  if (pwsh) shells.push(['PowerShell 7', pwsh, powershell, false])

  beforeEach(async () => {
    // The real `gh` reports its arguments and whether the shim directory is still on PATH, and exits 7.
    writeFileSync(join(dir, 'real', 'gh.cmd'), ['@echo off', 'echo real-gh:%*', 'echo config:%GH_CONFIG_DIR%',
      'echo %PATH% | findstr /i /c:"worker-bin" >nul', 'if errorlevel 1 (echo shim-stripped) else (echo shim-present)', 'exit /b 7', ''].join('\r\n'))
    // The agent's `gh` is a wrapper that calls `gh` by name, as the sh test does: it reaches the real one only if the shim left PATH.
    writeFileSync(join(dir, 'gh-agent.cmd'), ['@echo off', 'set "GH_CONFIG_DIR=%~dp0agent-config"', 'call gh %*', 'exit /b %ERRORLEVEL%', ''].join('\r\n'))
    await writeEnvironment(testDeployment({ stateDir: dir, github: { ...testDeployment().github, cli: join(dir, 'gh-agent.cmd') }, feishu: undefined }), ['personal-gh'], 'win32')
  })

  for (const [name, file, command, verbatim] of shells) {
    it(`${name}: \`gh\` reaches the real one through the agent's wrapper with its arguments, its exit code and a PATH without the shim directory`, async () => {
      const outcome = await run(file, command(name === 'cmd' ? 'gh a "b c"' : `gh a 'b c'`), workerPath(), verbatim)
      expect(outcome.stdout.split(/\r?\n/).filter(Boolean)).toEqual(['real-gh:a "b c"', `config:${join(dir, 'agent-config')}`, 'shim-stripped'])
      expect(outcome.code).toBe(7)
    }, SHELL_TIMEOUT)
    it(`${name}: a blocked command and a missing Feishu bot exit 1 with their message on stderr`, async () => {
      const blocked = await run(file, command('personal-gh'), workerPath(), verbatim)
      expect(blocked.code).toBe(1)
      expect(blocked.stderr).toContain('personal-gh is blocked in this installation; use gh, which acts as agent-bot.')
      expect(blocked.stdout.trim()).toBe('')
      const lark = await run(file, command('lark-cli im'), workerPath(), verbatim)
      expect(lark.code).toBe(1)
      expect(lark.stderr).toContain('lark-cli is unavailable: this installation has no Feishu bot.')
    }, SHELL_TIMEOUT)
  }
})

describe('agent git configuration', () => {
  it('ignores the operator\'s global and system git configuration, also after DSH drops credential-shaped variables', async () => {
    const home = join(dir, 'home'); mkdirSync(home)
    // Operator configuration that rewrites HTTPS to SSH, enables commit signing, and sets a credential helper.
    writeFileSync(join(home, '.gitconfig'), '[url "git@github.com:"]\n\tinsteadOf = https://github.com/\n[commit]\n\tgpgsign = true\n[credential]\n\thelper = osxkeychain\n')
    const deployment = testDeployment({ stateDir: dir, github: { ...testDeployment().github, cli: '/opt/agent tools/gh' } })
    await writeEnvironment(deployment, [])
    // Operator identity variables and git's fallback from the OS username must not apply to worker commits.
    const env = workerEnv({ PATH: process.env.PATH, HOME: home, GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'core.abbrev', GIT_CONFIG_VALUE_0: '12', GIT_AUTHOR_NAME: 'Operator', GIT_COMMITTER_EMAIL: 'operator@example.com', ...agentVariables(dir) })
    const git = async (...args: string[]): Promise<string> => (await exec('git', args, { cwd: dir, env })).stdout.trim()
    await git('init', '-q', 'repo')
    await exec('git', ['-C', 'repo', 'remote', 'add', 'origin', 'git@github.com:acme/widgets.git'], { cwd: dir, env })
    expect(await git('-C', 'repo', 'remote', 'get-url', '--push', 'origin')).toBe('https://github.com/acme/widgets.git')
    expect(await git('config', '--show-origin', '--get-all', 'credential.https://github.com.helper')).toBe(`file:${workerGitConfig(dir)}\t${credentialHelper('/opt/agent tools/gh')}`)
    expect(await git('config', '--get-all', 'credential.helper')).toBe('')
    await expect(git('config', 'commit.gpgsign')).rejects.toThrow()
    await expect(git('config', 'core.abbrev')).rejects.toThrow()
    expect(env).not.toHaveProperty('GIT_AUTHOR_NAME')
    expect(env).not.toHaveProperty('GIT_COMMITTER_EMAIL')
    await expect(git('-C', 'repo', 'commit', '--allow-empty', '-q', '-m', 'without identity')).rejects.toMatchObject({ stderr: expect.stringContaining('no email was given') })
    await git('-C', 'repo', '-c', 'user.name=Alice', '-c', 'user.email=alice@example.com', 'commit', '--allow-empty', '-q', '-m', 'with identity')
    expect(await git('-C', 'repo', 'log', '-1', '--format=%an <%ae> / %cn <%ce>')).toBe('Alice <alice@example.com> / Alice <alice@example.com>')
  })
})

it('fails instead of asking the operator\'s askpass helpers when the agent\'s credential helper has no answer', async () => {
  const log = join(dir, 'asked')
  const askpass = program(join(dir, 'askpass'), `echo asked >> ${log}; echo operator-secret`)
  const agent = program(join(dir, 'real', 'gh'), 'exit 0')
  const deployment = testDeployment({ stateDir: dir, github: { ...testDeployment().github, cli: agent } })
  await writeEnvironment(deployment, [])
  const env = workerEnv({ PATH: process.env.PATH, HOME: dir, GIT_ASKPASS: askpass, SSH_ASKPASS: askpass, ...agentVariables(dir) })
  await exec('git', ['init', '-q', 'repo'], { cwd: dir, env })
  await exec('git', ['-C', 'repo', 'config', 'core.askPass', askpass], { cwd: dir, env })
  const fill = exec('git', ['-C', 'repo', 'credential', 'fill'], { cwd: dir, env, timeout: 10_000 })
  fill.child.stdin?.end('protocol=https\nhost=github.com\n\n')
  await expect(fill).rejects.toMatchObject({ stderr: expect.stringContaining('terminal prompts disabled') })
  expect(() => readFileSync(log, 'utf8')).toThrow()
})

it('removes every spelling of a directory from PATH and keeps the other entries', () => {
  mkdirSync(join(dir, 'state', 'worker-bin'), { recursive: true })
  symlinkSync(join(dir, 'state'), join(dir, 'link'))
  const bin = join(dir, 'state', 'worker-bin')
  expect(withoutDirectory([`${bin}/`, join(dir, 'link', 'worker-bin'), '/usr/bin', 'node_modules/.bin'].join(':'), bin)).toBe('/usr/bin:node_modules/.bin')
})

/** Minimal SubprocessRuntime backed by child_process.spawn with an isolated global git config. */
const subprocess = (config: string): SubprocessRuntime => ({
  spawn: ({ argv, cwd }: { argv: readonly string[]; cwd: string }) => {
    const child = spawn(argv[0]!, argv.slice(1), { cwd, env: gitEnv({ GIT_CONFIG_GLOBAL: config, GIT_CONFIG_NOSYSTEM: '1' }) })
    const output = { stdout: '', stderr: '' }
    child.stdout.on('data', chunk => { output.stdout += String(chunk) })
    child.stderr.on('data', chunk => { output.stderr += String(chunk) })
    const reader = (name: 'stdout' | 'stderr') => ({ readFrom: () => ({ text: output[name], nextOffset: 0, lossy: false }) })
    const done = new Promise(resolve => child.on('close', code => resolve({ exitCode: code, signal: null })))
    return { done, collected: { stdout: reader('stdout'), stderr: reader('stderr') } }
  },
}) as unknown as SubprocessRuntime
describe('ticket directory check', () => {
  const signal = new AbortController().signal
  const env = () => gitEnv({ GIT_CONFIG_GLOBAL: join(dir, 'global'), GIT_CONFIG_NOSYSTEM: '1' })
  const git = (...args: string[]) => exec('git', args, { cwd: dir, env: env() })
  const check = (directory: string) => verifyDirectory(join(dir, directory), subprocess(join(dir, 'global')), signal)
  beforeEach(() => { writeFileSync(join(dir, 'global'), '[credential]\n\thelper = global-helper\n') })
  it('passes a directory whose repository adds no credentials, and one outside any repository', async () => {
    await git('init', '-q', 'repo')
    await expect(check('repo')).resolves.toBeUndefined()
    // When no config key matches at all, git config --get-regexp exits with status 1.
    writeFileSync(join(dir, 'global'), '')
    await expect(check('real')).resolves.toBeUndefined()
  })
  it('names the credential settings of the repository\'s own configuration', async () => {
    await git('init', '-q', 'repo')
    await git('-C', 'repo', 'config', 'http.https://github.com/.extraheader', 'AUTHORIZATION: basic x')
    await expect(check('repo')).rejects.toThrow('sets http.https://github.com/.extraheader')
  })
  it('fails when git cannot read the repository\'s configuration, instead of passing it', async () => {
    await git('init', '-q', 'repo')
    writeFileSync(join(dir, 'repo', '.git', 'config'), '[core\n')
    await expect(check('repo')).rejects.toThrow(/bad config/)
  })
  it('reports a failed command\'s exit status', async () => {
    const failing = ['sh', '-c', 'echo nope >&2; exit 3']
    const error = await runAsWorker(subprocess(join(dir, 'global')), failing, dir, signal).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(CliError)
    expect(error).toMatchObject({ message: 'nope', exitCode: 3 })
  })
})

describe('the repository the host\'s environment names', () => {
  it('is left alone by the tests\' git and named in no worker\'s environment, as when they run inside `git rebase --exec`', async () => {
    // A scratch repository stands for the one under test, which `git rebase --exec` names in GIT_DIR and GIT_WORK_TREE.
    await exec('git', ['init', '-q', 'scratch'], { cwd: dir, env: gitEnv() })
    const config = () => readFileSync(join(dir, 'scratch', '.git', 'config'), 'utf8')
    const before = config()
    vi.stubEnv('GIT_DIR', join(dir, 'scratch', '.git')); vi.stubEnv('GIT_WORK_TREE', join(dir, 'scratch'))
    // The operator's limit on git's search for a repository names none, and stays.
    vi.stubEnv('GIT_CEILING_DIRECTORIES', dir)
    try {
      // What the tests do: a repository of their own, checked as a ticket directory.
      await exec('git', ['init', '-q', 'repo'], { cwd: dir, env: gitEnv({ GIT_CONFIG_GLOBAL: join(dir, 'global'), GIT_CONFIG_NOSYSTEM: '1' }) })
      writeFileSync(join(dir, 'global'), '')
      await expect(verifyDirectory(join(dir, 'repo'), subprocess(join(dir, 'global')), new AbortController().signal)).resolves.toBeUndefined()
      expect(readdirSync(join(dir, 'repo'))).toContain('.git')
      expect(config()).toBe(before)
      // The worker environment, which workers' shells and the host's own commands get, names no repository.
      const env = workerEnv({ ...process.env, ...agentVariables(dir) })
      for (const name of GIT_LOCATION) expect(env, name).not.toHaveProperty(name)
      expect(env.GIT_CEILING_DIRECTORIES).toBe(dir)
    } finally { vi.unstubAllEnvs() }
  })
})

describe('the prepare shell', () => {
  it('runs a prepare command through the shell the platform has, and cmd where Windows has no sh', () => {
    expect(shellArgv('echo hi', 'linux', '')).toEqual(['sh', '-c', 'echo hi'])
    expect(shellArgv('echo hi', 'darwin', '')).toEqual(['sh', '-c', 'echo hi'])
    expect(shellArgv('echo hi', 'win32', '')).toEqual(['cmd.exe', '/d', '/s', '/c', 'echo hi'])
    // Git for Windows supplies sh.exe, and its syntax wins where it is installed.
    const bin = mkdtempSync(join(tmpdir(), 'prepare-shell-'))
    try {
      writeFileSync(join(bin, 'sh.exe'), '')
      expect(shellArgv('echo hi', 'win32', bin)).toEqual(['sh', '-c', 'echo hi'])
      expect(shellArgv('echo "quoted" && run', 'win32', bin)).toEqual(['sh', '-c', 'echo "quoted" && run'])
    } finally { rmSync(bin, { recursive: true, force: true }) }
  })
})