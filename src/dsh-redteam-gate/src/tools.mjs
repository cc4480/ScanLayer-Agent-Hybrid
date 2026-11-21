// Native scanner tools for the harness. Each tool name equals the binary name the scope gate matches
// (ACTIVE_TOOLS in scope.mjs), so the verified-scope check applies to every call before it runs.
// john is the exception: it is offline (no network target) and is not in ACTIVE_TOOLS.
import path from 'node:path'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { runTool, splitFlags } from './runner.mjs'
import { renderText } from './render.mjs'

export const BINARIES = {
  nmap: 'C:\\Program Files (x86)\\Nmap\\nmap.exe',
  nuclei: 'C:\\tools\\nuclei.exe',
  ffuf: 'C:\\Users\\Cho-zen\\AppData\\Local\\Microsoft\\WinGet\\Packages\\ffuf.ffuf_Microsoft.Winget.Source_8wekyb3d8bbwe\\ffuf.exe',
  gobuster: 'C:\\tools\\gobuster.exe',
  sqlmap: 'C:\\Users\\Cho-zen\\AppData\\Local\\Programs\\Python\\Python312\\Scripts\\sqlmap.exe',
  john: 'C:\\tools\\john.exe',
  // nikto is a batch file, so it only runs through cmd.exe (see niktoLaunch).
  nikto: 'C:\\tools\\nikto.bat',
}

export const CMD_EXE = 'C:\\Windows\\System32\\cmd.exe'
export const PERL_EXE = 'C:\\Strawberry\\perl\\bin\\perl.exe'
export const NIKTO_SCRIPT = 'C:\\tools\\nikto2\\program\\nikto.pl'

const OUTPUT = {
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      exitCode: { type: 'number' },
      stdout: { type: 'string' },
      stderr: { type: 'string' },
      truncated: { type: 'boolean' },
      timedOut: { type: 'boolean' },
    },
  },
  render: renderText,
}

/** Build the argv for one tool from its target and flags. Targets go in as a single argument, never a shell string. */
export function argvFor(tool, target, flags) {
  const extra = splitFlags(flags)
  switch (tool) {
    case 'nmap':
      return [...extra, target]
    case 'nuclei':
      return ['-u', target, ...extra]
    case 'ffuf':
      return ['-u', target, ...extra]
    case 'gobuster':
      return ['dir', '-u', target, ...extra]
    default:
      throw new Error(`unknown tool ${tool}`)
  }
}

// ---------- shared target and flag checks for the new tools ----------

const MAX_TARGET = 2048
// A URL target for sqlmap: http(s), no whitespace, quotes, pipes, or other shell-significant characters.
// '&' and '=' stay allowed because they are normal in query strings (argv is never shell-parsed).
const URL_TARGET_RE = /^https?:\/\/[^\s"'`<>|;\0]+$/i

export function validateUrlTarget(target) {
  const t = String(target ?? '')
  if (t.length === 0 || t.length > MAX_TARGET || !URL_TARGET_RE.test(t)) {
    throw new Error('target must be an http(s) URL with no spaces or shell characters')
  }
  return t
}

// Flags that would run commands, write files, pull in more targets, or route through another host.
const SQLMAP_DENIED = new Set([
  '-u', '--url', '-r', '-m', '-l', '-g', '-d',
  '--sitemap-url', '--proxy', '--proxy-file', '--tor', '--second-url', '--second-req',
  '--file-write', '--file-dest', '--eval', '--sql-shell', '--wizard',
])

/** Refuse sqlmap flags that run commands, write files, or name extra targets. Returns the tokens unchanged. */
export function checkSqlmapFlags(tokens) {
  for (const tok of tokens) {
    const name = tok.split('=')[0].toLowerCase()
    if (/:\/\/|^\\\\/.test(tok)) throw new Error('sqlmap flags must not name URLs or UNC paths; the target is set by the target field')
    if (name.startsWith('--os-') || SQLMAP_DENIED.has(name)) {
      throw new Error(`sqlmap flag ${name} is not allowed by the harness`)
    }
    // Single-dash short options that take a file of targets, a request file, a log, or a dork.
    if (/^-[rmlg]/.test(tok)) throw new Error(`sqlmap flag ${tok} is not allowed by the harness`)
  }
  return tokens
}

/** argv for sqlmap: target as one argument, --batch so it never waits for input, then checked flags. */
export function sqlmapArgv(target, flags) {
  const t = validateUrlTarget(target)
  const extra = checkSqlmapFlags(splitFlags(flags))
  return ['-u', t, '--batch', ...extra]
}

// nikto: strict host or URL pattern. Every character here is safe in a cmd.exe command line
// (no & | < > ^ % ! " spaces), so the target cannot inject into the fixed command.
const NIKTO_URL_RE = /^https?:\/\/[A-Za-z0-9][A-Za-z0-9.-]*(?::\d{1,5})?(?:\/[A-Za-z0-9._~/-]*)?$/
const NIKTO_HOST_RE = /^[A-Za-z0-9][A-Za-z0-9.-]*(?::\d{1,5})?$/

export function validateNiktoTarget(target) {
  const t = String(target ?? '')
  if (t.length === 0 || t.length > MAX_TARGET || !(NIKTO_URL_RE.test(t) || NIKTO_HOST_RE.test(t))) {
    throw new Error('nikto target must be an http(s) URL or host[:port] with no spaces or shell characters')
  }
  return t
}

/**
 * Launch spec for nikto: cmd.exe /d /s /c with one fixed command line. The only variable part is the
 * validated target. Paths contain no spaces, so no inner quoting is needed.
 */
export function niktoLaunch(target) {
  const t = validateNiktoTarget(target)
  // Runs the nikto2 script directly under Perl (no cmd.exe, no batch file). The old nikto.bat pointed at a missing script.
  return { binary: PERL_EXE, argv: [NIKTO_SCRIPT, '-h', t, '-nointeractive'] }
}

/**
 * argv for john in offline --show mode. The hash file must sit inside the workspace (cwd by default).
 * No free-form flags are accepted, so no option can load a remote resource or run an external mode.
 */
export function johnArgv(hashFile, format, workspace = process.cwd()) {
  const raw = String(hashFile ?? '')
  if (raw.length === 0 || raw.length > MAX_TARGET || /[\0\r\n"'`;&|<>^%!]/.test(raw) || raw.includes('://') || raw.startsWith('\\\\')) {
    throw new Error('hash file path contains disallowed characters or names a remote resource')
  }
  const root = path.resolve(workspace)
  const abs = path.resolve(root, raw)
  const rel = path.relative(root, abs)
  if (rel === '' || path.isAbsolute(rel) || rel.split(path.sep)[0] === '..') {
    throw new Error('hash file must be inside the workspace')
  }
  const argv = ['--show']
  if (format !== undefined && format !== null && String(format) !== '') {
    const f = String(format)
    if (!/^[A-Za-z0-9_.+-]{1,64}$/.test(f)) throw new Error('john format must be a plain format name')
    argv.push(`--format=${f}`)
  }
  argv.push(abs)
  return argv
}

// ---------- tool definitions ----------

function scannerTool(name, description) {
  return defineTool({
    name,
    description,
    parameters: {
      target: {
        type: 'string',
        required: true,
        description: 'Target: a host, IP, or URL. Must be a lab host or an ownership-verified domain; the scope gate checks it before this runs.',
      },
      flags: {
        type: 'string',
        description: 'Extra options as plain space-separated tokens (no shell operators).',
      },
    },
    output: OUTPUT,
    async execute(args, exec) {
      const argv = argvFor(name, String(args.target), args.flags)
      const r = await runTool(BINARIES[name], argv, { timeoutMs: 600_000, signal: exec?.signal })
      return {
        exitCode: r.exitCode ?? -1,
        stdout: r.stdout,
        stderr: r.stderr,
        truncated: r.truncated,
        timedOut: r.timedOut,
      }
    },
  })
}

function sqlmapTool() {
  return defineTool({
    name: 'sqlmap',
    description: 'SQL injection testing with sqlmap (native). Runs non-interactively (--batch). Command execution and file-write flags are refused.',
    parameters: {
      target: {
        type: 'string',
        required: true,
        description: 'Target URL (http or https). Must be a lab host or an ownership-verified domain; the scope gate checks it.',
      },
      flags: {
        type: 'string',
        description: 'Extra sqlmap options as plain space-separated tokens (for example --level=2 --risk=1 --dbs).',
      },
    },
    output: OUTPUT,
    async execute(args, exec) {
      const argv = sqlmapArgv(args.target, args.flags)
      const r = await runTool(BINARIES.sqlmap, argv, { timeoutMs: 900_000, signal: exec?.signal })
      return toResult(r)
    },
  })
}

function niktoTool() {
  return defineTool({
    name: 'nikto',
    description: 'Web server scan with nikto (native), run through cmd.exe with a fixed command. Takes a single target only.',
    parameters: {
      target: {
        type: 'string',
        required: true,
        description: 'Target: an http(s) URL, or host[:port]. Must be a lab host or an ownership-verified domain; the scope gate checks it.',
      },
    },
    output: OUTPUT,
    async execute(args, exec) {
      const { binary, argv } = niktoLaunch(args.target)
      const r = await runTool(binary, argv, { timeoutMs: 900_000, signal: exec?.signal })
      return toResult(r)
    },
  })
}

function johnTool() {
  return defineTool({
    name: 'john',
    description: 'Offline John the Ripper: shows cracked passwords from a hash file in the workspace (john --show). No network target; read-only.',
    parameters: {
      hashFile: {
        type: 'string',
        required: true,
        description: 'Path to a hash file inside the workspace (relative paths resolve from the workspace root).',
      },
      format: {
        type: 'string',
        description: 'Optional john format name, for example raw-md5.',
      },
    },
    output: OUTPUT,
    async execute(args, exec) {
      const argv = johnArgv(args.hashFile, args.format)
      // john is a Cygwin build: its DLLs live in the Metasploit bundle, so that folder must be on PATH for the child.
      const env = { ...process.env, PATH: `C:\\metasploit\\john\\bin;${process.env.PATH ?? ''}` }
      const r = await runTool(BINARIES.john, argv, { timeoutMs: 120_000, signal: exec?.signal, env })
      return toResult(r)
    },
  })
}

function toResult(r) {
  return {
    exitCode: r.exitCode ?? -1,
    stdout: r.stdout,
    stderr: r.stderr,
    truncated: r.truncated,
    timedOut: r.timedOut,
  }
}

export const nativeTools = [
  scannerTool('nmap', 'Port and service scan with nmap (native). Use -sT on Windows; -Pn skips host discovery.'),
  scannerTool('nuclei', 'Template-based vulnerability scan with nuclei (native).'),
  scannerTool('ffuf', 'Web fuzzing with ffuf (native). Put FUZZ in the target URL.'),
  scannerTool('gobuster', 'Directory brute-force with gobuster (native).'),
  sqlmapTool(),
  niktoTool(),
  johnTool(),
]
