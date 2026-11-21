// Native msfconsole wrapper for the RedTeam gate.
//
// Design:
//   - No shell. msfconsole is launched as the embedded ruby interpreter running the framework's
//     msfconsole script (the same thing msfconsole.bat does), with an argument array. Node will
//     not spawn a .bat without a shell, and avoiding cmd.exe removes quoting injection entirely.
//   - Commands are never built by string interpolation of model text. Every module name, option
//     name and option value is checked against a strict pattern before it reaches a resource
//     file. Resource files are ERB-processed by msfconsole, so `<`, `%`, `#{` and `;` are refused.
//   - The command grammar is a whitelist: use / set / setg / unset / run / sessions -l / exit -y.
//     Anything else (db_nmap, irb, shell, resource, spool, ...) is rejected, so no host can be
//     reached through a side channel that targetsForMsf would not see.
//   - Every host named by a HOST option is returned by targetsForMsf so the caller can gate it
//     with decideScope. runMsf and decideMsfScope both go through that gate; runMsf refuses to
//     spawn anything the gate denies.
//   - Module scope in this pass: auxiliary/scanner/* only. Exploit, post and payload modules are
//     rejected by buildCommands.

import { spawn } from 'node:child_process'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, delimiter } from 'node:path'
import { decideScope } from '../../scope.mjs'

export const MSF_ROOT = 'C:\\metasploit\\framework'
export const MSF_RUBY = `${MSF_ROOT}\\embedded\\bin\\ruby.exe`
export const MSF_SCRIPT = `${MSF_ROOT}\\embedded\\framework\\msfconsole`
export const MSF_BIN = `${MSF_ROOT}\\embedded\\bin`

// Exploit modules are allowed. Every target option (RHOST, RHOSTS, LHOST, VHOST) is still checked by the scope gate,
// so an exploit runs only against a loopback lab host or an ownership-verified domain. post/, payload/ and the
// rest of auxiliary/ are refused.
export const ALLOWED_MODULE_PREFIXES = ['auxiliary/scanner/', 'exploit/'];

const MODULE_RE = /^[a-z0-9_]+(?:\/[a-z0-9_]+)+$/;
const OPTION_NAME_RE = /^[A-Z][A-Z0-9_]{0,40}$/;
// Printable, no whitespace, no ERB/shell/Ruby/resource metacharacters.
const OPTION_VALUE_RE = /^[A-Za-z0-9._:,\-\/]{1,512}$/;
const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
const IPV6_RE = /^[0-9a-f]*(?::[0-9a-f]*){2,7}$/i;
const HOSTNAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i;
const MAX_HOSTS_PER_OPTION = 64;
const MAX_OUTPUT = 4 * 1024 * 1024;
const ANSI_RE = /\u001b\[[0-9;?]*[ -/]*[@-~]/g;

/** A host option name is any option whose name contains HOST (RHOST, RHOSTS, VHOST, ...). */
export function isHostOption(name) {
  return String(name).toUpperCase().includes('HOST');
}

function validateModule(module) {
  if (typeof module !== 'string' || !MODULE_RE.test(module)) {
    throw new Error(`invalid module name: ${JSON.stringify(String(module).slice(0, 80))}`);
  }
  if (!ALLOWED_MODULE_PREFIXES.some((p) => module.startsWith(p))) {
    throw new Error(`module ${module} is outside the allowed scope (${ALLOWED_MODULE_PREFIXES.join(', ')} only in this pass)`);
  }
  return module;
}

function validateOptionName(name) {
  const upper = String(name).toUpperCase();
  if (!OPTION_NAME_RE.test(upper)) throw new Error(`invalid option name: ${JSON.stringify(String(name).slice(0, 60))}`);
  return upper;
}

function validateOptionValue(name, value) {
  if (typeof value === 'number' && Number.isFinite(value)) value = String(value);
  if (typeof value !== 'string' || !OPTION_VALUE_RE.test(value) || value.includes('://')) {
    throw new Error(`invalid value for ${name}: ${JSON.stringify(String(value).slice(0, 80))}`);
  }
  if (isHostOption(name)) {
    const items = value.split(',');
    if (items.length > MAX_HOSTS_PER_OPTION) throw new Error(`${name}: more than ${MAX_HOSTS_PER_OPTION} hosts`);
    for (const item of items) {
      if (!isSingleHost(item)) {
        throw new Error(`${name}: ${JSON.stringify(item.slice(0, 80))} is not a single host (ranges, CIDR and file: forms are refused)`);
      }
    }
  }
  return value;
}

/** A single IPv4 address, IPv6 literal, or hostname whose last label contains a letter. */
function isSingleHost(item) {
  if (IPV4_RE.test(item)) return true;
  if (item.includes(':')) return IPV6_RE.test(item);
  if (!HOSTNAME_RE.test(item)) return false;
  const last = item.split('.').pop();
  return /[a-z]/i.test(last);
}

/**
 * Build the resource-file command list for one scanner run.
 * @param {{module: string, options?: Record<string, string|number>}} spec
 * @returns {string[]} command lines, in order
 */
export function buildCommands(spec) {
  if (!spec || typeof spec !== 'object') throw new Error('spec must be an object');
  const module = validateModule(spec.module);
  const lines = [`use ${module}`];
  for (const [rawName, rawValue] of Object.entries(spec.options ?? {})) {
    const name = validateOptionName(rawName);
    const value = validateOptionValue(name, rawValue);
    lines.push(`set ${name} ${value}`);
  }
  lines.push('run', 'sessions -l', 'exit -y');
  return lines;
}

/**
 * Parse one command line against the whitelist grammar. Throws on anything else.
 * @returns {{verb: string, name?: string, value?: string}}
 */
export function parseCommandLine(line) {
  const tokens = String(line).split(' ');
  const [verb, ...rest] = tokens;
  switch (verb) {
    case 'use': {
      if (rest.length !== 1) throw new Error(`malformed use line`);
      return { verb, value: validateModule(rest[0]) };
    }
    case 'set':
    case 'setg': {
      if (rest.length !== 2) throw new Error(`malformed ${verb} line`);
      const name = validateOptionName(rest[0]);
      return { verb, name, value: validateOptionValue(name, rest[1]) };
    }
    case 'unset': {
      if (rest.length !== 1) throw new Error('malformed unset line');
      return { verb, name: validateOptionName(rest[0]) };
    }
    case 'run':
      if (rest.length !== 0) throw new Error('malformed run line');
      return { verb };
    case 'sessions':
      if (rest.length === 1 && rest[0] === '-l') return { verb };
      throw new Error('only "sessions -l" is allowed');
    case 'exit':
      if (rest.length === 1 && rest[0] === '-y') return { verb };
      throw new Error('only "exit -y" is allowed');
    default:
      throw new Error(`command not in the whitelist: ${JSON.stringify(String(verb).slice(0, 40))}`);
  }
}

/**
 * Every host named by a HOST option (RHOST, RHOSTS, ...) in the command list.
 * Throws if any line is outside the grammar, so a malformed list fails closed.
 * @param {string[]} commands
 * @returns {string[]} lowercase, deduplicated hosts; empty when no host option is set
 */
export function targetsForMsf(commands) {
  if (!Array.isArray(commands)) throw new Error('commands must be an array of strings');
  const hosts = new Set();
  for (const line of commands) {
    const parsed = parseCommandLine(line);
    if ((parsed.verb === 'set' || parsed.verb === 'setg') && isHostOption(parsed.name)) {
      for (const item of parsed.value.split(',')) hosts.add(item.toLowerCase());
    }
  }
  return [...hosts];
}

/**
 * Gate a msfconsole request with decideScope before anything runs.
 * @param {object} spec - same shape as buildCommands
 * @param {{isVerified: (domain: string) => Promise<boolean>}} gate - must fail closed
 * @returns {Promise<{kind: 'allow', targets: string[]} | {kind: 'deny', reason: string}>}
 */
export async function decideMsfScope(spec, gate) {
  let targets;
  try {
    targets = targetsForMsf(buildCommands(spec));
  } catch (err) {
    return { kind: 'deny', reason: `metasploit request rejected: ${err.message}` };
  }
  const decision = await decideScope({ toolName: 'msfconsole', arguments: { targets } }, gate);
  return decision.kind === 'allow' ? { kind: 'allow', targets } : decision;
}

/** Parse msfconsole output into module results and sessions. Pure function. */
export function parseOutput(raw) {
  const text = String(raw).replace(ANSI_RE, '').replace(/\r/g, '');
  const openPorts = [];
  for (const m of text.matchAll(/^\[\+\]\s+(\S+):(\d{1,5})\s+-\s+(.*)$/gm)) {
    openPorts.push({ host: m[1], port: Number(m[2]), detail: m[3].trim() });
  }
  const positives = [...text.matchAll(/^\[\+\]\s+(.*)$/gm)].map((m) => m[1].trim());
  const errors = [...text.matchAll(/^\[[-!]\]\s+(.*)$/gm)].map((m) => m[1].trim()).slice(0, 50);
  const sessions = new Map();
  for (const m of text.matchAll(/(Command shell|Meterpreter|shell) session (\d+) opened \(([^)]*)\)/gi)) {
    sessions.set(Number(m[2]), { id: Number(m[2]), type: m[1].toLowerCase(), info: m[3] });
  }
  for (const m of text.matchAll(/^\s*(\d+)\s+(?:\S+\s+)?(shell|meterpreter)\s+(\S.*)$/gim)) {
    const id = Number(m[1]);
    if (!sessions.has(id)) sessions.set(id, { id, type: m[2].toLowerCase(), info: m[3].trim() });
  }
  return {
    completed: /Auxiliary module execution completed/i.test(text),
    openPorts,
    positives,
    errors,
    sessions: [...sessions.values()],
  };
}

/**
 * Run one scanner module through msfconsole, after the scope gate.
 * @param {{module: string, options?: Record<string, string|number>}} spec
 * @param {{gate: {isVerified: (domain: string) => Promise<boolean>}, timeoutMs?: number, workDir?: string, ruby?: string, script?: string, bin?: string}} opts
 * @returns {Promise<{status: 'ok'|'error'|'timeout'|'denied', reason?: string, exitCode?: number|null, commands?: string[], stdout?: string, stderr?: string, parsed?: ReturnType<typeof parseOutput>}>}
 */
export async function runMsf(spec, opts = {}) {
  if (!opts.gate) throw new Error('runMsf requires a scope gate');
  const decision = await decideMsfScope(spec, opts.gate);
  if (decision.kind !== 'allow') return { status: 'denied', reason: decision.reason };

  const commands = buildCommands(spec);
  const ruby = opts.ruby ?? MSF_RUBY;
  const script = opts.script ?? MSF_SCRIPT;
  const bin = opts.bin ?? MSF_BIN;
  const timeoutMs = opts.timeoutMs ?? 170000;

  const workDir = await mkdtemp(join(opts.workDir ?? tmpdir(), 'dsh-msf-'));
  const rcPath = join(workDir, 'run.rc');
  try {
    await writeFile(rcPath, `${commands.join('\n')}\n`, { encoding: 'utf8', mode: 0o600 });
    // Mirror msfconsole.bat: `set X=` in cmd deletes X, so drop these variables rather than blank them.
    const env = { ...process.env };
    for (const key of ['GEM_HOME', 'GEM_PATH', 'GEM_ROOT', 'RUBY_ENGINE', 'RUBY_ROOT']) delete env[key];
    const pathKey = Object.keys(env).find((k) => k.toUpperCase() === 'PATH') ?? 'PATH';
    env[pathKey] = `${bin}${delimiter}${env[pathKey] ?? ''}`;
    const { exitCode, stdout, stderr, timedOut } = await spawnCapture(ruby, [script, '-q', '-r', rcPath], {
      cwd: workDir, env, timeoutMs,
    });
    const parsed = parseOutput(stdout);
    if (timedOut) return { status: 'timeout', exitCode, commands, stdout, stderr, parsed };
    return { status: exitCode === 0 ? 'ok' : 'error', exitCode, commands, stdout, stderr, parsed };
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
}

function spawnCapture(command, args, { cwd, env, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, env, shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, timeoutMs);
    child.stdout.on('data', (d) => { if (stdout.length < MAX_OUTPUT) stdout += d.toString('utf8'); });
    child.stderr.on('data', (d) => { if (stderr.length < MAX_OUTPUT) stderr += d.toString('utf8'); });
    child.on('error', (err) => { clearTimeout(timer); reject(err); });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ exitCode: code, stdout, stderr, timedOut });
    });
  });
}
