// AlterEgo native bridge (read-only allowlist).
//
// Calls the same Python wrapper functions the AlterEgo MCP server registers (tool_wrappers.ALL_TOOLS),
// in-process in a short-lived Python child. No MCP connection, no HTTP, no bearer token.
// The child runs adapter.py, which refuses anything outside its own copy of the allowlist.
//
// Config (environment):
//   ALTEREGO_PC_AGENT_DIR  folder containing tool_wrappers.py (default: <home>/alterego/pc-agent)
//   ALTEREGO_PYTHON        python executable (default: python)

import { spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { READ_ONLY_ALLOWLIST, isAllowlisted, validateArgs } from './allowlist.mjs';

export const ADAPTER_PATH = path.join(path.dirname(fileURLToPath(import.meta.url)), 'adapter.py');
const DEFAULT_TIMEOUT_MS = 60_000;
const MAX_OUTPUT_BYTES = 32 * 1024 * 1024; // screenshots arrive as base64

export function resolvePcAgentDir(env = process.env) {
  return env.ALTEREGO_PC_AGENT_DIR || path.join(os.homedir(), 'alterego', 'pc-agent');
}

/**
 * Default invoker: runs adapter.py as a child process with JSON on stdin.
 * Resolves with the adapter's parsed JSON envelope: { ok, result } or { ok:false, error }.
 */
export function invokePcAgent(tool, args, { env = process.env, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const python = env.ALTEREGO_PYTHON || 'python';
  const pcAgentDir = resolvePcAgentDir(env);
  return new Promise((resolve, reject) => {
    const child = spawn(python, [ADAPTER_PATH], {
      shell: false,
      windowsHide: true,
      env: { ...env, ALTEREGO_PC_AGENT_DIR: pcAgentDir, PYTHONIOENCODING: 'utf-8' },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let size = 0;
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn(value);
    };
    const timer = setTimeout(() => {
      child.kill();
      finish(reject, new Error(`alterego ${tool} timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      size += Buffer.byteLength(chunk);
      if (size > MAX_OUTPUT_BYTES) {
        child.kill();
        finish(reject, new Error(`alterego ${tool} output exceeded ${MAX_OUTPUT_BYTES} bytes`));
        return;
      }
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      // Keep stderr short; it can contain tracebacks but never the session token.
      if (stderr.length < 4000) stderr += chunk;
    });
    child.on('error', (err) => finish(reject, new Error(`cannot start ${python}: ${err.code ?? err.message}`)));
    child.on('close', (code) => {
      let envelope = null;
      try {
        envelope = JSON.parse(stdout.trim().split('\n').pop() || 'null');
      } catch {
        envelope = null;
      }
      if (!envelope || typeof envelope !== 'object') {
        finish(reject, new Error(`alterego ${tool} produced no JSON (exit ${code}): ${stderr.slice(0, 300)}`));
        return;
      }
      finish(resolve, envelope);
    });
    child.stdin.on('error', () => {}); // child may exit before reading stdin
    child.stdin.end(JSON.stringify({ tool, args }));
  });
}

/**
 * Build the native bridge. `invoke` is injectable so tests never touch the PC.
 * call(name, args) never throws for policy refusals; it returns { ok:false, refused:true, error }.
 */
export function createAlterEgoBridge({ invoke = invokePcAgent, allowlist = READ_ONLY_ALLOWLIST } = {}) {
  const isAllowed = (name) => Object.prototype.hasOwnProperty.call(allowlist, name) && isAllowlisted(name);

  async function call(name, args) {
    if (!isAllowed(name)) {
      return { ok: false, refused: true, tool: String(name), error: `tool not allowlisted: ${String(name)}` };
    }
    const checked = validateArgs(name, args);
    if (!checked.ok) return { ok: false, refused: false, tool: name, error: checked.error };
    let envelope;
    try {
      envelope = await invoke(name, checked.args);
    } catch (err) {
      return { ok: false, refused: false, tool: name, error: err.message };
    }
    if (!envelope || typeof envelope !== 'object') {
      return { ok: false, refused: false, tool: name, error: 'invalid envelope from bridge' };
    }
    if (envelope.ok === false || envelope.error !== undefined) {
      return { ok: false, refused: Boolean(envelope.refused), tool: name, error: String(envelope.error ?? 'unknown error') };
    }
    if (envelope.result === undefined || envelope.result === null || typeof envelope.result !== 'object') {
      return { ok: false, refused: false, tool: name, error: 'bridge returned no result object' };
    }
    // AlterEgo wrappers report tool-level failures (including operator denials) as {"error": "..."}.
    if (typeof envelope.result.error === 'string') {
      return { ok: false, refused: false, tool: name, error: envelope.result.error };
    }
    return { ok: true, tool: name, result: envelope.result };
  }

  // Native tool descriptors in the executor's shape. Registration is the owner's call (tools.mjs is not edited here).
  const tools = Object.entries(allowlist).map(([name, spec]) => ({
    name: `alterego_${name}`,
    alterego_tool: name,
    description: spec.description,
    parameters: spec.parameters,
    risk: 'read',
    source: 'alterego',
    execute: (args) => call(name, args),
  }));

  return { call, tools, names: Object.keys(allowlist) };
}
