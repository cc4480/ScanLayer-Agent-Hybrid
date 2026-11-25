'use strict';
// Parent side of `execute`: spawns a fresh, confined child per run, serves its
// tool calls through the Gate one at a time, and enforces the limits:
//   program size 32,768 chars · wall clock 120 s default / 300 s ceiling
//   (enforced by SIGKILL from here, so tight loops and stuck awaits both die)
//   200 tool calls per run · heap cap · return value capped at 40,000 chars.
// Any gate denial aborts the run immediately (fail closed) and is receipted.
const { spawn, spawnSync } = require('child_process');
const path = require('path');
const crypto = require('crypto');
const { sha256 } = require('./canon');
const { childEnv } = require('./child-env');

const LIMITS = { programChars: 32768, defaultTimeoutMs: 120000, maxTimeoutMs: 300000, maxCalls: 200, resultChars: 40000, heapMb: 128 };
const CHILD = path.join(__dirname, 'sandbox-child.js');

let netnsSupport = null;
function netnsAvailable() {
  if (netnsSupport !== null) return netnsSupport;
  netnsSupport = false;
  if (process.platform !== 'linux') return false;
  const r = spawnSync('unshare', ['-n', 'true'], { stdio: 'ignore' });
  netnsSupport = r.status === 0;
  return netnsSupport;
}

function childCommand(cfg) {
  const major = Number(process.versions.node.split('.')[0]);
  const perm = major >= 24 ? '--permission' : '--experimental-permission';
  const nodeArgs = ['--no-warnings', perm, `--allow-fs-read=${CHILD}`, '--disallow-code-generation-from-strings', `--max-old-space-size=${LIMITS.heapMb}`, '--max-semi-space-size=8', CHILD];
  const useNetns = cfg.netns === true || (cfg.netns !== false && netnsAvailable());
  if (useNetns) return { cmd: 'unshare', args: ['-n', process.execPath, ...nodeArgs], network: 'denied (empty network namespace)' };
  return { cmd: process.execPath, args: nodeArgs, network: 'not denied at OS level (no netns on this host); no network API reachable from the program' };
}

function sandboxPosture(cfg = {}) {
  const c = childCommand(cfg);
  return { process: `separate node process per run, ${process.platform === 'win32' ? 'env limited to what Windows needs' : 'empty env'}, permission model (fs/child_process/worker denied), host codegen disabled`, network: c.network, limits: LIMITS };
}

/**
 * @returns {Promise<{ok, value?, truncated?, calls, run_id, error?:{kind,message,tool?,call_index?,receipt?}}>}
 */
function runProgram({ program, gate, audit, seat, catalogSnapshot, manifest, timeoutMs, cfg = {}, actions = {} }) {
  const run_id = 'run_' + crypto.randomBytes(6).toString('hex');
  const program_sha256 = sha256(program || '');
  if (typeof program !== 'string' || !program.trim()) return Promise.resolve({ invalid: 'program must be a non-empty string' });
  if (program.length > LIMITS.programChars) return Promise.resolve({ invalid: `program exceeds ${LIMITS.programChars} chars` });
  const timeout = Math.max(100, Math.min(LIMITS.maxTimeoutMs, Number(timeoutMs) || LIMITS.defaultTimeoutMs));

  const start = audit.append({ kind: 'execute_start', seat, run_id, program_sha256, program_chars: program.length, timeout_ms: timeout });
  const t0 = Date.now();
  const callReceipts = [];
  let calls = 0;

  return new Promise((resolve) => {
    const { cmd, args } = childCommand(cfg);
    const child = spawn(cmd, args, { stdio: ['ignore', 'ignore', 'pipe', 'ipc'], env: childEnv() });
    let stderr = '';
    child.stderr.on('data', (d) => { if (stderr.length < 4000) stderr += d; });
    let finished = false;
    let queue = Promise.resolve();

    const finish = (out) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      try { child.kill('SIGKILL'); } catch {}
      const decision = out.ok ? 'allow' : (out.error.kind === 'scope_denied' ? 'deny_scope' : out.error.kind);
      const end = audit.append({
        kind: 'execute_end', seat, run_id, program_sha256, decision, calls,
        call_root: sha256(callReceipts.join('\n')), call_receipts: callReceipts,
        result_chars: out.ok ? out.value_chars : 0, truncated: !!out.truncated,
        error: out.ok ? null : { kind: out.error.kind, message: out.error.message, tool: out.error.tool || null, call_index: out.error.call_index ?? null },
        duration_ms: Date.now() - t0, start_receipt: start.hash,
      });
      delete out.value_chars;
      resolve({ ...out, calls, run_id, receipt: end.hash });
    };

    const timer = setTimeout(() => finish({ ok: false, error: { kind: 'timeout', message: `run exceeded ${timeout} ms wall clock; process killed` } }), timeout);

    child.on('message', (m) => {
      if (finished) return;
      if (m.type === 'ready') {
        child.send({ type: 'run', program, catalog: JSON.stringify(catalogSnapshot), manifest: JSON.stringify(manifest || {}), seed: 1, syncTimeoutMs: Math.min(timeout, 30000) });
      } else if (m.type === 'call') {
        queue = queue.then(async () => {
          if (finished) return;
          const call_index = ++calls;
          if (call_index > LIMITS.maxCalls) { finish({ ok: false, error: { kind: 'limit', message: `more than ${LIMITS.maxCalls} tool calls in one run` } }); return; }
          let parsed;
          try { parsed = JSON.parse(m.args); } catch { parsed = { args: null }; }
          const r = await gate.call({ seat, ident: m.tool, args: parsed.args, opts: parsed.opts || {}, run_id, call_index });
          if (finished) return;
          callReceipts.push(r.receipt);
          if (r.denied) {
            finish({ ok: false, error: { kind: 'scope_denied', code: r.code, message: r.reason, tool: m.tool, call_index, receipt: r.receipt } });
            return;
          }
          if (r.error) {
            child.send({ type: 'result', id: m.id, json: JSON.stringify({ error: true, kind: 'tool_error', reason: r.reason, receipt: r.receipt }) });
            return;
          }
          child.send({ type: 'result', id: m.id, json: JSON.stringify(r) });
        });
      } else if (m.type === 'action') {
        queue = queue.then(async () => {
          if (finished) return;
          const fn = Object.prototype.hasOwnProperty.call(actions, m.name) ? actions[m.name] : undefined;
          let reply;
          if (!fn) reply = { error: `unknown action: ${m.name}` };
          else {
            try { reply = { value: await fn(seat) }; } catch (e) { reply = { error: e.message }; }
          }
          if (!finished) child.send({ type: 'result', id: m.id, json: JSON.stringify(reply) });
        });
      } else if (m.type === 'done') {
        queue.then(() => {
          if (m.ok) {
            const json = m.json;
            if (json.length > LIMITS.resultChars) {
              finish({ ok: true, truncated: true, value: json.slice(0, LIMITS.resultChars) + `\n[truncated: return value was ${json.length} chars; cap is ${LIMITS.resultChars} — return a summary plus identifiers and fetch the rest in a follow-up execute]`, value_chars: LIMITS.resultChars });
            } else {
              let value; try { value = JSON.parse(json); } catch { value = json; }
              finish({ ok: true, truncated: false, value, value_chars: json.length });
            }
          } else {
            finish({ ok: false, error: { kind: m.kind || 'runtime', message: m.message, receipt: m.receipt } });
          }
        });
      }
    });
    child.on('exit', (code, signal) => {
      if (!finished) queue.then(() => finish({ ok: false, error: { kind: 'runtime', message: `sandbox process died (code ${code}, signal ${signal})${/heap|memory/i.test(stderr) ? ': heap limit reached' : ''}` } }));
    });
    child.on('error', (e) => finish({ ok: false, error: { kind: 'runtime', message: 'sandbox failed to start: ' + e.message } }));
  });
}

module.exports = { runProgram, LIMITS, sandboxPosture };
