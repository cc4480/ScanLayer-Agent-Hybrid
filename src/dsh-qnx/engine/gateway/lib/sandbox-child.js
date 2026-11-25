'use strict';
// Sandbox child process. Runs ONE model-written program, then exits.
// Started by sandbox.js with: an empty environment, Node's permission model
// (no fs beyond this file, no child_process, no workers), host-realm code
// generation disabled (--disallow-code-generation-from-strings), a heap cap,
// and on Linux-as-root an empty network namespace (unshare -n).
//
// Inside, the program runs in a vm context whose ONLY non-builtin names are
// defined by BOOTSTRAP below, evaluated inside the context: `tools` (every
// call goes over IPC to the gateway's gate), `catalog` and `manifest`
// (read-only data), `parse` (pure helpers), `elapsed()`. node:vm is not a
// security boundary on its own (Node's own docs say so); it is one layer. The
// boundaries that hold even if it falls are the process restrictions above and
// the gate, which sits outside this process and re-decides every call.
const vm = require('vm');

let nextId = 1;
const pending = new Map();

// Host bridge: the one host function the bootstrap closes over. Never on the
// context's global; user code cannot name it.
function bridge(name, argsJson) {
  return new Promise((resolve) => {
    const id = nextId++;
    pending.set(id, resolve);
    process.send({ type: 'call', id, tool: String(name), args: String(argsJson) });
  });
}
// Engine actions (scan, verify, report, list checks): not target commands, answered by the gateway itself.
function actionBridge(name) {
  return new Promise((resolve) => {
    const id = nextId++;
    pending.set(id, resolve);
    process.send({ type: 'action', id, name: String(name) });
  });
}

const BOOTSTRAP = String.raw`(function (bridge, actionBridge, catalogJson, manifestJson, seed) {
  'use strict';
  const freezeDeep = (o) => { if (o && typeof o === 'object') { Object.values(o).forEach(freezeDeep); Object.freeze(o); } return o; };
  const callTool = (name, args, opts) => new Promise((resolve, reject) => {
    let payload;
    try { payload = JSON.stringify({ args: args === undefined ? [] : args, opts: opts || {} }); }
    catch (e) { reject(new TypeError('tool arguments must be JSON-serializable')); return; }
    bridge(name, payload).then((json) => {
      const r = JSON.parse(json);
      if (r.error) { const e = new Error(r.reason); e.kind = r.kind || 'tool_error'; e.receipt = r.receipt; reject(e); }
      else resolve(freezeDeep(r));
    });
  });
  const handler = {
    get(_t, prop) {
      if (typeof prop !== 'string' || prop === 'then') return undefined;
      return function (args, opts) { return callTool(prop, args, opts); };
    },
    set() { return false; }, defineProperty() { return false; }, deleteProperty() { return false; },
    has() { return true; }, ownKeys() { return []; }, getPrototypeOf() { return null; },
  };
  const tools = new Proxy(Object.freeze(Object.create(null)), handler);

  // Pure parsers so checks read real command output the same way on QNX and the stand-in.
  const parse = Object.freeze({
    lines: (s) => String(s).split('\n').filter((l) => l.trim().length),
    // netstat -an (QNX io-sock/BSD and Linux net-tools) or ss -lntu -> [{proto, addr, port, family}]
    listeners: (text) => {
      const out = [];
      for (const line of String(text).split('\n')) {
        const f = line.trim().split(/\s+/);
        if (!/^(tcp|udp)/.test(f[0])) continue;
        const proto = f[0].replace(/[46]$/, '');
        let local;
        if (/LISTEN/.test(line)) local = f[1] === 'LISTEN' ? f[4] : f[3];
        else if (proto === 'udp') local = f[1] === 'UNCONN' ? f[4] : f[3];
        else continue;
        if (!local) continue;
        let addr, port;
        const m = /^(.*)[:.](\d+)$/.exec(local);
        if (!m) continue;
        addr = m[1]; port = Number(m[2]);
        const family = (/6$/.test(f[0]) || addr.includes(':')) ? 'ipv6' : 'ipv4';
        if (!out.some((x) => x.proto === proto && x.addr === addr && x.port === port)) out.push({ proto, addr, port, family });
      }
      return out;
    },
    // ps -A -o pid= -o comm= / pidin -> [{pid, name}]
    processes: (text) => String(text).split('\n').map((l) => l.trim().split(/\s+/)).filter((f) => /^\d+$/.test(f[0]) && f[1])
      .map((f) => ({ pid: Number(f[0]), name: f[1].startsWith('/') ? f[1].replace(/^.*\//, '') : f[1] })),
    // ls -l / ls -la -> [{mode, name}]
    lsl: (text) => String(text).split('\n').map((l) => l.trim().split(/\s+/)).filter((f) => f.length >= 9 && /^[-dlcbps]/.test(f[0]))
      .map((f) => ({ mode: f[0], name: f.includes('->') ? f[f.indexOf('->') - 1] : f[f.length - 1] })),
  });

  // Deterministic PRNG (mulberry32) so runs are reproducible; no host clock.
  let s = seed >>> 0;
  Math.random = function () { s = (s + 0x6D2B79F5) >>> 0; let t = s; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  let ticks = 0;
  const elapsed = () => ++ticks; // monotonic counter, not a clock

  // The audit, as engine actions: the same receipted checks, verification and signed report the QNX pages run.
  const action = (name) => new Promise((resolve, reject) => {
    actionBridge(name).then((json) => {
      const r = JSON.parse(json);
      if (r.error) { const e = new Error(r.error); e.kind = 'action_error'; reject(e); } else resolve(freezeDeep(r.value));
    });
  });
  const qnx = Object.freeze({
    checks: () => action('checks'),
    scan: () => action('scan'),
    verify: () => action('verify'),
    report: () => action('report'),
  });
  globalThis.qnx = qnx;
  globalThis.tools = tools;
  globalThis.catalog = freezeDeep(JSON.parse(catalogJson));
  globalThis.manifest = freezeDeep(JSON.parse(manifestJson));
  globalThis.parse = parse;
  globalThis.elapsed = elapsed;
  delete globalThis.Date;
})`;

process.on('message', async (m) => {
  if (m.type === 'result') {
    const r = pending.get(m.id);
    if (r) { pending.delete(m.id); r(m.json); }
    return;
  }
  if (m.type !== 'run') return;
  const context = vm.createContext(Object.create(null), {
    codeGeneration: { strings: false, wasm: false },
    name: 'qnx-agent-program',
  });
  try {
    vm.runInContext(BOOTSTRAP, context, { timeout: 1000 })(bridge, actionBridge, m.catalog, m.manifest, m.seed || 1);
  } catch (e) {
    process.send({ type: 'done', ok: false, kind: 'runtime', message: 'bootstrap failed: ' + e.message });
    return;
  }
  let script;
  try {
    script = new vm.Script(`(async function () {\n'use strict';\n${m.program}\n})()`, { filename: 'program.js', lineOffset: -2 });
  } catch (e) {
    process.send({ type: 'done', ok: false, kind: 'runtime', message: `${e.name}: ${e.message}`, compile: true });
    return;
  }
  try {
    const p = script.runInContext(context, { timeout: m.syncTimeoutMs || 5000 });
    const value = await p;
    // Serialize with the context's own JSON so nothing host-side touches guest objects.
    const json = vm.runInContext('(v) => { const j = JSON.stringify(v); return j === undefined ? "null" : j; }', context)(value);
    process.send({ type: 'done', ok: true, json: String(json) });
  } catch (e) {
    const kind = (e && e.kind) || 'runtime';
    let message;
    try { message = `${e && e.name ? e.name + ': ' : ''}${e && e.message !== undefined ? e.message : String(e)}`; } catch { message = 'program threw a non-printable value'; }
    process.send({ type: 'done', ok: false, kind, message: String(message).slice(0, 2000), receipt: e && e.receipt });
  }
});
process.on('unhandledRejection', (e) => {
  try { process.send({ type: 'done', ok: false, kind: 'runtime', message: 'unhandled rejection: ' + String(e && e.message || e).slice(0, 500) }); } catch {}
});
process.send({ type: 'ready' });
