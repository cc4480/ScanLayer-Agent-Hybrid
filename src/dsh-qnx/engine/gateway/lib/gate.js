'use strict';
// The gate: the ONLY path from a program's `tools.x(...)` to a process on the
// target. Order is fixed and every step fails closed:
//   1 tool exists in the catalog          -> else deny unknown_tool
//   2 tool is callable (destructive OFF)  -> else deny destructive_off
//   3 argv well-formed                    -> else deny invalid_args
//   4 per-tool argument rules             -> else deny arg_rule
//   5 protected paths (gateway secrets)   -> else deny protected_path
//   6 scope gate on every target in argv  -> else deny out_of_scope
//   7 runner (which re-checks its own allowlist on the target)
// Steps 1–6 happen before any byte goes to the runner, so a denial spawns
// nothing and sends no packet. Every decision is a receipt in the audit chain.
const net = require('net');
const { spawn } = require('child_process');
const { sha256 } = require('./canon');
const scope = require('./scope');

const MAX_ARGS = 64;
const MAX_ARG_LEN = 4096;

function argRuleViolation(tool, args) {
  const r = tool.argRules;
  if (!r) return null;
  const deny = new Set(r.denyFlags || []);
  const singles = [...deny].filter((f) => /^-[A-Za-z0-9]$/.test(f)).map((f) => f[1]);
  for (const a of args) {
    const flag = a.split('=')[0];
    if (deny.has(flag)) return `flag ${flag} is not allowed for ${tool.name}`;
    for (const p of r.denyFlagPrefixes || []) if (flag.startsWith(p)) return `flag ${flag} is not allowed for ${tool.name}`;
    if (/^-[A-Za-z0-9]{2,}$/.test(a) && !a.startsWith('--')) {
      const hit = singles.find((c) => a.slice(1).includes(c));
      if (hit) return `flag cluster ${a} contains -${hit}, which is not allowed for ${tool.name}`;
    }
  }
  if (r.allowOnly) { const why = r.allowOnly(args); if (why) return why; }
  return null;
}

class RunnerClient {
  constructor(cfg) { this.cfg = cfg; }
  // maxOutput is for operator jobs (the inventory pull); Gate.call never passes it, so agent calls keep the runner's
  // default 40,000-character cap.
  run(argv, timeoutMs, maxOutput) {
    const req = JSON.stringify({ token: this.cfg.token, argv, timeout_ms: timeoutMs, ...(maxOutput ? { max_output: maxOutput } : {}) }) + '\n';
    const wait = timeoutMs + 15000;
    return new Promise((resolve, reject) => {
      let buf = '';
      const done = (fn, v) => { clearTimeout(timer); fn(v); };
      const timer = setTimeout(() => { try { sock && sock.destroy(); child && child.kill('SIGKILL'); } catch {} reject(new Error('runner did not answer')); }, wait);
      let sock = null, child = null;
      const onData = (d) => {
        buf += d;
        const i = buf.indexOf('\n');
        if (i >= 0) { try { done(resolve, JSON.parse(buf.slice(0, i))); } catch (e) { done(reject, new Error('runner sent invalid JSON')); } if (sock) sock.destroy(); }
      };
      if (this.cfg.mode === 'stdio') {
        child = spawn(this.cfg.path, ['--stdio', ...(this.cfg.allow_file ? ['--allow-file', this.cfg.allow_file] : []), ...(this.cfg.spawn_log ? ['--spawn-log', this.cfg.spawn_log] : [])], { stdio: ['pipe', 'pipe', 'ignore'], env: {} });
        child.stdout.setEncoding('utf8');
        child.stdout.on('data', onData);
        child.on('error', (e) => done(reject, e));
        child.stdin.end(req);
      } else {
        sock = net.connect({ host: this.cfg.host || '127.0.0.1', port: this.cfg.port });
        sock.setEncoding('utf8');
        sock.on('connect', () => sock.write(req));
        sock.on('data', onData);
        sock.on('error', (e) => done(reject, new Error(`runner unreachable: ${e.message}`)));
        sock.on('end', () => { if (!buf.includes('\n')) done(reject, new Error('runner closed without a reply')); });
      }
    });
  }
}

class Gate {
  /**
   * @param {object} o {catalog, audit, runner: RunnerClient, engagements: () => doc, protectedPaths: string[], destructiveSeats?: Set}
   */
  constructor(o) { Object.assign(this, o); }

  async call({ seat, ident, args = [], opts = {}, run_id = null, call_index = null }) {
    const base = { kind: 'call', seat, run_id, call_index };
    const t0 = Date.now();
    const deny = (code, reason, extra = {}) => {
      const e = this.audit.append({ ...base, tool: extra.tool || ident, decision: 'deny', deny: code, reason, argv_sha256: extra.argv_sha256 || null, targets: extra.targets || [], spawned: false });
      return { denied: true, code, reason, receipt: e.hash, seq: e.seq };
    };

    const tool = this.catalog.byIdent.get(ident) || this.catalog.byName.get(ident);
    if (!tool) return deny('unknown_tool', `"${ident}" is not in the target's catalog`);
    if (!this.catalog.visible(tool)) return deny('destructive_off', `${tool.name} is destructive; destructive tools are OFF by default on QNX`, { tool: tool.name });

    if (!Array.isArray(args) || args.length > MAX_ARGS || args.some((a) => typeof a !== 'string' || a.length > MAX_ARG_LEN || a.includes('\0'))) {
      return deny('invalid_args', `args must be an array of at most ${MAX_ARGS} strings (each <= ${MAX_ARG_LEN} chars, no NUL)`, { tool: tool.name });
    }
    const argv = [tool.path, ...args];
    const argv_sha256 = sha256(JSON.stringify(argv));

    const rule = argRuleViolation(tool, args);
    if (rule) return deny('arg_rule', rule, { tool: tool.name, argv_sha256 });

    const hit = (this.protectedPaths || []).find((p) => args.some((a) => a.includes(p)));
    if (hit) return deny('protected_path', 'argument touches the gateway\'s own state (tokens, keys, audit)', { tool: tool.name, argv_sha256 });

    const sc = scope.check(tool.name, args, this.catalog.doc, this.engagements());
    const targets = sc.decisions.map((d) => ({ target: d.target, kind: d.kind, in_scope: d.in_scope, reason: d.reason, engagement: d.engagement || null }));
    if (!sc.allowed) return deny('out_of_scope', sc.reason, { tool: tool.name, argv_sha256, targets });

    const timeout = Math.max(1, Math.min(300000, Number(opts.timeout_ms) || 100000));
    let r;
    try { r = await this.runner.run(argv, timeout); } catch (e) {
      const a = this.audit.append({ ...base, tool: tool.name, decision: 'error', reason: e.message, argv_sha256, targets, spawned: null, duration_ms: Date.now() - t0 });
      return { error: true, reason: e.message, receipt: a.hash, seq: a.seq };
    }
    if (!r.ok) {
      const a = this.audit.append({ ...base, tool: tool.name, decision: 'deny', deny: 'runner_' + r.error, reason: r.detail, argv_sha256, targets, spawned: false });
      return { denied: true, code: 'runner_' + r.error, reason: r.detail, receipt: a.hash, seq: a.seq };
    }
    const result = { exit: r.exit, signal: r.signal, stdout: r.stdout, stderr: r.stderr, truncated: r.truncated, timed_out: r.timed_out, duration_ms: r.duration_ms };
    const a = this.audit.append({
      ...base, tool: tool.name, decision: 'allow', argv: argv, argv_sha256, targets, spawned: true,
      exit: r.exit, signal: r.signal, timed_out: r.timed_out, truncated: r.truncated,
      stdout_sha256: sha256(r.stdout), stderr_sha256: sha256(r.stderr), stdout_bytes: Buffer.byteLength(r.stdout), duration_ms: Date.now() - t0,
    });
    return { ...result, receipt: a.hash, seq: a.seq };
  }
}

module.exports = { Gate, RunnerClient, argRuleViolation };
