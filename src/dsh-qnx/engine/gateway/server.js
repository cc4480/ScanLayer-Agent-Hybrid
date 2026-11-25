#!/usr/bin/env node
'use strict';
// QNX agent gateway — Code Mode over MCP for a QNX 8.0 target.
// The model sees exactly two tools: `search` and `execute`. Everything else
// (scope gate, destructive-off default, audit chain, signed reports, the
// verification board) sits behind them.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Catalog } = require('./lib/catalog');
const { Audit, verifyChain, loadOrCreateKey } = require('./lib/audit');
const { Gate, RunnerClient } = require('./lib/gate');
const { runProgram, sandboxPosture, LIMITS } = require('./lib/sandbox');
const scope = require('./lib/scope');
const { buildReport, saveReport } = require('./lib/report');
const { Board } = require('./lib/board');
const { renderReportHtml } = require('./lib/report-html');
const { sha256 } = require('./lib/canon');

const SERVER_INFO = { name: 'qnx-agent-gateway', version: '0.1.0' };
const PROTOCOLS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26'];

const SEARCH_TOOL = {
  name: 'search',
  description: 'Find tools on the QNX target by intent. Returns typed stubs (call them inside `execute` as tools.<ident>(args, opts)). Destructive tools are listed but not callable unless an operator enabled them.',
  inputSchema: {
    type: 'object',
    properties: {
      query: { type: 'string', description: 'What you want to do, e.g. "open ports" or "process list".' },
      names: { type: 'array', items: { type: 'string' }, description: 'Exact tool names to fetch stubs for.' },
      limit: { type: 'integer', minimum: 1, maximum: 20, default: 8 },
    },
  },
  annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
};
const EXECUTE_TOOL = {
  name: 'execute',
  description: 'Run a JavaScript async function body against the QNX target. Globals: tools.<ident>(args?: string[], opts?: {timeout_ms}) -> {exit, stdout, stderr, truncated, receipt}; catalog (meta, processes, listeners, resource_managers); manifest (declared image contents); parse.listeners/processes/lsl/lines. No network, fs, require or eval. Only your `return` value comes back (max 40,000 chars). An out-of-scope or disallowed call aborts the run with scope_denied.',
  inputSchema: {
    type: 'object',
    properties: {
      program: { type: 'string', maxLength: LIMITS.programChars, description: 'Async function body. Use `return` to send back a result.' },
      timeout_ms: { type: 'integer', minimum: 100, maximum: LIMITS.maxTimeoutMs },
    },
    required: ['program'],
  },
  annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
};

function loadConfig(file) {
  const dir = path.dirname(path.resolve(file));
  const c = JSON.parse(fs.readFileSync(file, 'utf8'));
  const r = (p) => (p ? path.resolve(dir, p) : p);
  c.state_dir = r(c.state_dir || '.');
  c.catalog = r(c.catalog);
  c.manifest = r(c.manifest);
  c.checks_dir = r(c.checks_dir || path.join(__dirname, '..', 'checks'));
  // inventory_path is a path on the target: resolve a relative one (the stand-in, where the target is this machine),
  // but keep an absolute one exactly as written (a QNX path such as /system/..., which must not become C:\system\...).
  if (c.inventory_path && !c.inventory_path.startsWith('/')) c.inventory_path = r(c.inventory_path);
  if (c.runner) { c.runner.token_file = r(c.runner.token_file); c.runner.path = r(c.runner.path); c.runner.allow_file = r(c.runner.allow_file); c.runner.spawn_log = r(c.runner.spawn_log); }
  return c;
}

function createGateway(cfg) {
  const S = (p) => path.join(cfg.state_dir, p);
  fs.mkdirSync(cfg.state_dir, { recursive: true });
  const audit = new Audit(S('audit.log'));
  const signer = loadOrCreateKey(cfg.state_dir);
  // Destructive tools: off (default on QNX), ask (each call needs an approver's yes) or on. allow_destructive: true = on.
  const destructiveMode = ['off', 'ask', 'on'].includes(cfg.destructive) ? cfg.destructive : (cfg.allow_destructive ? 'on' : 'off');
  let catalog = Catalog.load(cfg.catalog, { destructiveMode });
  const manifest = () => { try { return JSON.parse(fs.readFileSync(cfg.manifest, 'utf8')); } catch { return {}; } };
  const operatorKey = (() => { try { return fs.readFileSync(S('operator.key'), 'utf8').trim(); } catch { return null; } })();
  let engCache = null;
  const engagements = () => { engCache = scope.loadEngagements(S('engagements.json'), operatorKey); return engCache; };

  // seats: { seatName: sha256(token) }
  const seats = JSON.parse(fs.readFileSync(S('seats.json'), 'utf8'));
  const seatByHash = new Map(Object.entries(seats).map(([seat, h]) => [h, seat]));
  const authSeat = (req) => {
    const m = /^Bearer\s+(\S+)$/i.exec(req.headers.authorization || '');
    if (!m) return null;
    const h = sha256(m[1]);
    for (const [hh, seat] of seatByHash) if (hh.length === h.length && crypto.timingSafeEqual(Buffer.from(hh), Buffer.from(h))) return seat;
    return null;
  };

  const runnerCfg = { ...cfg.runner };
  if (runnerCfg.token_file) runnerCfg.token = fs.readFileSync(runnerCfg.token_file, 'utf8').trim();
  const runner = new RunnerClient(runnerCfg);
  const protectedPaths = [cfg.state_dir, ...(cfg.protected_paths || [])];
  // The approver is supplied by whoever hosts the engine (the harness bundle asks the user); without one, `ask` denies.
  const gate = new Gate({ catalog, audit, runner, engagements, protectedPaths, destructiveMode, approve: typeof cfg.approve === 'function' ? cfg.approve : undefined });
  const board = new Board(S('board.json'), S('audit.log'));
  const reportsDir = S('reports');

  audit.append({ kind: 'gateway_start', seat: null, catalog_hash: catalog.hash, catalog_tools: catalog.tools.length, visible_tools: catalog.visibleTools().length, allow_destructive: destructiveMode !== 'off', destructive_mode: destructiveMode, target: catalog.meta.hostname, os: catalog.meta.os, release: catalog.meta.release, signing_key: signer.keyId });

  // Engine actions a program can call as qnx.checks()/scan()/verify()/report(): the audit from chat, receipted like the pages.
  const actions = {
    checks: async () => listChecks().map((f) => f.replace(/^\d+-/, '').replace(/\.js$/, '')),
    scan: async (seat) => scanSummary(await runChecks(seat)),
    verify: async (seat) => verifyLatest(seat),
    report: async (seat) => reportSummary(verifiedReport(seat)),
  };
  const execute = (seat, program, timeoutMs) => runProgram({ program, gate, audit, seat, catalogSnapshot: catalog.snapshot(), manifest: manifest(), timeoutMs, cfg: cfg.sandbox || {}, actions });

  const short = (h) => (h ? String(h).slice(0, 12) : null);
  function scanSummary(r) {
    return {
      report: 'scan', signature: short(r.signature.sig), counts: r.counts, rejected: r.rejected.length,
      checks: r.checks.map((c) => ({ check: c.check, ok: c.ok, findings: c.finding_count, ...(c.ok ? {} : { error: c.error && c.error.message }) })),
      findings: r.findings.map((f) => ({ id: f.id, severity: f.severity, title: f.title, receipt: short(f.evidence[0] && f.evidence[0].receipt), seq: f.evidence[0] && f.evidence[0].seq })),
    };
  }
  function reportSummary(r) {
    return { report: 'verified', signature: short(r.signature.sig), audit: r.audit, confirmed: r.findings.map((f) => ({ id: f.id, severity: f.severity, title: f.title })), excluded: (r.board && r.board.excluded) || [] };
  }
  async function verifyLatest(seat) {
    let rep;
    try { rep = JSON.parse(fs.readFileSync(path.join(reportsDir, 'latest-scan.json'), 'utf8')); } catch { throw new Error('no scan yet: run qnx.scan() first'); }
    const posted = board.post(rep, seat);
    audit.append({ kind: 'board_post', seat, added: posted.added });
    await runSmith(seat);
    const mine = board.read().claims.filter((c) => c.report_sig === rep.signature.sig.slice(0, 32));
    return { verified_by: 'smith (separate process and token)', claims: mine.map((c) => ({ id: c.finding.id, verdict: c.status, observed: c.verdict && c.verdict.observed })) };
  }

  const listChecks = () => fs.readdirSync(cfg.checks_dir).filter((f) => f.endsWith('.js') && !f.startsWith('_')).sort();
  async function runChecks(seat, only) {
    const files = listChecks();
    const prelude = fs.readFileSync(path.join(cfg.checks_dir, '_prelude.js'), 'utf8');
    const results = [];
    for (const f of files) {
      const name = f.replace(/^\d+-/, '').replace(/\.js$/, '');
      if (only && only.length && !only.includes(name)) continue;
      const program = prelude + '\n' + fs.readFileSync(path.join(cfg.checks_dir, f), 'utf8');
      const r = await execute(seat, program, 120000);
      if (r.ok && r.value && typeof r.value === 'object') results.push({ check: r.value.check || name, ok: true, run_receipt: r.receipt, findings: r.value.findings || [], summary: r.value.summary || null });
      else results.push({ check: name, ok: false, run_receipt: r.receipt, error: r.error || { kind: 'runtime', message: r.truncated ? 'check output truncated' : 'check returned no object' }, findings: [] });
    }
    const report = buildReport({ kind: 'scan', checkResults: results, auditFile: S('audit.log'), signer, catalogMeta: catalog.meta, extra: { seat } });
    report.file = saveReport(reportsDir, report);
    audit.append({ kind: 'report', seat, report_kind: 'scan', findings: report.findings.length, rejected: report.rejected.length, sig: report.signature.sig.slice(0, 32) });
    return report;
  }

  function verifiedReport(seat) {
    const doc = board.read();
    const confirmed = doc.claims.filter((c) => c.status === 'CONFIRMED');
    const results = [{ check: 'verification-loop', ok: true, run_receipt: null, findings: confirmed.map((c) => ({ ...c.finding, id: c.finding.id, verification: c.verdict })) }];
    const report = buildReport({
      kind: 'verified', checkResults: results, auditFile: S('audit.log'), signer, catalogMeta: catalog.meta,
      extra: { seat, board: { total: doc.claims.length, confirmed: confirmed.length, refuted: doc.claims.filter((c) => c.status === 'REFUTED').length, unproven: doc.claims.filter((c) => c.status === 'UNPROVEN').length, excluded: doc.claims.filter((c) => c.status !== 'CONFIRMED').map((c) => ({ id: c.finding.id, status: c.status, observed: c.verdict && c.verdict.observed })) } },
    });
    report.file = saveReport(reportsDir, report);
    audit.append({ kind: 'report', seat, report_kind: 'verified', findings: report.findings.length, sig: report.signature.sig.slice(0, 32) });
    return report;
  }

  function state(seat) {
    const e = engagements();
    const chain = verifyChain(S('audit.log'));
    const self = scope.selfSet(catalog.doc);
    return {
      seat, server: SERVER_INFO, target: catalog.meta,
      catalog: { tools: catalog.tools.length, visible: catalog.visibleTools().length, free: catalog.tools.filter((t) => !t.destructive).length, destructive: catalog.tools.filter((t) => t.destructive).length, network: catalog.tools.filter((t) => t.network).length, known: catalog.tools.filter((t) => t.known).length, hash: catalog.hash, processes: (catalog.doc.processes || []).length, resource_managers: (catalog.doc.resource_managers || []).length, listeners: ((catalog.doc.network || {}).listeners || []), interface_ips: ((catalog.doc.network || {}).interface_ips || []) },
      policy: { allow_destructive: destructiveMode !== 'off', destructive_mode: destructiveMode, sandbox: sandboxPosture(cfg.sandbox || {}), self_scope: [...self.hosts, ...self.ips, '127.0.0.0/8', '::1'] },
      engagements: { verified: e.engagements.map((x) => ({ id: x.id, targets: x.targets, expires_at: x.expires_at || null, operator: x.operator || null })), rejected: e.rejected, error: e.error },
      audit: chain, signing_key: { key_id: signer.keyId, public_pem: signer.pubPem },
      seats: Object.keys(seats),
    };
  }

  function seal() {
    const chain = verifyChain(S('audit.log'));
    const body = { schema: 'qnx-agent.seal.v1', at: new Date().toISOString(), entries: chain.count, head: chain.head, chain_ok: chain.ok, target: catalog.meta.hostname };
    return { ...body, signature: { alg: 'ed25519', key_id: signer.keyId, sig: signer.sign(body) }, public_pem: signer.pubPem };
  }

  // Agent Smith runs as its OWN process with its OWN seat token and reaches this
  // engine over the loopback MCP listener, like any outside client.
  function runSmith(seat, url) {
    const tf = S('seat-smith.token');
    if (!fs.existsSync(tf)) return Promise.reject(new Error('no smith seat token on this box'));
    const { execFile } = require('child_process');
    const { host = '127.0.0.1', port = 8095 } = cfg.listen || {};
    return new Promise((resolve) => {
      execFile(process.execPath, [path.join(__dirname, '..', 'loop', 'smith.js'), '--url', url || `http://${host}:${port}`, '--token-file', tf], { timeout: 600000, env: {} }, (e, stdout, stderr) => {
        audit.append({ kind: 'smith_run', seat, ok: !e, lines: stdout.trim().split('\n').length, error: e ? String(stderr || e.message).slice(0, 300) : null });
        resolve({ ok: !e });
      });
    });
  }
  function startSmith(seat, url) { runSmith(seat, url).catch(() => {}); }

  // Engagements from the operator's pages: signed with the operator key on this box, like `cli.js engage add`.
  function addEngagement(seat, { id, targets, hours }) {
    const e = scope.addEngagement(S('engagements.json'), operatorKey, { id, targets, hours, operator: seat });
    audit.append({ kind: 'engagement_add', seat, id: e.id, targets: e.targets, expires_at: e.expires_at });
    return { id: e.id, targets: e.targets, expires_at: e.expires_at };
  }
  function revokeEngagement(seat, id) {
    const removed = scope.revokeEngagement(S('engagements.json'), id);
    audit.append({ kind: 'engagement_revoke', seat, id, removed });
    return { removed };
  }

  function reportHtml(kind) {
    const rep = JSON.parse(fs.readFileSync(path.join(reportsDir, `latest-${kind}.json`), 'utf8'));
    return renderReportHtml(rep, signer.pubPem);
  }

  async function refreshCatalog(seat) {
    if (!cfg.inventory_path) throw new Error('inventory_path is not configured');
    const r = await runner.run([cfg.inventory_path, '-'], 60000, 8 * 1024 * 1024);
    if (!r.ok || r.exit !== 0 || r.truncated) throw new Error(r.truncated ? 'inventory output exceeded 8 MiB' : `inventory failed: ${r.detail || r.stderr}`);
    const doc = JSON.parse(r.stdout);
    fs.writeFileSync(cfg.catalog, JSON.stringify(doc));
    catalog = Catalog.load(cfg.catalog, { destructiveMode });
    gate.catalog = catalog;
    audit.append({ kind: 'catalog_refresh', seat, catalog_hash: catalog.hash, catalog_tools: catalog.tools.length });
    return { tools: catalog.tools.length, callable: catalog.visibleTools().length, free: catalog.tools.filter((t) => !t.destructive).length, hash: catalog.hash };
  }

  // ---------------- MCP ----------------
  async function mcpDispatch(seat, msg) {
    const { id, method, params = {} } = msg;
    const ok = (result) => ({ jsonrpc: '2.0', id, result });
    const err = (code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });
    switch (method) {
      case 'initialize': {
        const want = params.protocolVersion;
        return ok({ protocolVersion: PROTOCOLS.includes(want) ? want : PROTOCOLS[1], capabilities: { tools: { listChanged: false } }, serverInfo: SERVER_INFO, instructions: 'QNX target behind a Code Mode gateway: use `search` to find tools, then `execute` a program that calls them. Only your return value comes back.' });
      }
      case 'ping': return ok({});
      case 'tools/list':
        audit.append({ kind: 'list', seat, tool: null });
        return ok({ tools: [SEARCH_TOOL, EXECUTE_TOOL] });
      case 'tools/call': {
        const name = params.name;
        const a = params.arguments || {};
        if (name === 'search') {
          if (!a.query && !(Array.isArray(a.names) && a.names.length)) return ok({ isError: true, content: [{ type: 'text', text: JSON.stringify({ error: 'invalid_argument', detail: 'query or names is required' }) }] });
          const res = catalog.search(a);
          audit.append({ kind: 'search', seat, tool: 'codemode.search', query: String(a.query || '').slice(0, 200), matches: res.matches.map((m) => m.name) });
          return ok({ content: [{ type: 'text', text: JSON.stringify(res) }], structuredContent: res });
        }
        if (name === 'execute') {
          const r = await execute(seat, a.program, a.timeout_ms);
          if (r.invalid) return ok({ isError: true, content: [{ type: 'text', text: JSON.stringify({ error: 'invalid_argument', detail: r.invalid }) }] });
          return ok({ isError: !r.ok, content: [{ type: 'text', text: JSON.stringify(r) }], structuredContent: r });
        }
        return err(-32602, `unknown tool: ${name}`);
      }
      default:
        if (method && method.startsWith('notifications/')) return null;
        return err(-32601, `method not found: ${method}`);
    }
  }

  // ---------------- HTTP ----------------
  const allowedHosts = new Set(['127.0.0.1', 'localhost', '[::1]', ...(cfg.allowed_hosts || [])]);
  const json = (res, code, body, headers = {}) => { res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers }); res.end(JSON.stringify(body)); };
  const readBody = (req, max = 1 << 20) => new Promise((resolve, reject) => {
    let n = 0; const chunks = [];
    req.on('data', (c) => { n += c.length; if (n > max) { reject(new Error('body too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });

  const server = http.createServer(async (req, res) => {
    try {
      const host = String(req.headers.host || '').replace(/:\d+$/, '');
      if (!allowedHosts.has(host)) return json(res, 421, { error: 'host not allowed' }); // DNS-rebinding guard
      const url = new URL(req.url, 'http://x');
      const p = url.pathname;

      if (p === '/health') return json(res, 200, { ok: true });
      const seat = authSeat(req);
      if (!seat) return json(res, 401, { error: 'unauthorized' }, { 'www-authenticate': 'Bearer' });

      if (p === '/mcp') {
        if (req.method === 'GET') return json(res, 405, { error: 'this server does not open server-initiated streams' }, { allow: 'POST' });
        if (req.method === 'DELETE') { res.writeHead(204); return res.end(); }
        if (req.method !== 'POST') return json(res, 405, { error: 'method not allowed' });
        let msg;
        try { msg = JSON.parse(await readBody(req)); } catch { return json(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }); }
        const batch = Array.isArray(msg);
        const outs = [];
        for (const m of batch ? msg : [msg]) {
          if (!m || m.jsonrpc !== '2.0' || typeof m.method !== 'string') { outs.push({ jsonrpc: '2.0', id: (m && m.id) ?? null, error: { code: -32600, message: 'invalid request' } }); continue; }
          const r = await mcpDispatch(seat, m);
          if (r && m.id !== undefined) outs.push(r);
        }
        if (!outs.length) { res.writeHead(202); return res.end(); }
        return json(res, 200, batch ? outs : outs[0]);
      }

      // ---------------- operator API ----------------
      if (p === '/api/state' && req.method === 'GET') return json(res, 200, state(seat));
      if (p === '/api/audit' && req.method === 'GET') return json(res, 200, { entries: audit.since(Number(url.searchParams.get('after') || 0), Math.min(2000, Number(url.searchParams.get('limit') || 500))) });
      if (p === '/api/audit/stream' && req.method === 'GET') {
        res.writeHead(200, { 'content-type': 'application/x-ndjson', 'cache-control': 'no-store' });
        const after = Number(url.searchParams.get('after') || 0);
        for (const e of audit.since(after, 5000)) res.write(JSON.stringify(e) + '\n');
        const on = (e) => res.write(JSON.stringify(e) + '\n');
        audit.on('entry', on);
        const ka = setInterval(() => res.write('{"kind":"keepalive"}\n'), 15000);
        req.on('close', () => { audit.off('entry', on); clearInterval(ka); });
        return;
      }
      if (p === '/api/verify' && req.method === 'GET') return json(res, 200, verifyChain(S('audit.log')));
      if (p === '/api/seal' && req.method === 'GET') return json(res, 200, seal());
      if (p === '/api/search' && req.method === 'GET') return json(res, 200, catalog.search({ query: url.searchParams.get('q') || '', limit: 20 }));
      if (p === '/api/execute' && req.method === 'POST') {
        const b = JSON.parse(await readBody(req));
        const r = await execute(seat, b.program, b.timeout_ms);
        return json(res, r.invalid ? 400 : 200, r);
      }
      if (p === '/api/checks' && req.method === 'GET') return json(res, 200, { checks: listChecks().map((f) => f.replace(/^\d+-/, '').replace(/\.js$/, '')) });
      if (p === '/api/checks/run' && req.method === 'POST') {
        const b = JSON.parse((await readBody(req)) || '{}');
        return json(res, 200, await runChecks(seat, b.checks));
      }
      if (p.startsWith('/api/report/') && req.method === 'GET') {
        const kind = p.split('/').pop();
        try { return json(res, 200, JSON.parse(fs.readFileSync(path.join(reportsDir, `latest-${kind}.json`), 'utf8'))); } catch { return json(res, 404, { error: 'no report yet' }); }
      }
      if (p === '/api/board' && req.method === 'GET') return json(res, 200, board.read());
      if (p === '/api/board/open' && req.method === 'GET') return json(res, 200, { claims: board.open(seat) });
      if (p === '/api/board/post' && req.method === 'POST') {
        const b = JSON.parse((await readBody(req)) || '{}');
        let r;
        if (Array.isArray(b.findings)) r = board.postClaims(b.findings, seat, b.tag || 'fixture');
        else {
          let rep; try { rep = JSON.parse(fs.readFileSync(path.join(reportsDir, 'latest-scan.json'), 'utf8')); } catch { return json(res, 404, { error: 'no scan report to post' }); }
          r = board.post(rep, seat);
        }
        audit.append({ kind: 'board_post', seat, added: r.added });
        return json(res, 200, r);
      }
      if (p === '/api/board/lock' && req.method === 'POST') {
        const b = JSON.parse(await readBody(req));
        const r = board.lock(b.id, seat);
        audit.append({ kind: 'board_lock', seat, claim: b.id, ok: !!r.ok, error: r.error || null });
        return json(res, r.ok ? 200 : 409, r);
      }
      if (p === '/api/board/verdict' && req.method === 'POST') {
        const b = JSON.parse(await readBody(req));
        const r = board.verdict(b.id, seat, b);
        audit.append({ kind: 'board_verdict', seat, claim: b.id, verdict: b.verdict, run_receipt: b.run_receipt || null, ok: !!r.ok, error: r.error || null });
        return json(res, r.ok ? 200 : 409, r);
      }
      const operatorOnly = ['/api/board/reset', '/api/catalog/refresh', '/api/loop/smith'];
      if (operatorOnly.includes(p) && seat !== 'operator') return json(res, 403, { error: 'operator seat required' });
      if (p === '/api/loop/smith' && req.method === 'POST') { startSmith(seat); return json(res, 202, { started: true }); }
      if (p === '/api/board/reset' && req.method === 'POST') { board.write({ claims: [] }); audit.append({ kind: 'board_reset', seat }); return json(res, 200, { ok: true }); }
      if (p === '/api/report/verified' && req.method === 'POST') return json(res, 200, verifiedReport(seat));
      if (p === '/api/catalog/refresh' && req.method === 'POST') {
        try { return json(res, 200, await refreshCatalog(seat)); } catch (e) { return json(res, 502, { error: e.message }); }
      }
      return json(res, 404, { error: 'not found' });
    } catch (e) {
      return json(res, 500, { error: 'internal', detail: e.message });
    }
  });
  server.requestTimeout = 0; // execute runs are bounded by the sandbox's own wall clock
  server.headersTimeout = 30000;

  return { server, audit, gate, catalog: () => catalog, execute, runChecks, verifiedReport, board, signer, cfg, state, seal, startSmith, runSmith, search: (q) => catalog.search(q), engagements, addEngagement, revokeEngagement, reportHtml, refreshCatalog, destructiveMode, actions, stateDir: cfg.state_dir };
}

if (require.main === module) {
  const cfgFile = process.argv[2] || process.env.QNX_AGENT_CONFIG || path.join(process.cwd(), 'config.json');
  const cfg = loadConfig(cfgFile);
  const gw = createGateway(cfg);
  const { host = '127.0.0.1', port = 8095 } = cfg.listen || {};
  gw.server.listen(port, host, () => {
    const posture = sandboxPosture(cfg.sandbox || {});
    console.log(`qnx-agent engine: MCP on http://${host}:${port}/mcp`);
    console.log(`target: ${gw.catalog().meta.os} ${gw.catalog().meta.release} "${gw.catalog().meta.hostname}"  tools: ${gw.catalog().tools.length} (${gw.catalog().visibleTools().length} callable)  destructive: ${gw.destructiveMode}`);
    console.log(`sandbox network: ${posture.network}`);
  });
}

module.exports = { createGateway, loadConfig };
