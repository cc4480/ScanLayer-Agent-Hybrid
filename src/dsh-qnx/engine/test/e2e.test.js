'use strict';
// End-to-end on the stand-in target: real runner (TCP, allowlist, spawn log),
// real inventory, real gateway, real MCP over HTTP. Hermetic: temp state dir,
// random ports.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const { spawn, execFileSync } = require('child_process');
const { createGateway, loadConfig } = require('../gateway/server');
const { McpClient, request } = require('../gateway/lib/mcp-client');
const { verifyChain } = require('../gateway/lib/audit');

const ROOT = path.join(__dirname, '..');
const RUNNER = path.join(ROOT, 'node-runtime', 'qnx-runner');
const freePort = () => new Promise((r) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });

let dir, runnerProc, gw, base, T = {};
const spawned = () => { try { return fs.readFileSync(path.join(dir, 'state', 'spawn.log'), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)); } catch { return []; } };

test.before(async () => {
  execFileSync('make', ['-sC', path.join(ROOT, 'node-runtime')]);
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-e2e-'));
  const st = path.join(dir, 'state');
  execFileSync(process.execPath, [path.join(ROOT, 'gateway', 'cli.js'), 'init', st]);
  execFileSync('sh', [path.join(ROOT, 'node-runtime', 'inventory-qnx.sh'), path.join(st, 'catalog.json')], { stdio: 'ignore' });
  fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify({ services: [], processes: ['*'] }));
  const rport = await freePort();
  const gport = await freePort();
  fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({
    listen: { host: '127.0.0.1', port: gport }, state_dir: 'state', catalog: 'state/catalog.json', manifest: 'manifest.json',
    checks_dir: path.join(ROOT, 'checks'), runner: { mode: 'tcp', host: '127.0.0.1', port: rport, token_file: 'state/runner.token' },
  }));
  const cfg = loadConfig(path.join(dir, 'config.json'));
  fs.writeFileSync(path.join(st, 'runner.allow'), execFileSync(process.execPath, [path.join(ROOT, 'gateway', 'cli.js'), 'allowlist', path.join(dir, 'config.json')]));
  runnerProc = spawn(RUNNER, ['--listen', String(rport), '--bind', '127.0.0.1', '--token-file', path.join(st, 'runner.token'), '--allow-file', path.join(st, 'runner.allow'), '--spawn-log', path.join(st, 'spawn.log')], { stdio: 'ignore' });
  await new Promise((r) => setTimeout(r, 200));
  gw = createGateway(cfg);
  await new Promise((r) => gw.server.listen(gport, '127.0.0.1', r));
  base = `http://127.0.0.1:${gport}`;
  for (const s of ['runner', 'smith', 'operator']) T[s] = fs.readFileSync(path.join(st, `seat-${s}.token`), 'utf8').trim();
});
test.after(() => { try { gw.server.close(); } catch {} try { runnerProc.kill(); } catch {} });

const client = () => new McpClient(base, T.runner);

test('ladder: 401 -> tools/list = [search, execute] -> search finds a real tool -> execute runs it on the target', async () => {
  const r401 = await request(base, null, 'POST', '/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/list' });
  assert.equal(r401.status, 401);
  const bad = await request(base, 'not-a-token', 'POST', '/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/list' });
  assert.equal(bad.status, 401);
  const c = client();
  const init = await c.initialize();
  assert.equal(init.serverInfo.name, 'qnx-agent-gateway');
  assert.deepEqual((await c.listTools()).map((t) => t.name), ['search', 'execute']);
  const s = await c.search('open ports listening sockets');
  assert.ok(s.matches.some((m) => m.name === 'netstat' && m.callable));
  const before = spawned().length;
  const r = await c.execute('const u = await tools.uname(["-s"]); return { os: u.stdout.trim(), exit: u.exit, receipt: u.receipt };');
  assert.equal(r.ok, true);
  assert.equal(r.value.os, os.type());
  assert.match(r.value.receipt, /^[0-9a-f]{64}$/);
  assert.equal(spawned().length, before + 1, 'runner logged exactly one spawn');
  assert.match(spawned().at(-1).argv[0], /uname$/);
});

test('Host header guard (DNS rebinding) refuses foreign hosts', async () => {
  const r = await new Promise((resolve) => {
    const req = require('http').request(base + '/health', { headers: { host: 'evil.example.com' } }, (res) => resolve(res.statusCode));
    req.end();
  });
  assert.equal(r, 421);
});

test('sandbox: no network, fs, process, require, eval, Function, import, wasm, Date', async () => {
  const c = client();
  const probes = {
    fetch: 'return typeof fetch',
    require: 'return typeof require',
    process: 'return typeof process',
    date: 'return typeof Date',
    wasm: 'try { return typeof WebAssembly === "undefined" ? "absent" : String(new WebAssembly.Module(new Uint8Array([0,97,115,109,1,0,0,0]))) } catch (e) { return "blocked:" + e.name }',
    eval: 'try { return eval("1+1") } catch (e) { return "blocked:" + e.name }',
    fn: 'try { return new Function("return 1")() } catch (e) { return "blocked:" + e.name }',
    ctorEscape: 'try { return tools.uname.constructor.constructor("return process")().pid } catch (e) { return "blocked:" + e.name }',
    promiseEscape: 'try { return tools.uname(["-s"]).constructor.constructor("return process")() } catch (e) { return "blocked:" + e.name }',
    dataEscape: 'try { return catalog.constructor.constructor("return globalThis.process")() } catch (e) { return "blocked:" + e.name }',
    importEscape: 'try { await import("fs"); return "IMPORTED" } catch (e) { return "blocked:" + (e.code || e.name) }',
    globals: 'return Object.getOwnPropertyNames(globalThis).filter((k) => ["tools","catalog","manifest","parse","elapsed","bridge","process","require"].includes(k)).sort()',
  };
  for (const [name, program] of Object.entries(probes)) {
    const r = await c.execute(program);
    assert.equal(r.ok, true, `${name}: ${JSON.stringify(r.error)}`);
    const v = r.value;
    if (['fetch', 'require', 'process', 'date'].includes(name)) assert.equal(v, 'undefined', name);
    else if (name === 'globals') assert.deepEqual(v, ['catalog', 'elapsed', 'manifest', 'parse', 'tools']);
    else assert.match(String(v), /^(blocked:|absent)/, `${name} -> ${v}`);
  }
});

test('sandbox: computed tool names still go through the gate and abort as scope_denied', async () => {
  const r = await client().execute('return await tools["s" + "h"](["-c", "id"]);');
  assert.equal(r.ok, false);
  assert.equal(r.error.kind, 'scope_denied');
  assert.equal(r.error.code, 'destructive_off');
  const r2 = await client().execute('return await tools.definitely_not_a_tool([]);');
  assert.equal(r2.error.code, 'unknown_tool');
});

test('limits: tight loop killed at wall clock, result capped at 40,000 chars, 200-call ceiling', async () => {
  const c = client();
  const t0 = Date.now();
  const loop = await c.execute('while (true) {}', 1500);
  assert.equal(loop.ok, false);
  assert.ok(['timeout', 'runtime'].includes(loop.error.kind), loop.error.kind); // vm sync timeout or parent SIGKILL — both kill it
  assert.ok(Date.now() - t0 < 8000);
  const asyncLoop = await c.execute('await new Promise(() => {});', 1200);
  assert.equal(asyncLoop.error.kind, 'timeout');
  const big = await c.execute('return "x".repeat(100000)');
  assert.equal(big.ok, true);
  assert.equal(big.truncated, true);
  assert.ok(big.value.length > 40000 && big.value.length < 40400);
  assert.match(big.value, /truncated: return value was 100002 chars/);
  const many = await c.execute('for (let i = 0; i < 205; i++) await tools.id([]); return "done"', 60000);
  assert.equal(many.ok, false);
  assert.equal(many.error.kind, 'limit');
});

test('scope: out-of-scope call is denied pre-spawn; a verified engagement lets the identical call run', async () => {
  const c = client();
  const program = 'const r = await tools.ping(["-c", "1", "-W", "1", "192.0.2.77"]); return { exit: r.exit }';
  const before = spawned().length;
  const denied = await c.execute(program);
  assert.equal(denied.ok, false);
  assert.equal(denied.error.kind, 'scope_denied');
  assert.equal(denied.error.code, 'out_of_scope');
  assert.match(denied.error.message, /192\.0\.2\.77/);
  assert.equal(spawned().length, before, 'nothing spawned on the target');
  execFileSync(process.execPath, [path.join(ROOT, 'gateway', 'cli.js'), 'engage', 'add', path.join(dir, 'state'), '--id', 'lab', '--target', '192.0.2.0/24', '--hours', '1']);
  const allowed = await c.execute(program, 20000);
  assert.equal(allowed.ok, true, JSON.stringify(allowed.error));
  assert.equal(spawned().length, before + 1);
  assert.match(spawned().at(-1).argv.join(' '), /ping -c 1 -W 1 192\.0\.2\.77/);
  execFileSync(process.execPath, [path.join(ROOT, 'gateway', 'cli.js'), 'engage', 'revoke', path.join(dir, 'state'), '--id', 'lab']);
  const again = await c.execute(program);
  assert.equal(again.error.code, 'out_of_scope', 'revocation takes effect on the next call');
  // a forged engagement (edited after signing) is ignored
  const ef = path.join(dir, 'state', 'engagements.json');
  execFileSync(process.execPath, [path.join(ROOT, 'gateway', 'cli.js'), 'engage', 'add', path.join(dir, 'state'), '--id', 'narrow', '--target', '198.51.100.1']);
  const doc = JSON.parse(fs.readFileSync(ef, 'utf8')); doc.engagements[0].targets = ['0.0.0.0/0', '192.0.2.77']; fs.writeFileSync(ef, JSON.stringify(doc));
  const forged = await c.execute(program);
  assert.equal(forged.error.code, 'out_of_scope');
});

test('destructive tools are off by default; protected paths are refused', async () => {
  const c = client();
  const k = await c.execute('return await tools.kill(["-0", "1"])');
  assert.equal(k.error.code, 'destructive_off');
  const p = await c.execute(`return await tools.cat([${JSON.stringify(path.join(dir, 'state', 'seat-operator.token'))}])`);
  assert.equal(p.error.code, 'protected_path');
  const a = await c.execute('return await tools.find(["/tmp", "-name", "x", "-delete"])');
  assert.equal(a.error.code, 'arg_rule');
});

test('runner defense in depth: refuses without its token and refuses paths outside its allowlist', async () => {
  const rport = gw.cfg.runner.port;
  const ask = (obj) => new Promise((resolve) => {
    const s = net.connect(rport, '127.0.0.1', () => s.end(JSON.stringify(obj) + '\n'));
    let b = ''; s.on('data', (d) => (b += d)); s.on('end', () => resolve(JSON.parse(b)));
  });
  const before = spawned().length;
  assert.equal((await ask({ argv: ['/bin/sh', '-c', 'id'] })).error, 'unauthorized');
  const tok = fs.readFileSync(path.join(dir, 'state', 'runner.token'), 'utf8').trim();
  const r = await ask({ token: tok, argv: ['/bin/sh', '-c', 'id'] });
  assert.equal(r.error, 'denied');
  assert.match(r.detail, /allowlist/);
  assert.equal(spawned().length, before);
});

test('every call and denial is in the hash chain, and the chain verifies end to end', async () => {
  const v = verifyChain(path.join(dir, 'state', 'audit.log'));
  assert.equal(v.ok, true);
  assert.ok(v.count > 20);
  const lines = fs.readFileSync(path.join(dir, 'state', 'audit.log'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  assert.ok(lines.some((e) => e.decision === 'deny' && e.deny === 'out_of_scope' && e.spawned === false && e.targets[0].target === '192.0.2.77'));
  const op = new McpClient(base, T.operator);
  const seal = (await op.get('/api/seal')).json;
  assert.equal(seal.chain_ok, true);
  const crypto = require('crypto');
  const { signature, public_pem, ...body } = seal;
  assert.ok(crypto.verify(null, Buffer.from(require('../gateway/lib/canon').canonical(body)), crypto.createPublicKey(public_pem), Buffer.from(signature.sig, 'base64')));
});

test('QNX formats: inventory on fake-QNX fixtures (pidin arg, io-sock BSD netstat/ifconfig)', () => {
  const out = path.join(dir, 'qcat.json');
  execFileSync('sh', [path.join(ROOT, 'node-runtime', 'inventory-qnx.sh'), out], { env: { ...process.env, QNX_INV_BIN: path.join(__dirname, 'fixtures', 'fake-qnx') }, stdio: 'ignore' });
  const c = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.equal(c.meta.os, 'QNX');
  assert.equal(c.meta.qnx_version, '8.0.0');
  assert.deepEqual(c.processes.map((p) => p.name), ['procnto-smp-instr', 'slogger2', 'io-sock', 'qnx-runner', 'ksh']);
  assert.deepEqual(c.network.interfaces, ['lo0', 'vtnet0']);
  assert.deepEqual(c.network.interface_ips, ['127.0.0.1', '10.0.2.15']);
  assert.deepEqual(c.network.listeners.map((l) => `${l.proto}/${l.addr}/${l.port}/${l.family}`), ['tcp/*/7781/ipv4', 'tcp/*/22/ipv6', 'tcp/*/22/ipv4', 'tcp/127.0.0.1/8000/ipv4', 'udp/*/68/ipv4']);
});

test('QNX formats: sandbox parsers read BSD netstat, pidin arg and ls -l', async () => {
  const fx = (n, a = []) => execFileSync(path.join(__dirname, 'fixtures', 'fake-qnx', n), a, { encoding: 'utf8' });
  const program = `const ns = ${JSON.stringify(fx('netstat', ['-an']))}; const pi = ${JSON.stringify(fx('pidin', ['arg']))};
    const ifc = ${JSON.stringify(fx('ifconfig'))};
    const up = [...ifc.matchAll(/^(\\S+): flags=\\w+<([^>]*)>/gm)].filter((m) => m[2].split(',').includes('UP')).map((m) => m[1]);
    return { l: parse.listeners(ns).map((x) => x.proto + ' ' + x.addr + ':' + x.port), p: parse.processes(pi).map((x) => x.name), up,
      ls: parse.lsl('crw-rw-rw-  1 root root 8, 2 Jan 01 00:00 null\\nbrw-rw-rw-  1 root root 3, 0 Jan 01 00:00 hd0\\nlrwxrwxrwx 1 root root 4 Jan 01 00:00 stdin -> /dev/x') };`;
  const r = await client().execute(program);
  assert.equal(r.ok, true, JSON.stringify(r.error));
  assert.deepEqual(r.value.l, ['tcp *:7781', 'tcp *:22', 'tcp 127.0.0.1:8000', 'udp *:68']);
  assert.deepEqual(r.value.p, ['procnto-smp-instr', 'slogger2', 'io-sock', 'qnx-runner', 'ksh']);
  assert.deepEqual(r.value.up, ['lo0', 'vtnet0']);
  assert.deepEqual(r.value.ls.map((x) => x.mode[0] + x.name), ['cnull', 'bhd0', 'lstdin']);
});

test('runner output cap: an operator job may raise it (full inventory), an agent call through the gate may not', async () => {
  const { RunnerClient } = require('../gateway/lib/gate');
  const tok = fs.readFileSync(path.join(dir, 'state', 'runner.token'), 'utf8').trim();
  const inv = path.join(ROOT, 'node-runtime', 'inventory-qnx.sh');
  fs.appendFileSync(path.join(dir, 'state', 'runner.allow'), inv + '\n');
  const rc = new RunnerClient({ mode: 'tcp', host: '127.0.0.1', port: gw.cfg.runner.port, token: tok });
  const capped = await rc.run([inv, '-'], 60000);
  assert.equal(capped.truncated, true, 'the default cap applies without max_output');
  assert.equal(capped.stdout.length, 40000);
  const full = await rc.run([inv, '-'], 60000, 8 * 1024 * 1024);
  assert.equal(full.truncated, false);
  assert.ok(JSON.parse(full.stdout).tools.length > 100, 'the full catalog parses');
  const big = path.join(dir, 'big.txt');
  fs.writeFileSync(big, 'y'.repeat(100000));
  const r = await client().execute(`const x = await tools.cat([${JSON.stringify(big)}]); return { len: x.stdout.length, truncated: x.truncated }`);
  assert.deepEqual(r.value, { len: 40000, truncated: true }, 'agent calls keep the 40,000-character cap');
});
