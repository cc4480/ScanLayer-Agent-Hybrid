#!/usr/bin/env node
'use strict';
// Demo driver for recording the video. Start the app (start-qnx.sh / start-qnx.ps1), open the QNX target page, start
// your screen recorder, then run this in a terminal beside it:
//
//   node src/dsh-qnx/engine/scripts/demo.js src/dsh-qnx/engine/standin/config.json      (or engine/qnx/config.json)
//   ... --auto 6      advance every 6 seconds instead of waiting for Enter
//
// Each step prints a one-line caption (the narration) and acts through the engine, so the gate tape in the harness
// shows it live. Nothing here is faked: the calls run on the target, through the gate, into the audit chain.
// On Linux/WSL with tcpdump (as root) the out-of-scope step also shows a live packet count.
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { spawn, spawnSync, execFileSync } = require('child_process');
const { loadConfig } = require('../gateway/server');
const { McpClient } = require('../gateway/lib/mcp-client');
const { verifyChain } = require('../gateway/lib/audit');

const args = process.argv.slice(2);
const cfgFile = args.find((a) => a.endsWith('.json')) || path.join(__dirname, '..', 'standin', 'config.json');
const autoIdx = args.indexOf('--auto');
const auto = autoIdx >= 0 ? Number(args[autoIdx + 1] || 6) : 0;
const cfg = loadConfig(cfgFile);
const st = cfg.state_dir;
const base = `http://${cfg.listen.host}:${cfg.listen.port}`;
const seat = (s) => new McpClient(base, fs.readFileSync(path.join(st, `seat-${s}.token`), 'utf8').trim());
const agent = seat('runner');
const cli = (...a) => execFileSync(process.execPath, [path.join(__dirname, '..', 'gateway', 'cli.js'), ...a], { encoding: 'utf8' }).trim();

const C = { b: '\x1b[1m', d: '\x1b[2m', g: '\x1b[32m', r: '\x1b[31m', y: '\x1b[33m', c: '\x1b[36m', x: '\x1b[0m' };
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const next = (what) => auto
  ? new Promise((r) => setTimeout(r, auto * 1000))
  : new Promise((r) => rl.question(`${C.d}  [Enter: ${what}]${C.x}`, () => r()));
let n = 0;
const step = async (caption, what) => { n++; console.log(`\n${C.b}${n}. ${caption}${C.x}`); await next(what); };
const show = (s) => console.log(`   ${s}`);

function witness(host) {
  if (process.platform !== 'linux' || spawnSync('tcpdump', ['--version']).status !== 0) return null;
  const p = spawn('tcpdump', ['-i', 'any', '-nn', '-l', '-U', 'host', host], { stdio: ['ignore', 'pipe', 'ignore'] });
  let count = 0;
  p.stdout.on('data', (d) => { count += String(d).split('\n').filter(Boolean).length; });
  return { stop: () => new Promise((r) => setTimeout(() => { p.kill('SIGINT'); r(count); }, 1200)) };
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  await agent.initialize();
  const state = (await seat('operator').get('/api/state')).json;
  const t = state.target;
  console.log(`${C.c}QNX agent demo — ${t.os === 'QNX' ? `QNX ${t.qnx_version || t.release}` : `${t.os} stand-in (not QNX)`} target "${t.hostname}". Keep the QNX target page visible.${C.x}`);

  await step('The model sees two tools: search and execute. It searches the target by intent.', 'search');
  const s = await agent.search('open ports listening sockets', 3);
  show(`search → ${s.matches.map((m) => m.name).join(', ')}   (${s.catalog_size} tools on the target, ${s.visible_size} callable)`);

  await step('It writes a program; the program calls netstat on the target. Only the answer comes back.', 'execute');
  const ex = await agent.execute('const r = await tools.netstat(["-an"]); return parse.listeners(r.stdout).map((l) => l.proto + " " + l.addr + ":" + l.port)');
  show(`${C.g}allowed${C.x} → ${ex.value.join(', ')}`);

  const victim = '192.0.2.77';
  await step(`Now it tries a host nobody approved: ping ${victim}.`, 'try it');
  try { cli('engage', 'revoke', st, '--id', 'demo-lab'); } catch {}
  let w = witness(victim);
  const denied = await agent.execute(`return await tools.ping(["-c", "2", "-W", "1", "${victim}"])`);
  show(`${C.r}denied${C.x} before anything ran: ${denied.error.message}`);
  if (w) show(`packets to ${victim}: ${C.b}${await w.stop()}${C.x}  (tcpdump was listening the whole time)`);

  await step('The operator signs an engagement for that network. The identical call now runs.', 'sign and retry');
  show(cli('engage', 'add', st, '--id', 'demo-lab', '--target', '192.0.2.0/24', '--hours', '1', '--operator', 'demo'));
  w = witness(victim);
  const allowed = await agent.execute(`const r = await tools.ping(["-c", "2", "-W", "1", "${victim}"]); return { exit: r.exit }`, 20000);
  show(`${C.g}allowed${C.x} (ping exit ${allowed.value && allowed.value.exit})`);
  if (w) show(`packets to ${victim}: ${C.b}${await w.stop()}${C.x}`);
  cli('engage', 'revoke', st, '--id', 'demo-lab');
  show(`${C.d}engagement revoked again${C.x}`);

  await step('A destructive command — kill — on a safety-critical OS.', 'try it');
  const k = await agent.execute('return await tools.kill(["-0", "1"])');
  show(`${C.r}${k.error.code}${C.x}: ${k.error.message}`);

  await step('Now the audit: six checks written for QNX, against the image manifest.', 'scan');
  await seat('operator').post('/api/board/reset');
  const scan = await agent.execute('return await qnx.scan()', 300000);
  for (const f of scan.value.findings.slice(0, 8)) show(`${f.severity === 'high' ? C.r : C.y}${f.severity.padEnd(6)}${C.x} ${f.title}  ${C.d}#${f.seq}${C.x}`);
  if (scan.value.findings.length > 8) show(`${C.d}… ${scan.value.findings.length - 8} more${C.x}`);

  await step('Agent Smith, a separate seat with its own key, reproduces every claim — including three planted lies.', 'verify');
  const real = (JSON.parse(fs.readFileSync(path.join(st, 'reports', 'latest-scan.json'), 'utf8')).findings[0] || {}).evidence || [];
  await agent.post('/api/board/post', { tag: 'planted-false', findings: [
    { id: 'planted: listener on 5555', severity: 'high', title: 'Planted false claim', evidence: real, reproduce: { tool: 'netstat', args: ['-an'], expect: { type: 'listener', proto: 'tcp', port: 5555 } } },
    { id: 'planted: ghostd running', severity: 'medium', title: 'Planted false claim', evidence: real, reproduce: { tool: 'ps', args: ['-A', '-o', 'pid=', '-o', 'comm='], expect: { type: 'process', name: 'ghostd' } } },
    { id: 'planted: forged receipt', severity: 'high', title: 'Planted false claim', evidence: [{ receipt: 'f'.repeat(64), tool: 'netstat', args: ['-an'], excerpt: '' }], reproduce: { tool: 'netstat', args: ['-an'], expect: { type: 'listener', proto: 'tcp', port: 4444 } } },
  ] });
  await agent.execute('return await qnx.verify()', 300000);
  for (const c of (await agent.get('/api/board')).json.claims) {
    const col = c.status === 'CONFIRMED' ? C.g : c.status === 'REFUTED' ? C.r : C.y;
    show(`${col}${c.status.padEnd(9)}${C.x} ${c.finding.id}`);
  }

  await step('Only confirmed findings reach the signed report.', 'sign');
  const rep = await agent.execute('return await qnx.report()', 300000);
  show(`${rep.value.confirmed.length} confirmed; ${rep.value.excluded.length} left out; signature ${rep.value.signature}…  (Scan & verify → Open the verified report)`);

  await step('Everything is one hash chain. Change one byte of a copy, and verification names the line.', 'tamper');
  const log = path.join(st, 'audit.log');
  const copy = path.join(st, 'audit.tampered-copy.log');
  const lines = fs.readFileSync(log, 'utf8').split('\n');
  const mid = Math.floor(lines.length / 2);
  lines[mid] = lines[mid].replace('"kind":"', '"kind":"X'); // one character, in one line in the middle
  fs.writeFileSync(copy, lines.join('\n'));
  const orig = verifyChain(log); const bad = verifyChain(copy);
  fs.unlinkSync(copy);
  show(`original: ${C.g}intact${C.x}, ${orig.count} entries`);
  show(`tampered copy: ${C.r}broken at line ${bad.bad_line}${C.x} (${bad.reason})`);

  console.log(`\n${C.c}That's an agent you can let near a safety-critical system: it only reaches what it's allowed to, proves every action, and a second agent checks its work.${C.x}\n`);
  rl.close();
  await sleep(50);
})().catch((e) => { console.error(e.message); rl.close(); process.exit(1); });
