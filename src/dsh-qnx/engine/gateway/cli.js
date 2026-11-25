#!/usr/bin/env node
'use strict';
// Operator CLI. Tokens and keys are written to 0600 files and never printed:
// "token seated on-box only — never through chat".
//
//   cli.js init <stateDir> [--seats runner,smith,operator]
//   cli.js engage add <stateDir> --id ID --target T [--target T...] [--hours 24] [--operator NAME]
//   cli.js engage list <stateDir>
//   cli.js engage revoke <stateDir> --id ID
//   cli.js verify-chain <audit.log>
//   cli.js verify-report <report.json> [--pub signing.pub.pem]
//   cli.js allowlist <config.json> [--extra /abs/path ...]
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { sha256 } = require('./lib/canon');
const scope = require('./lib/scope');
const { verifyChain, verifySigned, loadOrCreateKey } = require('./lib/audit');

const argv = process.argv.slice(2);
const flag = (name, many = false) => {
  const out = [];
  for (let i = 0; i < argv.length; i++) if (argv[i] === `--${name}` && argv[i + 1] !== undefined) out.push(argv[i + 1]);
  return many ? out : out[0];
};
const die = (m, code = 1) => { console.error(m); process.exit(code); };
const writeSecret = (file, value) => { fs.writeFileSync(file, value + '\n', { mode: 0o600 }); fs.chmodSync(file, 0o600); };
const token = () => crypto.randomBytes(32).toString('base64url');

const [cmd, sub] = argv;

if (cmd === 'init') {
  const dir = path.resolve(argv[1] || die('usage: init <stateDir>'));
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const seatNames = (flag('seats') || 'runner,smith,operator').split(',').map((s) => s.trim()).filter(Boolean);
  const seats = {};
  for (const s of seatNames) {
    const t = token();
    writeSecret(path.join(dir, `seat-${s}.token`), t);
    seats[s] = sha256(t);
  }
  fs.writeFileSync(path.join(dir, 'seats.json'), JSON.stringify(seats, null, 2));
  if (!fs.existsSync(path.join(dir, 'runner.token'))) writeSecret(path.join(dir, 'runner.token'), token());
  if (!fs.existsSync(path.join(dir, 'operator.key'))) writeSecret(path.join(dir, 'operator.key'), crypto.randomBytes(32).toString('hex'));
  const k = loadOrCreateKey(dir);
  fs.writeFileSync(path.join(dir, 'signing.pub.pem'), k.pubPem);
  console.log(`initialized ${dir}`);
  console.log(`  seats: ${seatNames.join(', ')} (tokens in seat-<name>.token, mode 0600 — not printed)`);
  console.log(`  runner.token, operator.key, signing key ${k.keyId}`);
} else if (cmd === 'engage') {
  const dir = path.resolve(argv[2] || die('usage: engage add|list|revoke <stateDir> ...'));
  const file = path.join(dir, 'engagements.json');
  const key = fs.readFileSync(path.join(dir, 'operator.key'), 'utf8').trim();
  let doc; try { doc = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { doc = { engagements: [] }; }
  if (sub === 'add') {
    const id = flag('id') || die('--id required');
    const targets = flag('target', true);
    if (!targets.length) die('at least one --target required (IPv4, exact CIDR, hostname, or qnet:<node>)');
    let e;
    try { e = scope.addEngagement(file, key, { id, targets, hours: Number(flag('hours') || 24), operator: flag('operator') || process.env.USER || 'operator' }); } catch (err) { die(err.message); }
    console.log(`engagement ${id} signed: ${e.targets.join(', ')} until ${e.expires_at}`);
  } else if (sub === 'list') {
    const v = scope.loadEngagements(file, key);
    for (const e of v.engagements) console.log(`VERIFIED  ${e.id}  ${e.targets.join(', ')}  until ${e.expires_at}`);
    for (const r of v.rejected) console.log(`REJECTED  ${r.id}  (${r.reason})`);
    if (v.error) console.log(`note: ${v.error}`);
  } else if (sub === 'revoke') {
    const id = flag('id') || die('--id required');
    doc.engagements = doc.engagements.filter((x) => x.id !== id);
    fs.writeFileSync(file, JSON.stringify(doc, null, 2));
    console.log(`engagement ${id} revoked`);
  } else die('engage add|list|revoke');
} else if (cmd === 'verify-chain') {
  const r = verifyChain(path.resolve(argv[1] || die('usage: verify-chain <audit.log>')));
  console.log(r.ok ? `CHAIN OK  ${r.count} entries  head ${r.head}` : `CHAIN BROKEN at line ${r.bad_line}: ${r.reason}`);
  process.exit(r.ok ? 0 : 2);
} else if (cmd === 'verify-report') {
  const file = path.resolve(argv[1] || die('usage: verify-report <report.json> [--pub pem]'));
  const rep = JSON.parse(fs.readFileSync(file, 'utf8'));
  const pubFile = flag('pub') || path.join(path.dirname(file), '..', 'signing.pub.pem');
  const { file: _f, ...body } = rep; // `file` is added after signing, for convenience
  const ok = verifySigned(body, fs.readFileSync(pubFile, 'utf8'));
  console.log(ok ? `SIGNATURE OK  ${rep.kind} report, ${rep.findings.length} findings, audit head ${rep.audit.head.slice(0, 16)}…` : 'SIGNATURE INVALID');
  process.exit(ok ? 0 : 2);
} else if (cmd === 'allowlist') {
  const { loadConfig } = require('./server');
  const { Catalog } = require('./lib/catalog');
  const cfg = loadConfig(argv[1] || die('usage: allowlist <config.json>'));
  const mode = ['off', 'ask', 'on'].includes(cfg.destructive) ? cfg.destructive : (cfg.allow_destructive ? 'on' : 'off');
  const c = Catalog.load(cfg.catalog, { destructiveMode: mode });
  process.stdout.write(c.allowlist([...(cfg.inventory_path ? [cfg.inventory_path] : []), ...flag('extra', true)]));
} else {
  die('commands: init | engage add|list|revoke | verify-chain | verify-report | allowlist');
}
