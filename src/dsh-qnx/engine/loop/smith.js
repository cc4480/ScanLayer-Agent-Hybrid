#!/usr/bin/env node
'use strict';
// Agent Smith's seat — the independent verifier (Phase 6).
//
// Works the engagement board: for every open claim it did not author, it takes
// the claim lock, then reproduces the claim ITSELF through the gateway with its
// own token. It never reuses the runner seat's output: it reads only the
// claim's `reproduce` spec, writes its own program, runs it on the target, and
// judges the fresh output:
//   CONFIRMED  fresh output shows what the claim says
//   REFUTED    fresh output contradicts it
//   UNPROVEN   cannot reproduce (denied / error / timeout / bad spec), or the
//              claim cites receipts that are not in the audit chain
//
//   node loop/smith.js --url http://127.0.0.1:8095 --token-file standin/state/seat-smith.token
const fs = require('fs');
const { McpClient } = require('../gateway/lib/mcp-client');

// The verifier program. The spec is embedded as a JSON literal — data, never code.
function reproductionProgram(spec) {
  return `const spec = ${JSON.stringify(spec)};
const r = await tools[spec.tool](spec.args || []);
const e = spec.expect || {};
const text = e.on === 'stderr' ? r.stderr : r.stdout;
let holds, observed;
switch (e.type) {
  case 'listener': case 'no_listener': {
    const ls = parse.listeners(text);
    const hit = ls.find((l) => l.proto === e.proto && l.port === Number(e.port));
    holds = e.type === 'listener' ? !!hit : !hit;
    observed = hit ? 'listener ' + hit.proto + ' ' + hit.addr + ':' + hit.port + ' present' : 'no ' + e.proto + '/' + e.port + ' listener among ' + ls.length;
    break;
  }
  case 'process': case 'no_process': {
    const hit = parse.processes(text).filter((p) => p.name === e.name);
    holds = e.type === 'process' ? hit.length > 0 : hit.length === 0;
    observed = hit.length ? e.name + ' running (pid ' + hit.map((p) => p.pid).join(', ') + ')' : e.name + ' not running';
    break;
  }
  case 'world_writable': {
    const mode = (text.trim().split(/\\s+/)[0] || '');
    holds = mode.length >= 10 && mode[8] === 'w';
    observed = mode ? 'mode ' + mode : 'path not found: ' + r.stderr.trim().slice(0, 120);
    break;
  }
  case 'regex': case 'not_regex': {
    const m = new RegExp(e.pattern, e.flags || '').exec(text);
    holds = e.type === 'regex' ? !!m : !m;
    observed = m ? 'matched: ' + m[0].slice(0, 120) : 'no match for /' + e.pattern + '/';
    break;
  }
  default: throw new Error('unknown predicate type: ' + e.type);
}
return { holds, observed, exit: r.exit, call_receipt: r.receipt };`;
}

async function verifyClaim(client, claim, chainHashes) {
  const f = claim.finding;
  const cited = (f.evidence || []).map((e) => e.receipt);
  if (!cited.length || cited.some((h) => !chainHashes.has(h))) {
    return { verdict: 'UNPROVEN', observed: 'claim cites receipts that are not in the audit chain' };
  }
  if (!f.reproduce || !f.reproduce.tool) return { verdict: 'UNPROVEN', observed: 'claim has no reproduce spec' };
  const res = await client.execute(reproductionProgram(f.reproduce), 60000);
  if (!res.ok) return { verdict: 'UNPROVEN', observed: `could not reproduce: ${res.error.kind}${res.error.code ? '/' + res.error.code : ''} — ${res.error.message}`, run_receipt: res.receipt };
  return { verdict: res.value.holds ? 'CONFIRMED' : 'REFUTED', observed: res.value.observed, run_receipt: res.receipt };
}

async function workBoard({ url, token, log = console.log }) {
  const client = new McpClient(url, token);
  await client.initialize();
  let entries = [];
  for (let after = 0; ;) {
    const page = (await client.get(`/api/audit?after=${after}&limit=2000`)).json.entries;
    entries = entries.concat(page);
    if (page.length < 2000) break;
    after = page[page.length - 1].seq;
  }
  const chainHashes = new Set(entries.filter((e) => e.kind === 'call' && e.decision === 'allow').map((e) => e.hash));
  const open = (await client.get('/api/board/open')).json.claims;
  const out = [];
  for (const c of open) {
    const lock = await client.post('/api/board/lock', { id: c.id });
    if (lock.status !== 200) { log(`skip ${c.finding.id}: ${lock.json.error}`); continue; }
    let v;
    try { v = await verifyClaim(client, c, chainHashes); } catch (e) { v = { verdict: 'UNPROVEN', observed: `verifier error: ${e.message}` }; }
    const posted = await client.post('/api/board/verdict', { id: c.id, ...v });
    if (posted.status !== 200 && v.verdict !== 'UNPROVEN') {
      // the board refused (e.g. reproduce tool never actually ran): downgrade, never upgrade
      const fallback = await client.post('/api/board/verdict', { id: c.id, verdict: 'UNPROVEN', observed: `board refused ${v.verdict}: ${posted.json.error}` });
      v = { verdict: 'UNPROVEN', observed: `board refused: ${posted.json.error}`, ok: fallback.status === 200 };
    }
    log(`${v.verdict.padEnd(9)} ${c.finding.id} — ${v.observed}`);
    out.push({ id: c.finding.id, ...v });
  }
  return out;
}

if (require.main === module) {
  const arg = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i > 0 ? process.argv[i + 1] : d; };
  const url = arg('url', 'http://127.0.0.1:8095');
  const token = fs.readFileSync(arg('token-file', 'standin/state/seat-smith.token'), 'utf8').trim();
  workBoard({ url, token }).then((r) => { console.log(`verified ${r.length} claim(s)`); }).catch((e) => { console.error(e.message); process.exit(1); });
}

module.exports = { workBoard, reproductionProgram, verifyClaim };
