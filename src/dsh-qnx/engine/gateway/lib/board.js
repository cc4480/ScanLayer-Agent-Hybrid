'use strict';
// Phase 6 — verification loop. The runner seat posts findings as CLAIMS on an
// engagement board. A DIFFERENT seat (Agent Smith's) must lock a claim and
// reproduce it itself, through the same gateway, with its own token:
//   CONFIRMED  its own fresh run shows what the claim says
//   REFUTED    its own fresh run contradicts the claim
//   UNPROVEN   it could not reproduce (denied, error, timeout) or the claim
//              cites receipts that are not in the chain
// The board refuses a verdict unless: the seat holds the lock, the seat is not
// the claim's author, and (for CONFIRMED/REFUTED) the cited run is a real
// execute_end by that seat that made an allowed call to the claim's
// reproduce tool. Only CONFIRMED claims reach the verified report.
const fs = require('fs');
const { Audit } = require('./audit');

const LOCK_MS = 120000;

class Board {
  constructor(file, auditFile) { this.file = file; this.auditFile = auditFile; }
  read() { try { return JSON.parse(fs.readFileSync(this.file, 'utf8')); } catch { return { claims: [] }; } }
  write(doc) { const tmp = this.file + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(doc, null, 2)); fs.renameSync(tmp, this.file); }

  post(report, seat) {
    const doc = this.read();
    let added = 0;
    for (const f of report.findings) {
      const id = `${report.generated_at}#${f.id}`;
      if (doc.claims.some((c) => c.id === id)) continue;
      doc.claims.push({ id, finding: f, author_seat: seat, report_sig: report.signature.sig.slice(0, 32), status: 'OPEN', lock: null, verdict: null, posted_at: new Date().toISOString() });
      added++;
    }
    this.write(doc);
    return { added, total: doc.claims.length };
  }

  /** Post arbitrary claims (used by the fixture with planted true/false findings). */
  postClaims(findings, seat, tag = 'fixture') {
    const doc = this.read();
    const now = new Date().toISOString();
    for (const f of findings) doc.claims.push({ id: `${tag}@${now}#${f.id}`, finding: f, author_seat: seat, report_sig: null, status: 'OPEN', lock: null, verdict: null, posted_at: now });
    this.write(doc);
    return { added: findings.length };
  }

  lock(id, seat, now = Date.now()) {
    const doc = this.read();
    const c = doc.claims.find((x) => x.id === id);
    if (!c) return { error: 'no such claim' };
    if (c.author_seat === seat) return { error: 'a claim cannot be verified by the seat that made it' };
    if (!['OPEN', 'LOCKED'].includes(c.status)) return { error: `claim already ${c.status}` };
    if (c.status === 'LOCKED' && c.lock.seat !== seat && Date.parse(c.lock.until) > now) return { error: `locked by ${c.lock.seat}` };
    c.status = 'LOCKED';
    c.lock = { seat, until: new Date(now + LOCK_MS).toISOString() };
    this.write(doc);
    return { ok: true, claim: c };
  }

  verdict(id, seat, { verdict, run_receipt, observed }) {
    const doc = this.read();
    const c = doc.claims.find((x) => x.id === id);
    if (!c) return { error: 'no such claim' };
    if (c.status !== 'LOCKED' || !c.lock || c.lock.seat !== seat) return { error: 'seat does not hold the lock' };
    if (c.author_seat === seat) return { error: 'a claim cannot be verified by the seat that made it' };
    if (!['CONFIRMED', 'REFUTED', 'UNPROVEN'].includes(verdict)) return { error: 'verdict must be CONFIRMED, REFUTED or UNPROVEN' };
    const entries = Audit.readAll(this.auditFile);
    const byHash = new Map(entries.map((e) => [e.hash, e]));
    if (verdict !== 'UNPROVEN') {
      const run = byHash.get(run_receipt);
      if (!run || run.kind !== 'execute_end' || run.seat !== seat || run.decision !== 'allow') return { error: 'run_receipt is not a successful execute run by this seat' };
      const want = c.finding.reproduce && c.finding.reproduce.tool;
      const made = (run.call_receipts || []).map((h) => byHash.get(h)).filter(Boolean);
      if (!made.some((e) => e.decision === 'allow' && e.tool === want)) return { error: `run made no allowed call to the reproduce tool "${want}"` };
      // the claim's own evidence must be real too
      const ev = c.finding.evidence || [];
      if (!ev.length || ev.some((e) => !byHash.has(e.receipt))) return { error: 'claim cites receipts not in the chain: only UNPROVEN is allowed' };
    }
    c.status = verdict;
    c.verdict = { verdict, seat, run_receipt: run_receipt || null, observed: observed || null, at: new Date().toISOString() };
    c.lock = null;
    this.write(doc);
    return { ok: true, claim: c };
  }

  open(seat) { return this.read().claims.filter((c) => (c.status === 'OPEN' || c.status === 'LOCKED') && c.author_seat !== seat); }
}

module.exports = { Board };
