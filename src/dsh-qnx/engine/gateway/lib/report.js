'use strict';
// Signed reports. A finding reaches a report only if every receipt it cites
// exists in an intact audit chain. Unbacked findings are listed by id in
// `rejected`, never as findings.
const fs = require('fs');
const path = require('path');
const { Audit, verifyChain } = require('./audit');

function buildReport({ kind, checkResults, auditFile, signer, catalogMeta, extra = {} }) {
  const chain = verifyChain(auditFile);
  const entries = Audit.readAll(auditFile);
  const byHash = new Map(entries.map((e) => [e.hash, e]));
  const findings = [];
  const rejected = [];
  const checks = [];
  for (const cr of checkResults) {
    checks.push({ check: cr.check, ok: cr.ok, run_receipt: cr.run_receipt, error: cr.error || null, finding_count: (cr.findings || []).length, summary: cr.summary || null });
    for (const f of cr.findings || []) {
      const ev = Array.isArray(f.evidence) ? f.evidence : [];
      const missing = ev.filter((e) => !byHash.has(e.receipt) || byHash.get(e.receipt).decision !== 'allow');
      if (!chain.ok || ev.length === 0 || missing.length) {
        rejected.push({ id: f.id, check: cr.check, reason: !chain.ok ? 'audit chain broken' : ev.length === 0 ? 'cites no receipt' : `cites ${missing.length} receipt(s) not found as allowed calls in the chain` });
        continue;
      }
      findings.push({
        // a verified report re-collects findings from the board: keep the check that originally found each one
        ...f, check: f.check || cr.check,
        evidence: ev.map((e) => {
          const a = byHash.get(e.receipt);
          return { ...e, seq: a.seq, argv: a.argv, exit: a.exit, stdout_sha256: a.stdout_sha256, ts: a.ts };
        }),
      });
    }
  }
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9) || a.id.localeCompare(b.id));
  const body = {
    schema: 'qnx-agent.report.v1', kind,
    generated_at: new Date().toISOString(),
    target: { hostname: catalogMeta.hostname, os: catalogMeta.os, release: catalogMeta.release, qnx_version: catalogMeta.qnx_version || null, machine: catalogMeta.machine },
    audit: { verified: chain.ok, entries: chain.count, head: chain.head },
    checks, findings, rejected,
    counts: Object.fromEntries(Object.keys(sevOrder).map((s) => [s, findings.filter((f) => f.severity === s).length])),
    ...extra,
  };
  return { ...body, signature: { alg: 'ed25519', key_id: signer.keyId, sig: signer.sign(body) } };
}

function saveReport(dir, report) {
  fs.mkdirSync(dir, { recursive: true });
  const name = `${report.kind}-${report.generated_at.replace(/[:.]/g, '-')}.json`;
  const file = path.join(dir, name);
  fs.writeFileSync(file, JSON.stringify(report, null, 2));
  fs.writeFileSync(path.join(dir, `latest-${report.kind}.json`), JSON.stringify(report, null, 2));
  return file;
}

module.exports = { buildReport, saveReport };
