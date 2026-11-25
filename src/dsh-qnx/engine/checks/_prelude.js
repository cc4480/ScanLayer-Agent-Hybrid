// Shared prelude, prepended to every check program. Runs inside the sandbox.
// Checks are ordinary `execute` programs: they call real tools on the target
// through the gate, and every finding cites the receipt of the call that
// proves it, plus a `reproduce` spec an independent seat can re-run.
const isQNX = catalog.meta.os === 'QNX';
const glob = (p) => new RegExp('^' + String(p).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
const matchesAny = (name, pats) => (pats || []).some((p) => glob(p).test(name));
const excerpt = (text, needle, max = 400) => {
  const lines = String(text).split('\n').filter((l) => l.trim());
  const hit = needle === undefined || needle === '' ? lines : lines.filter((l) => (needle instanceof RegExp ? needle.test(l) : l.includes(needle)));
  return (hit.length ? hit : lines).slice(0, 4).join('\n').slice(0, max);
};
const evidence = (r, tool, args, needle) => ({ receipt: r.receipt, tool, args, excerpt: excerpt(r.stdout + (r.stdout ? '' : r.stderr), needle) });
const MAX_FINDINGS = 25;
const capFindings = (findings, check) => {
  if (findings.length <= MAX_FINDINGS) return findings;
  const kept = findings.slice(0, MAX_FINDINGS);
  kept.push({ id: `${check}-more`, severity: 'info', title: `${findings.length - MAX_FINDINGS} more findings not listed`, detail: 'Raise MAX_FINDINGS or narrow the manifest to see all.', evidence: kept[0].evidence, reproduce: kept[0].reproduce });
  return kept;
};
