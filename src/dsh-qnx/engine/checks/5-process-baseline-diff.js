// @check process-baseline-diff
// Running processes vs. what the image ships. Anything running that the image
// didn't declare is a finding — the QNX version of "who else is in my house".
// QNX: pidin is authoritative; ps is the POSIX fallback (and the stand-in's).
let tool = 'ps', args = ['-A', '-o', 'pid=', '-o', 'comm='];
let r = isQNX ? null : await tools.ps(args);
let procs = r ? parse.processes(r.stdout) : [];
if (isQNX) {
  tool = 'pidin'; args = ['arg']; // one row per process: pid + full argument line
  r = await tools.pidin(args);
  procs = parse.processes(r.stdout);
  if (!procs.length) { tool = 'ps'; args = ['-A', '-o', 'pid=', '-o', 'comm=']; r = await tools.ps(args); procs = parse.processes(r.stdout); }
}
const declared = manifest.processes || [];
const required = manifest.required_processes || [];
const byName = new Map();
for (const p of procs) { if (!byName.has(p.name)) byName.set(p.name, []); byName.get(p.name).push(p.pid); }

const findings = [];
for (const [name, pids] of byName) {
  if (matchesAny(name, declared)) continue;
  findings.push({
    id: `proc-${name}`, severity: 'medium',
    title: `Undeclared process running: ${name} (pid ${pids.join(', ')})`,
    detail: 'The image manifest does not ship this process. Something started it after boot.',
    evidence: [evidence(r, tool, args, new RegExp(`\\s${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*$`))],
    reproduce: { tool, args, expect: { type: 'process', name } },
  });
}
for (const name of required) {
  if (byName.has(name)) continue;
  findings.push({
    id: `proc-missing-${name}`, severity: 'high',
    title: `Required process not running: ${name}`,
    detail: 'The manifest marks this process required for the system to be in its declared state.',
    evidence: [evidence(r, tool, args)],
    reproduce: { tool, args, expect: { type: 'no_process', name } },
  });
}
return {
  check: 'process-baseline-diff',
  summary: { running: procs.length, distinct: byName.size, declared_patterns: declared.length, source: `${tool} ${args.join(' ')}`, receipt: r.receipt },
  findings: capFindings(findings, 'process-baseline-diff'),
};
