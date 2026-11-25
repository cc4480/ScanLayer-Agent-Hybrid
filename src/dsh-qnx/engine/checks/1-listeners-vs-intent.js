// @check listeners-vs-intent
// Listening services on the target vs. the services the image manifest
// declares. Anything listening that the image didn't declare is a finding;
// a declared service that isn't listening is reported too.
const args = ['-an'];
const r = await tools.netstat(args);
const listeners = parse.listeners(r.stdout);
const declared = manifest.services || [];
const findings = [];
const isLoop = (a) => a === '::1' || a === 'localhost' || /^127\./.test(a) || a === '[::1]';
const isWild = (a) => a === '0.0.0.0' || a === '*' || a === '::' || a === '[::]' || a === '*.*';

for (const l of listeners) {
  const d = declared.find((s) => s.proto === l.proto && Number(s.port) === l.port);
  if (d) continue;
  const sev = isLoop(l.addr) ? 'low' : isWild(l.addr) ? 'high' : 'medium';
  findings.push({
    id: `listener-${l.proto}-${l.port}`,
    severity: sev,
    title: `Undeclared ${l.proto.toUpperCase()} listener on ${l.addr}:${l.port}`,
    detail: `The image manifest declares ${declared.length} service(s); nothing declares ${l.proto}/${l.port}. ${isWild(l.addr) ? 'It is bound to every interface, so it is reachable from the network.' : isLoop(l.addr) ? 'Loopback only.' : 'Bound to a specific address.'}`,
    evidence: [evidence(r, 'netstat', args, new RegExp(`[.:]${l.port}\\s`))],
    reproduce: { tool: 'netstat', args, expect: { type: 'listener', proto: l.proto, port: l.port } },
  });
}
for (const d of declared.filter((s) => s.required)) {
  if (listeners.some((l) => l.proto === d.proto && l.port === Number(d.port))) continue;
  findings.push({
    id: `service-down-${d.proto}-${d.port}`,
    severity: 'medium',
    title: `Declared service ${d.name || ''} (${d.proto}/${d.port}) is not listening`,
    detail: 'The manifest marks this service required, but no socket is bound to it.',
    evidence: [evidence(r, 'netstat', args, 'LISTEN')],
    reproduce: { tool: 'netstat', args, expect: { type: 'no_listener', proto: d.proto, port: Number(d.port) } },
  });
}
return {
  check: 'listeners-vs-intent',
  summary: { listeners: listeners.length, declared: declared.length, undeclared: findings.filter((f) => f.id.startsWith('listener-')).length, receipt: r.receipt },
  findings: capFindings(findings, 'listeners-vs-intent'),
};
