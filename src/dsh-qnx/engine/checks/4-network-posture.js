// @check network-posture
// Interfaces up, routes, IP forwarding. On QNX 8 these come from io-sock's
// BSD-style ifconfig / netstat / sysctl; the stand-in uses the Linux names.
const net = manifest.network || {};
const findings = [];
const esc = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// IP forwarding: a target that routes between networks is a pivot.
const fwdKey = isQNX ? 'net.inet.ip.forwarding' : 'net.ipv4.ip_forward';
const fwd = await tools.sysctl([fwdKey]);
const fwdVal = (/[:=]\s*(\d+)/.exec(fwd.stdout) || [])[1] || null;
if (fwdVal === '1' && !net.forwarding) {
  findings.push({
    id: 'ip-forwarding', severity: 'high',
    title: 'IP forwarding is enabled',
    detail: 'The target routes packets between interfaces, and the manifest does not declare it as a router. A compromised peer can pivot through it.',
    evidence: [evidence(fwd, 'sysctl', [fwdKey])],
    reproduce: { tool: 'sysctl', args: [fwdKey], expect: { type: 'regex', pattern: '[:=]\\s*1\\b' } },
  });
}

// Interfaces that are UP vs. declared.
const ifc = await tools.ifconfig(['-a']);
const ifaces = [];
for (const m of ifc.stdout.matchAll(/^(\S+): flags=\w+<([^>]*)>/gm)) ifaces.push({ name: m[1], up: m[2].split(',').includes('UP'), flags: m[2] });
for (const i of ifaces.filter((x) => x.up)) {
  if (matchesAny(i.name, net.interfaces || [])) continue;
  findings.push({
    id: `iface-${i.name}`, severity: /^lo\d*$/.test(i.name) ? 'info' : 'medium',
    title: `Interface ${i.name} is UP but not declared`,
    detail: `Flags <${i.flags}>. The manifest declares: ${(net.interfaces || []).join(', ') || 'none'}.`,
    evidence: [evidence(ifc, 'ifconfig', ['-a'], `${i.name}:`)],
    reproduce: { tool: 'ifconfig', args: ['-a'], expect: { type: 'regex', pattern: `^${esc(i.name)}: flags=\\w+<[^>]*\\bUP\\b`, flags: 'm' } },
  });
}

// Routing table.
const rt = await tools.netstat(['-rn']);
const defaults = parse.lines(rt.stdout).filter((l) => /^(default|0\.0\.0\.0)\s/.test(l.trim()));
if (defaults.length && net.default_route === false) {
  findings.push({
    id: 'default-route', severity: 'medium',
    title: 'Default route present on an isolated target',
    detail: 'The manifest says this target has no default route (isolated network), but one exists.',
    evidence: [evidence(rt, 'netstat', ['-rn'], /^(default|0\.0\.0\.0)\s/)],
    reproduce: { tool: 'netstat', args: ['-rn'], expect: { type: 'regex', pattern: '^(default|0\\.0\\.0\\.0)\\s', flags: 'm' } },
  });
}
return {
  check: 'network-posture',
  summary: { forwarding: fwdVal, interfaces: ifaces, default_routes: defaults, receipts: [fwd.receipt, ifc.receipt, rt.receipt] },
  findings: capFindings(findings, 'network-posture'),
};
