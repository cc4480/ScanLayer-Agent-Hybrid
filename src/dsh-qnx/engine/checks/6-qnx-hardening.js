// @check qnx-hardening
// QNX-specific exposure that a generic scanner misses:
//   - qconn, the QNX target agent: it lets a connected host launch processes, move files and debug with no
//     authentication. It belongs on development images only; on a shipped image it is a remote takeover.
//   - pdebug (remote debug agent) and the cleartext remote-login family (inetd, telnetd, ftpd, rlogind, rshd).
//   - Qnet: with lsm-qnet loaded, other nodes reach this node's resource managers by pathname (/net/<node>/...).
//   - A security policy (secpol) where the manifest says one is required.
// Allowed development services can be listed in manifest.allowed_dev_services (e.g. ["qconn"] on a lab image).
const findings = [];
const allowed = new Set(manifest.allowed_dev_services || []);
const net = manifest.network || {};

const RISKY = [
  { name: 'qconn', port: 8000, severity: 'high', title: 'qconn, the QNX target agent, is running', detail: 'qconn lets any connected host launch processes, transfer files and attach a debugger, with no authentication. It is for development images and must not ship.' },
  { name: 'pdebug', port: 8000, severity: 'high', title: 'pdebug, the QNX remote debug agent, is running', detail: 'A remote debug agent lets a connected host control processes on this target.' },
  { name: 'telnetd', port: 23, severity: 'high', title: 'telnetd is running: cleartext remote login', detail: 'Credentials and sessions cross the network unencrypted.' },
  { name: 'ftpd', port: 21, severity: 'high', title: 'ftpd is running: cleartext file transfer with login', detail: 'Credentials and files cross the network unencrypted.' },
  { name: 'rlogind', port: 513, severity: 'high', title: 'rlogind is running: legacy trust-based remote login', detail: 'Host-based trust with no encryption.' },
  { name: 'rshd', port: 514, severity: 'high', title: 'rshd is running: legacy trust-based remote shell', detail: 'Host-based trust with no encryption.' },
  { name: 'inetd', port: null, severity: 'medium', title: 'inetd is running: services start on demand', detail: 'inetd starts telnet, ftp and other services when a connection arrives; the listeners may not show until then.' },
];

// Processes. On QNX, `pidin arg` (pid then full arguments) also shows what io-sock loaded (Qnet); elsewhere only
// names are needed, and full argument lines can exceed the runner's 40,000-character output cap.
const pTool = isQNX ? 'pidin' : 'ps';
const pArgs = isQNX ? ['arg'] : ['-A', '-o', 'pid=', '-o', 'comm='];
const pr = await tools[pTool](pArgs);
const procs = parse.processes(pr.stdout);
const nArgs = ['-an'];
const nr = await tools.netstat(nArgs);
const listeners = parse.listeners(nr.stdout);

// A port is explained when any service that uses it is running (qconn and pdebug share 8000).
const explained = new Set(RISKY.filter((r) => r.port && procs.some((p) => p.name === r.name)).map((r) => r.port));
for (const r of RISKY) {
  if (allowed.has(r.name)) continue;
  const running = procs.filter((p) => p.name === r.name);
  if (running.length) {
    findings.push({
      id: `qnx-${r.name}`, severity: r.severity, title: `${r.title} (pid ${running.map((p) => p.pid).join(', ')})`, detail: r.detail,
      evidence: [evidence(pr, pTool, pArgs, new RegExp(`(^|/|\\s)${r.name}(\\s|$)`))],
      reproduce: { tool: pTool, args: pArgs, expect: { type: 'process', name: r.name } },
    });
    continue;
  }
  const port = r.port && !explained.has(r.port) && listeners.find((l) => l.proto === 'tcp' && l.port === r.port);
  if (port && !findings.some((f) => f.id === `qnx-port-${r.port}`)) {
    findings.push({
      id: `qnx-port-${r.port}`, severity: 'medium', title: `TCP ${r.port} is listening: the port ${r.name} uses`,
      detail: `Nothing named ${r.name} is running, but its default port is open on ${port.addr}. Check what owns it.`,
      evidence: [evidence(nr, 'netstat', nArgs, new RegExp(`[.:]${r.port}\\s`))],
      reproduce: { tool: 'netstat', args: nArgs, expect: { type: 'listener', proto: 'tcp', port: r.port } },
    });
  }
}

// Qnet (QNX only): io-sock loads lsm-qnet; with it, other nodes reach this node by pathname.
let qnet = 'not applicable (not QNX)';
if (isQNX) {
  const loaded = /lsm-qnet/.test(pr.stdout);
  qnet = loaded ? 'enabled' : 'not loaded';
  if (loaded && !net.qnet) {
    findings.push({
      id: 'qnx-qnet', severity: 'medium', title: 'Qnet is enabled: other nodes can reach this node by pathname',
      detail: 'lsm-qnet is loaded, so any Qnet node can open this node\'s resource managers through /net/<node>/... The manifest does not declare Qnet.',
      evidence: [evidence(pr, pTool, pArgs, /lsm-qnet/)],
      reproduce: { tool: pTool, args: pArgs, expect: { type: 'regex', pattern: 'lsm-qnet' } },
    });
  }
}

// Security policy (QNX only): reported always; a finding only when the manifest requires one.
let secpol = 'not applicable (not QNX)';
if (isQNX) {
  const bArgs = ['/proc/boot'];
  const br = await tools.ls(bArgs);
  const has = /(^|\s)secpol[^\s]*(\s|$)/m.test(br.stdout);
  secpol = has ? 'present in /proc/boot' : 'none in /proc/boot';
  if (!has && manifest.security_policy_required) {
    findings.push({
      id: 'qnx-no-secpol', severity: 'high', title: 'No security policy in the boot image',
      detail: 'The manifest requires a QNX security policy (secpol), but none is in /proc/boot, so processes run without the policy\'s type and ability limits.',
      evidence: [evidence(br, 'ls', bArgs)],
      reproduce: { tool: 'ls', args: bArgs, expect: { type: 'not_regex', pattern: '(^|\\s)secpol', flags: 'm' } },
    });
  }
}

return {
  check: 'qnx-hardening',
  summary: { qconn: procs.some((p) => p.name === 'qconn') ? 'running' : 'not running', qnet, secpol, allowed_dev_services: [...allowed], process_list_truncated: pr.truncated, receipts: [pr.receipt, nr.receipt] },
  findings: capFindings(findings, 'qnx-hardening'),
};
