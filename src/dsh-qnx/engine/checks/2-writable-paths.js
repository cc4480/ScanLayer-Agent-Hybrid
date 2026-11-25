// @check writable-paths
// World-writable files and directories in the image, and resource-manager
// pathnames under /dev that any process can write. On QNX, drivers and
// resource managers ARE pathnames, so a world-writable /dev entry is an open
// door to a driver.
const roots = manifest.writable_scan_roots || (isQNX
  ? ['/proc/boot', '/system', '/data', '/bin', '/sbin', '/usr', '/etc', '/var', '/tmp']
  : ['/bin', '/sbin', '/usr', '/etc', '/opt', '/var', '/tmp', '/home', '/root']);
const allow = manifest.writable_allow || ['/tmp', '/var/tmp', '/dev/shm', '/var/lock', '/run/lock'];
const findings = [];

const wwArgs = [...roots, '-xdev', '-perm', '-0002', '!', '-type', 'l', '-print'];
const ww = await tools.find(wwArgs, { timeout_ms: 60000 });
const stickyArgs = [...roots, '-xdev', '-type', 'd', '-perm', '-1002', '-print'];
const sticky = await tools.find(stickyArgs, { timeout_ms: 60000 });
const stickySet = new Set(parse.lines(sticky.stdout));
const execDirs = isQNX ? /^\/(proc\/boot|system|bin|sbin|usr\/bin|usr\/sbin|usr\/lib|lib|etc)(\/|$)/ : /^\/(bin|sbin|usr\/bin|usr\/sbin|usr\/lib|lib|lib64|etc)(\/|$)/;

for (const p of parse.lines(ww.stdout)) {
  if (matchesAny(p, allow)) continue;
  const isSticky = stickySet.has(p);
  const sev = execDirs.test(p) ? 'high' : isSticky ? 'low' : 'medium';
  findings.push({
    id: `ww-${p}`,
    severity: sev,
    title: `World-writable ${isSticky ? 'sticky directory' : 'path'}: ${p}`,
    detail: execDirs.test(p) ? 'Writable by any process inside a system/executable location: a local process can replace what the system runs or reads.' : isSticky ? 'Sticky bit limits deletion to owners, but any process can create entries here.' : 'Any process on the target can modify this path.',
    evidence: [evidence(ww, 'find', wwArgs, p)],
    reproduce: { tool: 'ls', args: ['-ld', p], expect: { type: 'world_writable' } },
  });
}

const devAllow = manifest.dev_world_writable_allow || ['/dev/null', '/dev/zero', '/dev/full', '/dev/tty', '/dev/random', '/dev/urandom', '/dev/ptmx', '/dev/ptyp*', '/dev/ttyp*', '/dev/shmem', '/dev/socket', '/dev/name', '/dev/mqueue', '/dev/shm', '/dev/pts', '/dev/console'];
const devArgs = ['-l', '/dev'];
const dev = await tools.ls(devArgs);
for (const e of parse.lsl(dev.stdout)) {
  const p = '/dev/' + e.name;
  if (e.mode[0] === 'l' || e.mode[8] !== 'w' || matchesAny(p, devAllow)) continue;
  findings.push({
    id: `dev-ww-${e.name}`,
    severity: e.mode[0] === 'b' ? 'high' : 'medium',
    title: `Resource manager pathname ${p} is world-writable (${e.mode})`,
    detail: e.mode[0] === 'b' ? 'Block device writable by any process: raw access to storage.' : 'Any process can send write/devctl requests to the resource manager behind this pathname.',
    evidence: [evidence(dev, 'ls', devArgs, ' ' + e.name)],
    reproduce: { tool: 'ls', args: ['-ld', p], expect: { type: 'world_writable' } },
  });
}
return {
  check: 'writable-paths',
  summary: { roots, world_writable: parse.lines(ww.stdout).length, sticky_dirs: stickySet.size, scan_truncated: ww.truncated, dev_entries: parse.lsl(dev.stdout).length, receipts: [ww.receipt, sticky.receipt, dev.receipt] },
  findings: capFindings(findings, 'writable-paths'),
};
