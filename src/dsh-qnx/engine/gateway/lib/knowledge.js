'use strict';
// Tool knowledge for the QNX target: what each utility does (for `search`),
// its class, and argument rules the gate enforces before anything spawns.
//
// Classes:
//   read        local, read-only inspection. Visible by default.
//   net         sends packets to a target. Visible by default, but every target
//               in argv must pass the scope gate (self, or a verified engagement).
//   destructive changes state (kills, writes, mounts, reconfigures) or executes
//               arbitrary code. OFF by default on QNX — a safety-critical OS —
//               enabling is an explicit operator action, never a default.
//
// FAIL CLOSED: a tool not listed here is classed `destructive` (MCP's own
// default for unannotated tools is destructiveHint=true). It stays in the
// catalog, findable by name, but is not callable unless the operator opts in.

const T = (cls, desc, extra = {}) => ({ cls, desc, ...extra });

// argRules: { denyFlags: [...], denyFlagPrefixes: [...], allowOnly: fn(args) -> null | reason }
const KNOWLEDGE = {
  // ---------------- QNX-native inspection ----------------
  pidin: T('read', 'QNX process/thread inspector: list processes, threads, states, memory maps, file descriptors, timers, arguments, environment (pidin arg, pidin mem, pidin fds, pidin info).', {
    qnx: true, tags: ['process', 'thread', 'memory', 'fd', 'system info', 'ps'],
  }),
  slog2info: T('read', 'QNX system logger: dump slog2 log buffers (driver, kernel and service logs). Use -w only interactively; it is rejected here.', {
    qnx: true, tags: ['log', 'syslog', 'dmesg', 'events'], argRules: { denyFlags: ['-w', '-c'] },
  }),
  sloginfo: T('read', 'QNX legacy system log reader (slogger).', { qnx: true, tags: ['log', 'syslog'], argRules: { denyFlags: ['-c'] } }),
  use: T('read', 'QNX: print the usage message embedded in a binary; "use -i <file>" prints its build/version info (component version inventory).', {
    qnx: true, tags: ['usage', 'help', 'version', 'build info', 'component'],
  }),
  showmem: T('read', 'QNX: summarize system and per-process memory usage.', { qnx: true, tags: ['memory', 'ram'] }),
  hogs: T('read', 'QNX: list processes using the most CPU. Pass -i <n> to bound iterations.', { qnx: true, tags: ['cpu', 'top', 'load'] }),
  'pci-tool': T('read', 'QNX: enumerate PCI devices and configuration space (read-only flags only).', {
    qnx: true, tags: ['pci', 'hardware', 'devices'], argRules: { denyFlagPrefixes: ['-w', '--write'] },
  }),
  getconf: T('read', 'Print system configuration variables (POSIX).', { tags: ['config', 'limits'] }),
  sysctl: T('read', 'Read kernel/network-stack variables (io-sock on QNX 8). Writes (name=value, -w) are rejected.', {
    tags: ['kernel', 'network', 'forwarding', 'tunables'],
    argRules: { denyFlags: ['-w', '-f', '-p', '--write', '--load', '--system'], allowOnly: (a) => (a.some((x) => x.includes('=')) ? 'sysctl writes (name=value) are destructive' : null) },
  }),

  // ---------------- POSIX inspection ----------------
  uname: T('read', 'Print OS name, release (QNX version), machine.', { tags: ['os', 'version', 'kernel'] }),
  hostname: T('read', 'Print the node name. Setting it is rejected.', { tags: ['host', 'name'], argRules: { allowOnly: (a) => (a.filter((x) => !x.startsWith('-')).length ? 'setting the hostname is destructive' : null) } }),
  id: T('read', 'Print user and group IDs.', { tags: ['user', 'identity'] }),
  whoami: T('read', 'Print the effective user name.', { tags: ['user'] }),
  date: T('read', 'Print the date. Setting the clock is rejected.', { tags: ['time', 'clock'], argRules: { allowOnly: (a) => (a.some((x) => !x.startsWith('-') && !x.startsWith('+')) || a.includes('-s') || a.includes('--set') ? 'setting the clock is destructive' : null) } }),
  uptime: T('read', 'Time since boot and load.', { tags: ['boot', 'load'] }),
  ps: T('read', 'List processes (POSIX ps).', { tags: ['process', 'running'] }),
  ls: T('read', 'List directory contents; on QNX, ls /dev shows resource managers, ls /proc/boot shows the image file system.', { tags: ['files', 'directory', 'resource manager', 'dev'] }),
  cat: T('read', 'Print file contents.', { tags: ['read file', 'contents'] }),
  head: T('read', 'Print the first lines of a file.', { tags: ['read file'] }),
  tail: T('read', 'Print the last lines of a file (follow mode rejected).', { tags: ['read file', 'log'], argRules: { denyFlags: ['-f', '-F', '--follow'] } }),
  wc: T('read', 'Count lines, words, bytes.', { tags: ['count'] }),
  stat: T('read', 'File status: permissions, owner, size, times.', { tags: ['permissions', 'metadata', 'file info'] }),
  file: T('read', 'Identify file type.', { tags: ['type', 'binary'] }),
  find: T('read', 'Search the filesystem by name, type, permissions (e.g. -perm -0002 for world-writable). Actions that execute or delete are rejected.', {
    tags: ['search files', 'permissions', 'world-writable', 'suid'],
    argRules: { denyFlags: ['-delete', '-exec', '-execdir', '-ok', '-okdir', '-fprint', '-fprint0', '-fprintf', '-fls'] },
  }),
  grep: T('read', 'Search file contents by pattern.', { tags: ['search text', 'pattern', 'regex'] }),
  df: T('read', 'Filesystem space usage and mounts.', { tags: ['disk', 'filesystem', 'mount'] }),
  du: T('read', 'Disk usage of files/dirs.', { tags: ['disk', 'size'] }),
  mount: T('read', 'With no arguments: list mounted filesystems. Mounting is rejected.', { tags: ['mount', 'filesystem'], argRules: { allowOnly: (a) => (a.length ? 'mount with arguments is destructive' : null) } }),
  which: T('read', 'Locate a command on PATH.', { tags: ['path', 'locate'] }),
  readlink: T('read', 'Resolve a symbolic link.', { tags: ['link'] }),
  realpath: T('read', 'Resolve a canonical path.', { tags: ['path'] }),
  basename: T('read', 'Strip directory from a path.', {}),
  dirname: T('read', 'Strip last component from a path.', {}),
  cksum: T('read', 'POSIX checksum of files (component integrity).', { tags: ['hash', 'integrity'] }),
  md5sum: T('read', 'MD5 digest of files.', { tags: ['hash', 'integrity'] }),
  sha256sum: T('read', 'SHA-256 digest of files (component integrity).', { tags: ['hash', 'integrity', 'version'] }),
  sha1sum: T('read', 'SHA-1 digest of files.', { tags: ['hash'] }),
  strings: T('read', 'Print printable strings in a binary (version strings).', { tags: ['binary', 'version'] }),
  od: T('read', 'Dump file bytes.', { tags: ['hex', 'dump'] }),
  hexdump: T('read', 'Dump file bytes in hex.', { tags: ['hex', 'dump'] }),
  ldd: T('read', 'List shared libraries a binary links against.', { tags: ['libraries', 'dependencies', 'version'] }),
  printenv: T('read', 'Print the (runner-sanitized) environment.', { tags: ['environment'] }),
  sort: T('read', 'Sort lines of files. Output-file flags are rejected.', { argRules: { denyFlags: ['-o'], denyFlagPrefixes: ['--output'] } }),
  uniq: T('read', 'Filter repeated lines (single input only; an output file argument is rejected).', { argRules: { allowOnly: (a) => (a.filter((x) => !x.startsWith('-')).length > 1 ? 'uniq with an output file writes' : null) } }),
  cut: T('read', 'Select columns from lines.', {}),
  diff: T('read', 'Compare files.', { tags: ['compare', 'baseline'] }),
  cmp: T('read', 'Compare files byte by byte.', { tags: ['compare'] }),
  free: T('read', 'Memory usage (Linux stand-in).', { tags: ['memory'] }),
  lscpu: T('read', 'CPU information (Linux stand-in).', { tags: ['cpu', 'hardware'] }),
  lsof: T('read', 'Open files and sockets per process (Linux stand-in; QNX: pidin fds).', { tags: ['sockets', 'files', 'listeners'] }),
  dmesg: T('read', 'Kernel ring buffer (Linux stand-in; QNX: slog2info). Clearing is rejected.', { tags: ['log', 'kernel'], argRules: { denyFlags: ['-c', '-C', '--clear', '--read-clear', '-n', '--console-level'] } }),
  who: T('read', 'Logged-in users.', { tags: ['users', 'sessions'] }),
  w: T('read', 'Logged-in users and activity.', { tags: ['users', 'sessions'] }),
  last: T('read', 'Login history.', { tags: ['users', 'history'] }),

  // ---------------- network inspection (local) ----------------
  ifconfig: T('read', 'Show network interfaces, addresses and flags (io-sock on QNX 8). Only "-a", "-l" or a single interface name; reconfiguring is rejected.', {
    tags: ['network', 'interfaces', 'ip address', 'posture'],
    argRules: { allowOnly: (a) => { const pos = a.filter((x) => !x.startsWith('-')); const flags = a.filter((x) => x.startsWith('-')); if (pos.length > 1 || flags.some((f) => !['-a', '-l', '-u', '-d', '-v'].includes(f))) return 'ifconfig with configuration arguments is destructive'; return null; } },
  }),
  netstat: T('read', 'Sockets, listeners (netstat -an), routing table (netstat -rn), interface stats. On QNX 8 this is the io-sock (BSD) netstat.', {
    tags: ['network', 'listeners', 'ports', 'routes', 'sockets', 'posture', 'open ports'],
  }),
  ss: T('read', 'Socket statistics: listening ports (ss -lntu). Kill flag rejected.', { tags: ['network', 'listeners', 'ports'], argRules: { denyFlags: ['-K', '--kill'] } }),
  ip: T('read', 'Show addresses/routes/links (ip addr, ip route, ip link). Changes are rejected.', {
    tags: ['network', 'routes', 'interfaces'],
    argRules: { allowOnly: (a) => (a.some((x) => ['add', 'del', 'delete', 'set', 'flush', 'change', 'replace', 'append', 'exec', 'netns', '-batch', '-b', '-force'].includes(x)) ? 'ip with a modifying subcommand is destructive' : null) },
  }),
  route: T('read', 'Show/get routes (route show, route get, route -n). Changes are rejected.', {
    tags: ['network', 'routes'],
    argRules: { allowOnly: (a) => (a.some((x) => ['add', 'delete', 'del', 'change', 'flush'].includes(x)) ? 'route modifications are destructive' : null) },
  }),
  arp: T('read', 'Show the ARP table (arp -an). Changes rejected.', { tags: ['network', 'neighbors'], argRules: { denyFlags: ['-d', '-s', '-f', '-S'] } }),
  tcpdump: T('read', 'Passive packet capture on an interface (use -c to bound). Writing capture files is rejected. Sends no packets.', {
    tags: ['packets', 'capture', 'sniff', 'traffic', 'witness'], argRules: { denyFlags: ['-w', '-z', '-Z', '-C', '-G', '-W'] },
  }),

  // ---------------- network probes (send packets; scope-gated) ----------------
  ping: T('net', 'ICMP echo to a target. Use -c to bound the count.', { tags: ['reachability', 'icmp', 'host up', 'scan'], network: true }),
  ping6: T('net', 'ICMPv6 echo to a target.', { tags: ['reachability', 'icmp'], network: true }),
  traceroute: T('net', 'Trace the route to a target.', { tags: ['route', 'path', 'hops'], network: true }),
  nc: T('net', 'TCP/UDP connect probe (e.g. nc -z -w 2 host port). Listen and exec modes are rejected.', {
    tags: ['port', 'connect', 'scan', 'tcp', 'banner'], network: true, argRules: { denyFlags: ['-l', '-e', '-c', '-k', '--exec', '--sh-exec', '--lua-exec', '-L'] },
  }),
  nmap: T('net', 'Port scanner (TCP connect / service detection). Script engine and output files are rejected.', {
    tags: ['scan', 'ports', 'services', 'discovery'], network: true, argRules: { denyFlagPrefixes: ['--script', '-sC', '-oN', '-oX', '-oG', '-oA', '-oS', '--resume', '--datadir', '-iL'] },
  }),
  curl: T('net', 'HTTP(S) GET of a URL. Uploads, request bodies, method overrides, config files and output files are rejected.', {
    tags: ['http', 'web', 'url', 'fetch', 'banner'], network: true,
    argRules: { denyFlags: ['-o', '-O', '-T', '-d', '-F', '-K', '-X', '-u', '--next', '-:'], denyFlagPrefixes: ['--output', '--remote-name', '--upload', '--data', '--form', '--config', '--request', '--json', '--create-dirs', '--cookie-jar', '-c', '--user'] },
  }),
  nslookup: T('net', 'DNS lookup (queries a resolver).', { tags: ['dns', 'resolve'], network: true }),
  host: T('net', 'DNS lookup.', { tags: ['dns'], network: true }),
  dig: T('net', 'DNS lookup.', { tags: ['dns'], network: true }),

  // ---------------- destructive (named so search can explain why they are off) ----------------
  slay: T('destructive', 'QNX: kill or signal processes by name.', { qnx: true, tags: ['kill', 'signal', 'process'] }),
  kill: T('destructive', 'Send a signal to a process.', { tags: ['kill', 'signal'] }),
  on: T('destructive', 'QNX: run a command on another node, CPU or with another priority (on -n node cmd).', { qnx: true, tags: ['remote', 'qnet', 'priority'] }),
  shutdown: T('destructive', 'QNX: shut down or reboot the system.', { qnx: true, tags: ['reboot', 'power'] }),
  mkifs: T('destructive', 'QNX: build an OS image filesystem.', { qnx: true, tags: ['image', 'build'] }),
  mkqnx6fs: T('destructive', 'QNX: format a Power-Safe (qnx6) filesystem.', { qnx: true, tags: ['format', 'disk'] }),
  umount: T('destructive', 'Unmount a filesystem.', { tags: ['mount'] }),
  rm: T('destructive', 'Remove files.', { tags: ['delete'] }),
  rmdir: T('destructive', 'Remove directories.', {}),
  mv: T('destructive', 'Move/rename files.', {}),
  cp: T('destructive', 'Copy files (writes).', {}),
  ln: T('destructive', 'Create links (writes).', {}),
  mkdir: T('destructive', 'Create directories.', {}),
  touch: T('destructive', 'Create/modify file timestamps.', {}),
  chmod: T('destructive', 'Change permissions.', { tags: ['permissions'] }),
  chown: T('destructive', 'Change ownership.', {}),
  dd: T('destructive', 'Raw block copy.', {}),
  sh: T('destructive', 'Shell — arbitrary execution.', { tags: ['shell'] }),
  ksh: T('destructive', 'Korn shell — arbitrary execution.', { tags: ['shell'] }),
  bash: T('destructive', 'Shell — arbitrary execution.', { tags: ['shell'] }),
  env: T('destructive', 'Runs arbitrary commands.', {}),
  xargs: T('destructive', 'Runs arbitrary commands.', {}),
  awk: T('destructive', 'Interpreter with system() — arbitrary execution.', {}),
  sed: T('destructive', 'Stream editor; -i and w commands write files.', {}),
  tee: T('destructive', 'Writes files.', {}),
  ssh: T('destructive', 'Remote execution.', { network: true }),
  telnet: T('destructive', 'Interactive remote session.', { network: true }),
  'io-sock': T('destructive', 'QNX 8 network stack manager (starting another instance reconfigures networking).', { qnx: true }),
  reboot: T('destructive', 'Reboot.', {}),
  halt: T('destructive', 'Halt.', {}),
  python3: T('destructive', 'Interpreter — arbitrary execution.', {}),
  perl: T('destructive', 'Interpreter — arbitrary execution.', {}),
  node: T('destructive', 'Interpreter — arbitrary execution.', {}),
};

// Prefix families (QNX drivers & managers): starting one changes the system.
const PREFIX_FAMILIES = [
  ['devb-', 'QNX block-device driver (starting one attaches disks).'],
  ['devc-', 'QNX character-device driver (serial/console).'],
  ['devnp-', 'QNX network driver.'],
  ['devu-', 'QNX USB driver.'],
  ['io-', 'QNX resource manager / stack.'],
  ['fs-', 'QNX filesystem manager.'],
];

function lookup(name) {
  if (Object.prototype.hasOwnProperty.call(KNOWLEDGE, name)) return KNOWLEDGE[name];
  for (const [p, d] of PREFIX_FAMILIES) if (name.startsWith(p)) return T('destructive', d, { qnx: true, tags: ['driver', 'resource manager'] });
  return null;
}

// Tools that send packets; every non-flag argument is a target candidate.
const NETWORK_TOOLS = new Set(Object.entries(KNOWLEDGE).filter(([, v]) => v.network).map(([k]) => k)
  .concat(['traceroute6', 'netcat', 'ncat', 'wget', 'arping', 'fping', 'ftp', 'tftp', 'tracepath']));

module.exports = { KNOWLEDGE, lookup, NETWORK_TOOLS };
