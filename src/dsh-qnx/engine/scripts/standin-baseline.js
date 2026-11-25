#!/usr/bin/env node
'use strict';
// Operator tool (not an agent tool): write the stand-in target's "image
// manifest" from a clean baseline, the way a real QNX manifest is written from
// the image's buildfile. Run it BEFORE planting faults; whatever appears after
// is drift the checks must find.
//   node scripts/standin-baseline.js standin/state/catalog.json standin/manifest.json
const fs = require('fs');
const { execFileSync } = require('child_process');
const [catFile, outFile] = process.argv.slice(2);
if (fs.existsSync('/opt/qnx-agent-demo')) { console.error('demo faults are planted: run scripts/plant-standin-faults.sh --clear first (a baseline must be clean)'); process.exit(1); }
const cat = JSON.parse(fs.readFileSync(catFile, 'utf8'));
const sh = (cmd, args) => { try { return execFileSync(cmd, args, { encoding: 'utf8' }); } catch (e) { return e.stdout || ''; } };

const listeners = cat.network.listeners || [];
const services = listeners.map((l) => ({ proto: l.proto, port: l.port, name: `baseline:${l.addr}` }));
services.push({ proto: 'tcp', port: 7781, name: 'qnx-runner', required: true }, { proto: 'tcp', port: 8095, name: 'qnx-agent engine (loopback MCP)' }, { proto: 'tcp', port: 3080, name: 'DeepSeek Harness web' });
const procNames = [...new Set((cat.processes || []).map((p) => p.name))];
const kthreads = ['kworker/*', 'ksoftirqd/*', 'migration/*', 'cpuhp/*', 'rcu_*', 'kthreadd', 'idle_inject/*', 'irq/*', 'scsi_*', 'jbd2/*', 'ext4-*', 'kswapd*', 'watchdog*', 'pool_workqueue_*', 'oom_reaper', 'khungtaskd', 'kcompactd*', 'kdevtmpfs', 'writeback', 'kblockd', 'kintegrityd', 'blkcg_punt_bio', 'ata_sff', 'md', 'edac-poller', 'devfreq_wq', 'kthrotld', 'xenbus*', 'kaluad', 'kmpath_rdacd', 'ipv6_addrconf', 'mld', 'netns', 'inet_frag_wq', 'tpm_dev_wq', 'zswap-shrink', 'khugepaged', 'ksmd', 'card*-crtc*', 'hwrng', 'rcu*', 'kauditd', 'psimon', 'kstrp', 'charger_manager', 'mm_percpu_wq', 'ksoftirqd'];
// The agent's own stack and this session's tooling are part of the "image".
const ours = ['qnx-runner', 'node', 'MainThread', 'sh', 'bash', 'dash', 'ps', 'sleep', 'unshare', 'tcpdump', 'python3', 'timeout', 'cat', 'tail', 'claude', 'npm', 'environment-man', 'process_api', 'make', 'curl'];
// A demo "image component" the stand-in ships (the fault script tampers with it to show drift detection).
const NAVD = '/usr/local/lib/qnx-agent-image/navd';
fs.mkdirSync(require('path').dirname(NAVD), { recursive: true });
fs.writeFileSync(NAVD, 'navd 1.4.2 build 2026-11-20\n', { mode: 0o755 });
const runnerBin = require('path').resolve(__dirname, '../node-runtime/qnx-runner');
const components = ['/bin/uname', '/bin/ls', '/usr/bin/netstat', '/usr/bin/find', '/usr/bin/ps', runnerBin, NAVD].filter((p) => fs.existsSync(p)).map((p) => {
  const [crc, size] = sh('cksum', [p]).trim().split(/\s+/);
  return { name: p.split('/').pop(), path: p, cksum: crc, size: Number(size) };
});
const ifaces = [...sh('ifconfig', ['-a']).matchAll(/^(\S+): flags=\w+<([^>]*)>/gm)].filter((m) => m[2].split(',').includes('UP')).map((m) => m[1]);
const fwd = (/=\s*(\d)/.exec(sh('sysctl', ['net.ipv4.ip_forward'])) || [])[1];

const manifest = {
  schema: 'qnx-agent.manifest.v1',
  _comment: 'Stand-in baseline written by scripts/standin-baseline.js from a clean target. On QNX this file comes from the image buildfile (image/manifest.json).',
  generated_at: new Date().toISOString(),
  os_release: cat.meta.release,
  services,
  processes: [...new Set([...procNames, ...kthreads, ...ours])].sort(),
  required_processes: ['qnx-runner'],
  components,
  network: { interfaces: ifaces, forwarding: fwd === '1', default_route: true },
  writable_allow: ['/tmp', '/var/tmp', '/dev/shm', '/var/lock', '/run/lock', '/tmp/*', '/var/tmp/*', '/var/crash', '/var/metrics', '/root/.claude*', '/root/.cache*', '/home/*/.cache*'],
};
fs.writeFileSync(outFile, JSON.stringify(manifest, null, 2));
console.log(`manifest: ${services.length} services, ${manifest.processes.length} process patterns, ${manifest.components.length} components, interfaces ${ifaces.join(',')}, forwarding ${fwd}`);
