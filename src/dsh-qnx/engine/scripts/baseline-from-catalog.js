#!/usr/bin/env node
'use strict';
// Write an image manifest from a CLEAN target's own inventory, the way the stand-in baseline does for Linux. On QNX
// this replaces the draft image/manifest.json with what the booted image actually runs and listens on.
//   node scripts/baseline-from-catalog.js <catalog.json> <out manifest.json> [cksums.txt]
// cksums.txt: `cksum <files>` output taken on the target (phase0.sh collects it over ssh); each line pins one component.
const fs = require('fs');
const [catFile, outFile, cksumFile] = process.argv.slice(2);
if (!catFile || !outFile) { console.error('usage: baseline-from-catalog.js <catalog.json> <out.json> [cksums.txt]'); process.exit(64); }
const cat = JSON.parse(fs.readFileSync(catFile, 'utf8'));
const net = cat.network || {};

const services = (net.listeners || []).map((l) => ({ proto: l.proto, port: l.port, name: `baseline:${l.addr}` }));
if (!services.some((s) => s.proto === 'tcp' && s.port === 7781)) services.push({ proto: 'tcp', port: 7781, name: 'qnx-runner' });
for (const s of services) if (s.port === 7781) s.required = true;

const components = [];
if (cksumFile && fs.existsSync(cksumFile)) {
  for (const line of fs.readFileSync(cksumFile, 'utf8').split('\n')) {
    const m = /^(\d+)\s+(\d+)\s+(\S+)\s*$/.exec(line.trim());
    if (m) components.push({ name: m[3].split('/').pop(), path: m[3], cksum: m[1], size: Number(m[2]) });
  }
}

const manifest = {
  schema: 'qnx-agent.manifest.v1',
  _comment: `Baseline of the clean ${cat.meta.os} ${cat.meta.release} image "${cat.meta.hostname}", written by scripts/baseline-from-catalog.js from the target's own inventory.`,
  generated_at: new Date().toISOString(),
  os_release: cat.meta.release,
  services,
  processes: [...new Set((cat.processes || []).map((p) => p.name))].sort(),
  required_processes: ['qnx-runner'],
  components,
  boot_image_allow: ['*'],
  network: { interfaces: net.interfaces || [], forwarding: false, default_route: true },
  writable_allow: ['/tmp', '/tmp/*', '/data/*', '/dev/shmem', '/dev/shmem/*', '/var/run', '/var/log/*'],
  dev_world_writable_allow: ['/dev/null', '/dev/zero', '/dev/tty', '/dev/random', '/dev/urandom', '/dev/ptmx', '/dev/ptyp*', '/dev/ttyp*', '/dev/shmem', '/dev/socket', '/dev/name', '/dev/mqueue', '/dev/console'],
};
fs.writeFileSync(outFile, JSON.stringify(manifest, null, 2));
console.log(`manifest: ${services.length} services, ${manifest.processes.length} processes, ${components.length} pinned components, interfaces ${manifest.network.interfaces.join(',')}`);
