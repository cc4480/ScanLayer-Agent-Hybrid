'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const scope = require('../gateway/lib/scope');
const { Audit, verifyChain } = require('../gateway/lib/audit');
const { argRuleViolation } = require('../gateway/lib/gate');
const { Catalog } = require('../gateway/lib/catalog');

const CAT = {
  meta: { hostname: 'qnxtarget', os: 'QNX', release: '8.0.0' },
  network: { interface_ips: ['10.0.2.15', '127.0.0.1'] },
  tools: [
    { name: 'pidin', path: '/proc/boot/pidin' }, { name: 'ping', path: '/usr/bin/ping' }, { name: 'slay', path: '/proc/boot/slay' },
    { name: 'netstat', path: '/usr/bin/netstat' }, { name: 'find', path: '/usr/bin/find' }, { name: 'nc', path: '/usr/bin/nc' },
    { name: 'devb-eide', path: '/proc/boot/devb-eide' }, { name: 'mystery-bin', path: '/usr/bin/mystery-bin' }, { name: 'pci-tool', path: '/usr/sbin/pci-tool' },
    { name: 'sysctl', path: '/sbin/sysctl' }, { name: 'ifconfig', path: '/sbin/ifconfig' }, { name: 'curl', path: '/usr/bin/curl' },
  ],
};
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'qa-'));

function engagementsWith(targets, { key = 'k'.repeat(64), expires = Date.now() + 3600e3, tamper = false } = {}) {
  const d = tmp();
  const e = { id: 'eng1', targets, operator: 'test', issued_at: new Date().toISOString(), expires_at: new Date(expires).toISOString() };
  e.sig = scope.signEngagement(e, key);
  if (tamper) e.targets = [...targets, '0.0.0.0/0'];
  fs.writeFileSync(path.join(d, 'e.json'), JSON.stringify({ engagements: [e] }));
  return scope.loadEngagements(path.join(d, 'e.json'), key);
}
const NONE = { engagements: [] };

test('target extraction: IPv4, CIDR, URL host, host:port, user@host, Qnet', () => {
  const t = (tool, args) => scope.extractTargets(tool, args).targets.map((x) => `${x.kind}:${x.value}`);
  assert.deepEqual(t('ping', ['-c', '1', '192.0.2.7']), ['ipv4:192.0.2.7']);
  assert.deepEqual(t('nmap', ['-p', '1-1024', '198.51.100.0/24']), ['cidr:198.51.100.0/24']);
  assert.deepEqual(t('curl', ['-s', 'http://evil.example.com:8080/x']), ['host:evil.example.com']);
  assert.deepEqual(t('nc', ['-z', '-w', '2', 'admin@203.0.113.5', '22']), ['ipv4:203.0.113.5']);
  assert.deepEqual(t('ls', ['/net/ecu2/dev/']), ['qnet:ecu2']);
  assert.deepEqual(t('on', ['-n', 'ECU3', 'pidin']), ['qnet:ecu3']);
  assert.deepEqual(t('grep', ['x', '/var/log/messages']), []);
  assert.deepEqual(t('grep', ['10.1.2.3', '/var/log/messages']), ['ipv4:10.1.2.3']); // IPs extracted from every tool
});

test('network tools fail closed on unparseable arguments', () => {
  const r = scope.check('curl', ['-H', 'X-Evil: 1', 'http://127.0.0.1/'], CAT, NONE);
  assert.equal(r.allowed, false);
  assert.match(r.reason, /not a recognizable target/);
});

test('self is always in scope; everything else needs an engagement', () => {
  for (const a of [['127.0.0.1'], ['localhost'], ['10.0.2.15'], ['qnxtarget'], ['::1'], ['127.9.9.9']]) assert.equal(scope.check('ping', ['-c', '1', ...a], CAT, NONE).allowed, true, a[0]);
  assert.equal(scope.check('ping', ['-c', '1', '10.0.2.2'], CAT, NONE).allowed, false);
  assert.equal(scope.check('ls', ['/net/ecu2/dev'], CAT, NONE).allowed, false);
});

test('engagements: exact IP, CIDR membership, exact-CIDR rule, hostnames, qnet', () => {
  const e = engagementsWith(['10.0.2.0/24', '198.51.100.7', 'plc.lab', 'qnet:ecu2']);
  assert.equal(e.engagements.length, 1);
  assert.equal(scope.check('ping', ['10.0.2.99'], CAT, e).allowed, true);
  assert.equal(scope.check('ping', ['198.51.100.7'], CAT, e).allowed, true);
  assert.equal(scope.check('ping', ['198.51.100.8'], CAT, e).allowed, false);
  assert.equal(scope.check('nmap', ['10.0.2.0/24'], CAT, e).allowed, true);
  assert.equal(scope.check('nmap', ['10.0.2.0/25'], CAT, e).allowed, false, 'a narrower CIDR is not the named CIDR');
  assert.equal(scope.check('nmap', ['10.0.0.0/16'], CAT, e).allowed, false, 'a wider CIDR is never implied');
  assert.equal(scope.check('curl', ['http://plc.lab/status'], CAT, e).allowed, true);
  assert.equal(scope.check('curl', ['http://plc.lab.evil.com/'], CAT, e).allowed, false);
  assert.equal(scope.check('ls', ['/net/ecu2/proc'], CAT, e).allowed, true);
});

test('engagements fail closed: tampered, expired, missing key, broken file', () => {
  assert.equal(engagementsWith(['10.0.0.0/8'], { tamper: true }).engagements.length, 0);
  assert.equal(engagementsWith(['10.0.0.0/8'], { expires: Date.now() - 1 }).engagements.length, 0);
  const d = tmp();
  fs.writeFileSync(path.join(d, 'bad.json'), '{not json');
  const b = scope.loadEngagements(path.join(d, 'bad.json'), 'k');
  assert.equal(b.engagements.length, 0);
  assert.match(b.error, /unreadable/);
  assert.equal(scope.loadEngagements(path.join(d, 'missing.json'), 'k').engagements.length, 0);
  fs.writeFileSync(path.join(d, 'nokey.json'), JSON.stringify({ engagements: [{ id: 'x', targets: ['1.2.3.4'], sig: 'aa' }] }));
  assert.equal(scope.loadEngagements(path.join(d, 'nokey.json'), null).engagements.length, 0);
});

test('catalog: unknown tools and driver families are destructive and not callable', () => {
  const c = new Catalog(CAT);
  const by = (n) => c.byName.get(n);
  assert.equal(by('pidin').cls, 'read');
  assert.equal(by('ping').cls, 'net');
  assert.equal(by('slay').cls, 'destructive');
  assert.equal(by('devb-eide').cls, 'destructive');
  assert.equal(by('mystery-bin').cls, 'destructive');
  assert.equal(c.visible(by('mystery-bin')), false);
  assert.equal(by('pci-tool').ident, 'pci_tool');
  assert.equal(new Catalog(CAT, { allowDestructive: true }).visible(by('slay')), true);
  const s = c.search({ query: 'kill a process' });
  const slay = s.matches.find((m) => m.name === 'slay');
  assert.ok(slay && slay.callable === false && /destructive/.test(slay.why_not));
  assert.equal(c.search({ query: 'open ports listening' }).matches[0].name, 'netstat');
  assert.equal(c.search({ query: 'process threads' }).matches[0].name, 'pidin');
});

test('argument rules: exact flags, prefixes, short-flag clusters, writes', () => {
  const c = new Catalog(CAT);
  const v = (n, a) => argRuleViolation(c.byName.get(n), a);
  assert.match(v('find', ['/', '-name', 'x', '-delete']), /-delete/);
  assert.match(v('find', ['/', '-exec', 'rm', '{}', ';']), /-exec/);
  assert.equal(v('find', ['/', '-perm', '-0002', '-type', 'f']), null);
  assert.match(v('nc', ['-lvp', '4444']), /cluster/);
  assert.match(v('curl', ['--data-binary', '@/etc/passwd', 'http://127.0.0.1']), /--data/);
  assert.match(v('curl', ['-o', '/etc/x', 'http://127.0.0.1']), /-o/);
  assert.match(v('sysctl', ['net.inet.ip.forwarding=1']), /writes/);
  assert.equal(v('sysctl', ['net.inet.ip.forwarding']), null);
  assert.match(v('ifconfig', ['vtnet0', 'down']), /destructive/);
  assert.equal(v('ifconfig', ['-a']), null);
  assert.match(v('pci-tool', ['-w', '0x10']), /not allowed/);
});

test('audit chain: verifies, detects a one-byte tamper, refuses to extend a broken chain', () => {
  const d = tmp();
  const f = path.join(d, 'audit.log');
  const a = new Audit(f);
  for (let i = 0; i < 5; i++) a.append({ kind: 'call', tool: 'pidin', i });
  assert.deepEqual(verifyChain(f).ok, true);
  assert.equal(verifyChain(f).count, 5);
  const lines = fs.readFileSync(f, 'utf8').split('\n');
  lines[2] = lines[2].replace('"i":2', '"i":7');
  fs.writeFileSync(f, lines.join('\n'));
  const v = verifyChain(f);
  assert.equal(v.ok, false);
  assert.equal(v.bad_line, 3);
  assert.throws(() => new Audit(f), /refusing to start/);
  // deleting a line is caught too
  const d2 = tmp(); const f2 = path.join(d2, 'audit.log'); const a2 = new Audit(f2);
  for (let i = 0; i < 4; i++) a2.append({ kind: 'x', i });
  const l2 = fs.readFileSync(f2, 'utf8').split('\n'); l2.splice(1, 1); fs.writeFileSync(f2, l2.join('\n'));
  assert.equal(verifyChain(f2).ok, false);
});

test('child processes: empty env on POSIX; on Windows only what the OS needs (Winsock needs SystemRoot), never secrets', () => {
  const { childEnv } = require('../gateway/lib/child-env');
  const host = { SystemRoot: 'C:\\Windows', windir: 'C:\\Windows', TEMP: 'C:\\T', DEEPSEEK_API_KEY: 'sk-secret', PATH: 'C:\\bin', USERPROFILE: 'C:\\Users\\x' };
  assert.deepEqual(childEnv('linux', host), {});
  assert.deepEqual(childEnv('darwin', host), {});
  assert.deepEqual(childEnv('win32', host), { SystemRoot: 'C:\\Windows', windir: 'C:\\Windows', TEMP: 'C:\\T' });
});
