import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { decideScope } from '../../src/scope.mjs'
import {
  buildCommands, parseCommandLine, targetsForMsf, decideMsfScope, parseOutput, runMsf, MSF_RUBY,
} from '../../src/engines/metasploit/msf.mjs'

const never = { isVerified: async () => false }
const neverCalled = { isVerified: async () => { throw new Error('gate must not be consulted for this case') } }

const portscan = (rhosts) => ({
  module: 'auxiliary/scanner/portscan/tcp',
  options: { RHOSTS: rhosts, PORTS: '1-100', THREADS: 10 },
})

test('buildCommands produces the whitelisted resource lines in order', () => {
  assert.deepEqual(buildCommands(portscan('127.0.0.1')), [
    'use auxiliary/scanner/portscan/tcp',
    'set RHOSTS 127.0.0.1',
    'set PORTS 1-100',
    'set THREADS 10',
    'run',
    'sessions -l',
    'exit -y',
  ])
})

test('post, payload and non-scanner auxiliary modules are still refused', () => {
  for (const module of ['post/multi/manage/shell_to_meterpreter', 'payload/windows/x64/meterpreter/reverse_tcp', 'auxiliary/admin/smb/psexec_command']) {
    assert.throws(() => buildCommands({ module, options: { RHOSTS: '127.0.0.1' } }), /outside the allowed scope|invalid module/, module)
  }
})

test('exploit modules build against a loopback lab target', () => {
  const lines = buildCommands({ module: 'exploit/windows/smb/ms17_010_eternalblue', options: { RHOST: '127.0.0.1', PAYLOAD: 'windows/x64/meterpreter/reverse_tcp' } })
  assert.equal(lines[0], 'use exploit/windows/smb/ms17_010_eternalblue')
  assert.ok(lines.includes('set RHOST 127.0.0.1'))
})

test('an exploit against a non-lab host is denied by the scope gate before anything runs', async () => {
  const r = await decideMsfScope({ module: 'exploit/windows/smb/ms17_010_eternalblue', options: { RHOST: '192.168.1.50' } }, never)
  assert.equal(r.kind, 'deny')
})

test('malformed module names are refused', () => {
  for (const module of ['auxiliary/scanner/portscan/tcp; sh', 'auxiliary/scanner/x y', '../../etc', '', undefined]) {
    assert.throws(() => buildCommands({ module, options: {} }), /invalid module|outside/, String(module))
  }
})

test('option names and values with shell, ERB, Ruby or resource metacharacters are refused', () => {
  const badValues = ['127.0.0.1; exec calc', '127.0.0.1 && whoami', '<%= `id` %>', '#{system("x")}', '127.0.0.1\nrun', '$(id)', 'a|b', "x'y", '127.0.0.1`id`']
  for (const v of badValues) {
    assert.throws(() => buildCommands({ module: 'auxiliary/scanner/portscan/tcp', options: { PORTS: v } }), /invalid value/, JSON.stringify(v))
  }
  for (const name of ['RHOSTS;run', 'rhosts x', '1ABC', 'RHOST\nrun']) {
    assert.throws(() => buildCommands({ module: 'auxiliary/scanner/portscan/tcp', options: { [name]: '1' } }), /invalid option name|invalid value/, name)
  }
})

test('host option values must be single hosts: CIDR, ranges and file: are refused', () => {
  for (const v of ['127.0.0.0/8', '127.0.0.1-5', 'file:/tmp/hosts.txt', '127.0.0.1-200.1', '10.0.0.1/32', 'http://127.0.0.1/']) {
    assert.throws(() => buildCommands(portscan(v)), /invalid value|not a single host/, v)
  }
})

test('targetsForMsf extracts every RHOST/RHOSTS value from set and setg', () => {
  assert.deepEqual(targetsForMsf(buildCommands(portscan('127.0.0.1'))), ['127.0.0.1'])
  assert.deepEqual(
    targetsForMsf(['use auxiliary/scanner/portscan/tcp', 'setg RHOST localhost', 'set RHOSTS ::1,127.0.0.1', 'run', 'exit -y']),
    ['localhost', '::1', '127.0.0.1'],
  )
})

test('targetsForMsf returns nothing when no host option is set', () => {
  assert.deepEqual(targetsForMsf(['use auxiliary/scanner/portscan/tcp', 'set PORTS 1-100', 'run', 'exit -y']), [])
})

test('targetsForMsf throws on any line outside the whitelist', () => {
  for (const line of ['db_nmap 10.0.0.5', 'irb', 'shell', 'resource /tmp/x.rc', 'spool /tmp/x', 'sessions -K', 'sessions -i 1', 'exit', 'run -j']) {
    assert.throws(() => targetsForMsf(['use auxiliary/scanner/portscan/tcp', line]), /whitelist|only|malformed/, line)
  }
})

test('parseCommandLine accepts the whitelist and rejects extras', () => {
  assert.deepEqual(parseCommandLine('sessions -l'), { verb: 'sessions' })
  assert.deepEqual(parseCommandLine('exit -y'), { verb: 'exit' })
  assert.throws(() => parseCommandLine('unset'), /malformed/)
})

test('loopback scanner request is allowed by the gate', async () => {
  const r = await decideMsfScope(portscan('127.0.0.1'), never)
  assert.equal(r.kind, 'allow')
  assert.deepEqual(r.targets, ['127.0.0.1'])
})

test('non-lab IP is denied by decideScope', async () => {
  const r = await decideMsfScope(portscan('192.168.1.50'), neverCalled)
  assert.equal(r.kind, 'deny')
  assert.match(r.reason, /192\.168\.1\.50/)
})

test('non-lab IP is denied by decideScope when fed directly (msfconsole tool name)', async () => {
  const r = await decideScope({ toolName: 'msfconsole', arguments: { targets: ['10.0.0.5'] } }, never)
  assert.equal(r.kind, 'deny')
})

test('unverified domain in RHOSTS is denied', async () => {
  const r = await decideMsfScope(portscan('victim.example.org'), never)
  assert.equal(r.kind, 'deny')
  assert.match(r.reason, /victim\.example\.org/)
})

test('a mixed host list with one non-lab host is denied', async () => {
  const r = await decideMsfScope(portscan('127.0.0.1,10.0.0.5'), never)
  assert.equal(r.kind, 'deny')
})

test('a run with no target is denied', async () => {
  const r = await decideMsfScope({ module: 'auxiliary/scanner/portscan/tcp', options: { PORTS: '1-100' } }, neverCalled)
  assert.equal(r.kind, 'deny')
  assert.match(r.reason, /no target/)
})

test('a rejected spec is denied before the gate is consulted', async () => {
  const r = await decideMsfScope({ module: 'post/multi/manage/shell_to_meterpreter', options: { RHOSTS: '127.0.0.1' } }, neverCalled)
  assert.equal(r.kind, 'deny')
})

test('runMsf refuses to spawn when the gate denies, and requires a gate', async () => {
  const denied = await runMsf(portscan('192.168.1.50'), { gate: never })
  assert.equal(denied.status, 'denied')
  assert.equal(denied.stdout, undefined)
  await assert.rejects(() => runMsf(portscan('127.0.0.1'), {}), /requires a scope gate/)
})

test('parseOutput reads open ports, positives, errors and sessions', () => {
  const sample = [
    '\u001b[0m[*] 127.0.0.1:1-100 - Scanning',
    '[+] 127.0.0.1:80 - TCP OPEN',
    '[+] 127.0.0.1:22 - TCP OPEN',
    '[-] 127.0.0.1:99 - closed',
    '[!] 127.0.0.1: something odd',
    '[*] Command shell session 3 opened (127.0.0.1:4444 -> 127.0.0.1:50000) at 2026-11-21',
    '[*] Auxiliary module execution completed',
    'Active sessions',
    '  Id  Name  Type   Information     Connection',
    '  3           shell  x86/windows    127.0.0.1:4444',
  ].join('\n')
  const p = parseOutput(sample)
  assert.equal(p.completed, true)
  assert.deepEqual(p.openPorts, [
    { host: '127.0.0.1', port: 80, detail: 'TCP OPEN' },
    { host: '127.0.0.1', port: 22, detail: 'TCP OPEN' },
  ])
  assert.equal(p.errors.length, 2)
  assert.deepEqual(p.sessions.map((s) => s.id), [3])
  assert.equal(p.sessions[0].type, 'command shell')
})

test('parseOutput on empty output reports nothing found', () => {
  assert.deepEqual(parseOutput(''), { completed: false, openPorts: [], positives: [], errors: [], sessions: [] })
})

// Live: needs the Metasploit install msf.mjs launches (MSF_RUBY), like the other live tests need theirs.
test('live: portscan against 127.0.0.1 only through msfconsole', { skip: !existsSync(MSF_RUBY) && `Metasploit not installed at ${MSF_RUBY}` }, async () => {
  const r = await runMsf(portscan('127.0.0.1'), { gate: never, timeoutMs: 230000 })
  console.log('--- msfconsole exit:', r.exitCode, 'status:', r.status)
  console.log(r.stdout)
  assert.equal(r.status, 'ok', r.reason ?? r.stderr)
  assert.equal(r.parsed.completed, true)
  assert.deepEqual(targetsForMsf(r.commands), ['127.0.0.1'])
})
