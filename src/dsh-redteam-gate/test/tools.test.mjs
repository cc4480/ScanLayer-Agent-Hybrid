import { test } from 'node:test'
import assert from 'node:assert/strict'
import path from 'node:path'
import { argvFor, nativeTools, sqlmapArgv, niktoLaunch, johnArgv, validateNiktoTarget, PERL_EXE, NIKTO_SCRIPT, CMD_EXE, BINARIES } from '../src/tools.mjs'
import { ACTIVE_TOOLS } from '../src/scope.mjs'

test('native tool names: scanners are gate-active, john is offline and not gated', () => {
  const names = nativeTools.map((t) => t.name).sort()
  assert.deepEqual(names, ['ffuf', 'gobuster', 'john', 'nikto', 'nmap', 'nuclei', 'sqlmap'])
  for (const n of ['ffuf', 'gobuster', 'nikto', 'nmap', 'nuclei', 'sqlmap']) assert.ok(ACTIVE_TOOLS.has(n), n)
  assert.equal(ACTIVE_TOOLS.has('john'), false)
})

test('sqlmap argv: URL target as one argument, --batch, checked flags', () => {
  assert.deepEqual(sqlmapArgv('http://127.0.0.1:8080/item?id=1&cat=2', '--level=2 --risk 1'), [
    '-u', 'http://127.0.0.1:8080/item?id=1&cat=2', '--batch', '--level=2', '--risk', '1',
  ])
  assert.deepEqual(sqlmapArgv('https://127.0.0.1/', ''), ['-u', 'https://127.0.0.1/', '--batch'])
})

test('sqlmap refuses shell metacharacters, non-URL targets, and command or file-write flags', () => {
  assert.throws(() => sqlmapArgv('http://127.0.0.1/ && calc', ''), /target must be/)
  assert.throws(() => sqlmapArgv('http://127.0.0.1/ | whoami', ''), /target must be/)
  assert.throws(() => sqlmapArgv('127.0.0.1', ''), /target must be/)
  assert.throws(() => sqlmapArgv('http://127.0.0.1/', '--dbs && calc'), /metacharacters/)
  assert.throws(() => sqlmapArgv('http://127.0.0.1/', '--os-shell'), /not allowed/)
  assert.throws(() => sqlmapArgv('http://127.0.0.1/', '--os-cmd=id'), /not allowed/)
  assert.throws(() => sqlmapArgv('http://127.0.0.1/', '--sql-shell'), /not allowed/)
  assert.throws(() => sqlmapArgv('http://127.0.0.1/', '--file-write local.txt'), /not allowed/)
  assert.throws(() => sqlmapArgv('http://127.0.0.1/', '--eval=import os'), /not allowed/)
})

test('sqlmap refuses flags that name extra targets or files of targets', () => {
  assert.throws(() => sqlmapArgv('http://127.0.0.1/', '--url=http://203.0.113.5/'), /URLs|not allowed/)
  assert.throws(() => sqlmapArgv('http://127.0.0.1/', '-m targets.txt'), /not allowed/)
  assert.throws(() => sqlmapArgv('http://127.0.0.1/', '-r req.txt'), /not allowed/)
  assert.throws(() => sqlmapArgv('http://127.0.0.1/', '--proxy=http://203.0.113.5:8080'), /URLs|not allowed/)
  assert.throws(() => sqlmapArgv('http://127.0.0.1/', '--sitemap-url https://example.com/sitemap.xml'), /URLs|not allowed/)
  assert.throws(() => sqlmapArgv('http://127.0.0.1/', '--proxy 203.0.113.5:8080'), /not allowed/)
})

test('nikto launch: perl runs the nikto2 script directly, with the target as one argument', () => {
  const { binary, argv } = niktoLaunch('http://127.0.0.1:8080/app/')
  assert.equal(binary, PERL_EXE)
  assert.deepEqual(argv, [NIKTO_SCRIPT, '-h', 'http://127.0.0.1:8080/app/', '-nointeractive'])
})

test('nikto accepts a bare host:port target', () => {
  assert.deepEqual(niktoLaunch('127.0.0.1:8080').argv, [NIKTO_SCRIPT, '-h', '127.0.0.1:8080', '-nointeractive'])
})

test('nikto refuses cmd.exe metacharacters and anything not a host or URL', () => {
  const bad = [
    'http://127.0.0.1 & calc',
    'http://127.0.0.1&calc',
    'http://127.0.0.1|calc',
    'http://127.0.0.1/%PATH%',
    'http://127.0.0.1/^x',
    'http://127.0.0.1/"x"',
    'http://127.0.0.1/!x!',
    'http://127.0.0.1;calc',
    'http://127.0.0.1>out',
    '-h',
    '--evil',
    'http://127.0.0.1/x y',
    'ftp://127.0.0.1/',
    '',
  ]
  for (const t of bad) assert.throws(() => validateNiktoTarget(t), /nikto target/, t)
})

test('argv keeps the target as one argument and splits flags safely', () => {
  assert.deepEqual(argvFor('nmap', '127.0.0.1', '-Pn -sT -p 80'), ['-Pn', '-sT', '-p', '80', '127.0.0.1'])
  assert.deepEqual(argvFor('nuclei', 'http://127.0.0.1:8080', '-severity high'), ['-u', 'http://127.0.0.1:8080', '-severity', 'high'])
  assert.deepEqual(argvFor('gobuster', 'http://127.0.0.1/', ''), ['dir', '-u', 'http://127.0.0.1/'])
})

test('a target with spaces or shell characters stays a single literal argument', () => {
  // The target is never split or shell-interpreted, so an injected operator is just text in one argv slot.
  const argv = argvFor('nmap', '127.0.0.1 && calc', '')
  assert.equal(argv.length, 1)
  assert.equal(argv[0], '127.0.0.1 && calc')
})

test('flags with shell operators are refused', () => {
  assert.throws(() => argvFor('nmap', '127.0.0.1', '-sT && calc'), /metacharacters/)
})

test('john argv: offline --show on a hash file inside the workspace only', () => {
  const ws = path.resolve('C:/work/ws')
  assert.deepEqual(johnArgv('hashes/md5.txt', undefined, ws), ['--show', path.join(ws, 'hashes', 'md5.txt')])
  assert.deepEqual(johnArgv('hashes.txt', 'raw-md5', ws), ['--show', '--format=raw-md5', path.join(ws, 'hashes.txt')])
})

test('john refuses paths outside the workspace and remote or shell-like input', () => {
  const ws = path.resolve('C:/work/ws')
  assert.throws(() => johnArgv('../secret.txt', undefined, ws), /inside the workspace/)
  assert.throws(() => johnArgv(path.resolve('C:/other/h.txt'), undefined, ws), /inside the workspace/)
  assert.throws(() => johnArgv('', undefined, ws), /disallowed|remote/)
  assert.throws(() => johnArgv('https://example.com/hashes.txt', undefined, ws), /remote/)
  assert.throws(() => johnArgv('\\\\server\\share\\h.txt', undefined, ws), /remote/)
  assert.throws(() => johnArgv('h.txt & calc', undefined, ws), /disallowed/)
  assert.throws(() => johnArgv('h.txt', '--wordlist=http://x', ws), /plain format name/)
  assert.throws(() => johnArgv('h.txt', 'raw-md5 --pipe', ws), /plain format name/)
})
