import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { splitFlags, runTool } from '../src/runner.mjs'

const NMAP = 'C:\\Program Files (x86)\\Nmap\\nmap.exe'

test('splitFlags tokenizes plain options', () => {
  assert.deepEqual(splitFlags('-sV -p 80,443'), ['-sV', '-p', '80,443'])
  assert.deepEqual(splitFlags(''), [])
})

test('splitFlags refuses shell metacharacters', () => {
  assert.throws(() => splitFlags('-sV; rm -rf /'), /metacharacters/)
  assert.throws(() => splitFlags('$(whoami)'), /metacharacters/)
  assert.throws(() => splitFlags('a | b'), /metacharacters/)
})

test('a missing binary reports a spawn error instead of running anything', async () => {
  const r = await runTool('C:\\does\\not\\exist.exe', [])
  assert.ok(r.spawnError, 'expected a spawn error')
})

test('nmap scans loopback only and reports the open port', { skip: !existsSync(NMAP) }, async () => {
  const { createServer } = await import('node:net')
  // nmap's probe closes the socket abruptly; the test server must absorb that, not crash on it.
  const srv = createServer((sock) => sock.on('error', () => {})).listen(0, '127.0.0.1')
  await new Promise((res) => srv.once('listening', res))
  const port = srv.address().port
  try {
    // -sT: Windows cannot run the default SYN scan against localhost.
    const r = await runTool(NMAP, ['-Pn', '-sT', '-p', String(port), '-n', '127.0.0.1'], { timeoutMs: 60_000 })
    assert.equal(r.exitCode, 0)
    assert.match(r.stdout, new RegExp(`${port}/tcp\\s+open`))
  } finally {
    srv.close()
  }
})
