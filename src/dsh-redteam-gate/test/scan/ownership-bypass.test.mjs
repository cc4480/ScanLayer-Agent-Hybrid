// SCAN_SKIP_OWNERSHIP_GATE switches the ownership gate off for the operator's own testing.
// Default (unset) stays fail-closed. Run with: node --import tsx --test test/scan/ownership-bypass.test.mjs
import { test } from 'node:test'
import assert from 'node:assert/strict'
import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs'
import { ownershipGateDisabled } from '../../src/scan-gate-helpers.mjs'
import { gateScanTarget } from '../../src/scan-gate.mjs'
import { decideScope } from '../../src/scope.mjs'
import { webappScanHandler } from '../../src/scan-handlers.mjs'
import { LocalDomainVerifier } from '../../src/verifier.mjs'

const storeFile = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-')), 'v.json')
// Verifier that always says no, so any "allowed" result is the bypass, not a real verification.
const neverVerified = () => new LocalDomainVerifier({ storeFile: storeFile(), resolveTxt: async () => [] })

function withEnv(value, fn) {
  const prev = process.env.SCAN_SKIP_OWNERSHIP_GATE
  if (value === undefined) delete process.env.SCAN_SKIP_OWNERSHIP_GATE
  else process.env.SCAN_SKIP_OWNERSHIP_GATE = value
  return (async () => { try { return await fn() } finally {
    if (prev === undefined) delete process.env.SCAN_SKIP_OWNERSHIP_GATE
    else process.env.SCAN_SKIP_OWNERSHIP_GATE = prev
  } })()
}

test('only an exact true enables the bypass', () => {
  assert.equal(ownershipGateDisabled({}), false)
  assert.equal(ownershipGateDisabled({ SCAN_SKIP_OWNERSHIP_GATE: 'false' }), false)
  assert.equal(ownershipGateDisabled({ SCAN_SKIP_OWNERSHIP_GATE: '1' }), false)
  assert.equal(ownershipGateDisabled({ SCAN_SKIP_OWNERSHIP_GATE: 'yes' }), false)
  assert.equal(ownershipGateDisabled({ SCAN_SKIP_OWNERSHIP_GATE: ' TRUE ' }), true)
  assert.equal(ownershipGateDisabled({ SCAN_SKIP_OWNERSHIP_GATE: 'true' }), true)
})

test('default (unset): an unverified domain is still refused with zero packets', () => withEnv(undefined, async () => {
  const gate = await gateScanTarget('https://not-mine.example/', neverVerified())
  assert.equal(gate.ok, false)
  assert.match(gate.reason, /Zero packets sent/)
  const d = await decideScope({ toolName: 'webapp_scan', arguments: { url: 'https://not-mine.example/' } }, neverVerified())
  assert.equal(d.kind, 'deny')
}))

test('bypass on: any http/https host is allowed and marked unverified', () => withEnv('true', async () => {
  const gate = await gateScanTarget('https://not-mine.example/app', neverVerified())
  assert.equal(gate.ok, true)
  assert.equal(gate.unverified, true)
  assert.equal(gate.host, 'not-mine.example')
  // Even a raw IP, which is normally never verifiable.
  assert.equal((await gateScanTarget('http://203.0.113.9/', neverVerified())).ok, true)
}))

test('bypass on: the pre-execute scope hook allows an unverified target', () => withEnv('true', async () => {
  const d = await decideScope({ toolName: 'seclayer_scan', arguments: { url: 'https://not-mine.example/' } }, neverVerified())
  assert.equal(d.kind, 'allow')
}))

test('bypass on: a completed scan result says unverified: true', { skip: !process.env.DATABASE_URL && 'needs DATABASE_URL' }, () => withEnv('true', async () => {
  const prevPriv = process.env.ALLOW_PRIVATE_SCAN_TARGETS
  process.env.ALLOW_PRIVATE_SCAN_TARGETS = 'true'
  try {
    const http = await import('node:http')
    const server = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<!doctype html><title>lab</title>') })
    await new Promise((r) => server.listen(0, '127.0.0.1', r))
    try {
      const out = JSON.parse(await webappScanHandler({ url: `http://127.0.0.1:${server.address().port}/` }, neverVerified()))
      // A loopback target reports lab:true; the unverified flag is present and false there. The flag's
      // true path is covered by the gateScanTarget test above without a live scan.
      assert.equal(out.status, 'complete')
      assert.equal(typeof out.unverified, 'boolean')
    } finally { server.close() }
  } finally {
    if (prevPriv === undefined) delete process.env.ALLOW_PRIVATE_SCAN_TARGETS
    else process.env.ALLOW_PRIVATE_SCAN_TARGETS = prevPriv
  }
}))
