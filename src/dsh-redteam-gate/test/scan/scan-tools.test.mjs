// Tests for the scan agent tools. Run with: node --import tsx --test test/scan/scan-tools.test.mjs
import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { gateScanTarget } from '../../src/scan-gate.mjs'
import { webappScanHandler, seclayerScanHandler } from '../../src/scan-handlers.mjs'
import { decideScope } from '../../src/scope.mjs'

/** Verifier that records every lookup, so a test can prove the gate asked before anything ran. */
function fakeVerifier(verified = new Set()) {
  const calls = []
  return { calls, async isVerified(domain) { calls.push(domain); return verified.has(domain) } }
}

const HANDLERS = { webapp_scan: webappScanHandler, seclayer_scan: seclayerScanHandler }
const run = (name, args, verifier) => HANDLERS[name](args, verifier)

test('gate refuses an unverified domain and asks the verifier first', async () => {
  const v = fakeVerifier()
  const r = await gateScanTarget('https://not-mine.example', v)
  assert.equal(r.ok, false)
  assert.match(r.reason, /Zero packets sent/)
  assert.deepEqual(v.calls, ['not-mine.example'])
})

test('gate allows a verified domain', async () => {
  const r = await gateScanTarget('https://mine.example/app', fakeVerifier(new Set(['mine.example'])))
  assert.equal(r.ok, true)
  assert.equal(r.lab, false)
  assert.equal(r.host, 'mine.example')
})

test('gate refuses IP targets and non-http schemes', async () => {
  const v = fakeVerifier(new Set(['x.example']))
  assert.equal((await gateScanTarget('http://203.0.113.5/', v)).ok, false)
  assert.equal((await gateScanTarget('ftp://mine.example/', v)).ok, false)
  assert.deepEqual(v.calls, [], 'no DNS or verifier lookup for IP or scheme refusals')
})

test('gate allows loopback lab hosts without a verification record', async () => {
  const v = fakeVerifier()
  const r = await gateScanTarget('http://127.0.0.1:9999/', v)
  assert.equal(r.ok, true)
  assert.equal(r.lab, true)
  assert.deepEqual(v.calls, [])
})

test('webapp_scan returns refused and does not run the engine for an unverified site', async () => {
  const v = fakeVerifier()
  const out = JSON.parse(await run('webapp_scan', { url: 'https://not-mine.example' }, v))
  assert.equal(out.status, 'refused')
  assert.match(out.reason, /not ownership-verified/)
})

test('seclayer_scan returns refused for an unverified site', async () => {
  const out = JSON.parse(await run('seclayer_scan', { url: 'https://not-mine.example' }, fakeVerifier()))
  assert.equal(out.status, 'refused')
})

test('scope pre-execute hook denies an unverified target for the new tools', async () => {
  const v = fakeVerifier()
  for (const toolName of ['webapp_scan', 'seclayer_scan']) {
    const d = await decideScope({ toolName, arguments: { url: 'https://not-mine.example/' } }, v)
    assert.equal(d.kind, 'deny', toolName)
  }
})

test('live: webapp_scan completes against a loopback lab site', async (t) => {
  // Lab targets need the engine's private-target allowance; set it only for this test.
  const prev = process.env.ALLOW_PRIVATE_SCAN_TARGETS
  process.env.ALLOW_PRIVATE_SCAN_TARGETS = 'true'
  t.after(() => { if (prev === undefined) delete process.env.ALLOW_PRIVATE_SCAN_TARGETS; else process.env.ALLOW_PRIVATE_SCAN_TARGETS = prev })
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end('<!doctype html><title>lab</title><h1>lab site</h1>')
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  t.after(() => server.close())
  const port = server.address().port
  const out = JSON.parse(await run('webapp_scan', { url: `http://127.0.0.1:${port}/` }, fakeVerifier()))
  assert.equal(out.status, 'complete', JSON.stringify(out).slice(0, 300))
  assert.equal(out.lab, true)
  assert.ok(out.result, 'engine result present')
})
