// Phase 2 done-test: DNS TXT ownership gate, fail closed, with a zero-packet negative control.
// Run with: node --import tsx --test test/scan/ownership-gate.test.mjs
import { test } from 'node:test'
import assert from 'node:assert/strict'
import dns from 'node:dns'
import http from 'node:http'
import net from 'node:net'
import tls from 'node:tls'
import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs'
import { LocalDomainVerifier, CHALLENGE_RECORD_PREFIX } from '../../src/verifier.mjs'
import { webappScanHandler, seclayerScanHandler } from '../../src/scan-handlers.mjs'
import { fetchTarget } from '../../src/scan-adapters.mjs'

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ownership-'))
const storeFile = (name) => path.join(tmp, `${name}.json`)

/** Every attempt to reach a host, whatever the code path: TCP/TLS connects, http requests, fetch, DNS lookups of a name. */
function packetSpy(t, target) {
  const seen = []
  const hit = (what, h) => { if (String(h).includes(target)) seen.push(`${what}:${h}`) }
  const restore = []
  const patch = (obj, key, what, pick) => {
    const orig = obj[key]
    obj[key] = function (...args) { hit(what, pick(args)); return orig.apply(this, args) }
    restore.push(() => { obj[key] = orig })
  }
  patch(net.Socket.prototype, 'connect', 'connect', (a) => (typeof a[0] === 'object' ? a[0].host ?? a[0].hostname : a[0]))
  patch(net, 'connect', 'connect', (a) => (typeof a[0] === 'object' ? a[0].host ?? a[0].hostname : a[0]))
  patch(net, 'createConnection', 'connect', (a) => (typeof a[0] === 'object' ? a[0].host ?? a[0].hostname : a[0]))
  patch(http, 'request', 'http.request', (a) => (typeof a[0] === 'string' ? a[0] : a[0]?.host ?? a[0]?.hostname))
  patch(tls, 'connect', 'connect', (a) => (typeof a[0] === 'object' ? a[0].host ?? a[0].hostname : a[0]))
  patch(dns, 'lookup', 'dns.lookup', (a) => a[0])
  const origFetch = globalThis.fetch
  globalThis.fetch = (input, init) => { hit('fetch', typeof input === 'string' ? input : input.url); return origFetch(input, init) }
  restore.push(() => { globalThis.fetch = origFetch })
  t.after(() => restore.forEach((r) => r()))
  return seen
}

test('negative control: an unverified domain is refused and no connection to it is attempted', async (t) => {
  const packets = packetSpy(t, 'example.com')
  // Real verifier, real TXT lookup. example.com has no _secscan-challenge record, so the lookup fails or returns nothing.
  const verifier = new LocalDomainVerifier({ storeFile: storeFile('neg') })
  const out = JSON.parse(await webappScanHandler({ url: 'https://example.com/' }, verifier))
  assert.equal(out.status, 'refused')
  assert.match(out.reason, /Zero packets sent/)
  assert.deepEqual(packets, [], `packets sent to the unverified target: ${packets.join(', ')}`)
})

test('negative control holds for every tool that reaches a target', async (t) => {
  const packets = packetSpy(t, 'example.com')
  const verifier = new LocalDomainVerifier({ storeFile: storeFile('neg2') })
  assert.equal(JSON.parse(await seclayerScanHandler({ url: 'https://example.com/' }, verifier)).status, 'refused')
  await assert.rejects(() => fetchTarget(verifier, 'https://example.com/'))
  assert.deepEqual(packets, [])
})

test('a TXT record that does not carry the challenge token does not verify', async () => {
  const verifier = new LocalDomainVerifier({
    storeFile: storeFile('wrong'),
    resolveTxt: async () => [['secscan-verify-not-the-token']],
  })
  await verifier.start('mine.example')
  const r = await verifier.check('mine.example')
  assert.equal(r.verified, false)
  assert.match(r.reason, /none carries the challenge token/)
  assert.equal(await verifier.isVerified('mine.example'), false)
})

test('positive control: the published challenge verifies, and the gate then allows the domain', async () => {
  let published = []
  const verifier = new LocalDomainVerifier({
    storeFile: storeFile('pos'),
    resolveTxt: async (name) => (name === `${CHALLENGE_RECORD_PREFIX}.mine.example` ? published : []),
  })
  const c = await verifier.start('mine.example')
  published = [[c.token]]
  const r = await verifier.check('mine.example')
  assert.equal(r.verified, true)
  assert.equal(await verifier.isVerified('mine.example'), true)
  // The gate in front of the scan tools now lets the domain through (no scan is started here).
  const { gateScanTarget } = await import('../../src/scan-gate.mjs')
  const gate = await gateScanTarget('https://mine.example/app', verifier)
  assert.equal(gate.ok, true)
})

test('verification is per domain: verifying one does not verify a sibling', async () => {
  const verifier = new LocalDomainVerifier({
    storeFile: storeFile('sibling'),
    resolveTxt: async (name) => [[name.endsWith('mine.example') ? 'x' : 'y']],
  })
  const c = await verifier.start('mine.example')
  verifier.resolveTxt = async () => [[c.token]]
  await verifier.check('mine.example')
  assert.equal(await verifier.isVerified('mine.example'), true)
  assert.equal(await verifier.isVerified('other.example'), false)
})

test('a verification store that cannot be read fails closed', async () => {
  const bad = storeFile('corrupt')
  fs.writeFileSync(bad, '{not json')
  const verifier = new LocalDomainVerifier({ storeFile: bad })
  assert.equal(await verifier.isVerified('mine.example'), false)
  const out = JSON.parse(await webappScanHandler({ url: 'https://mine.example/' }, verifier))
  assert.equal(out.status, 'refused')
})

test('the packet spy is not vacuous: it records a connection attempt when one is made', async (t) => {
  const seen = packetSpy(t, 'spy-check.invalid')
  await new Promise((resolve) => {
    const s = net.connect({ host: 'spy-check.invalid', port: 9 })
    s.on('error', () => resolve())
    s.on('connect', () => { s.destroy(); resolve() })
  })
  assert.ok(seen.some((x) => x.startsWith('connect:') || x.startsWith('dns.lookup:')), `spy saw: ${seen.join(', ')}`)
  // An IP-literal connection involves no name lookup, so it must be caught by the connect hook itself.
  const seenIp = packetSpy(t, '203.0.113.9')
  await new Promise((resolve) => { const s = net.connect({ host: '203.0.113.9', port: 9, timeout: 200 }); s.on('error', resolve); s.on('timeout', () => { s.destroy(); resolve() }); s.on('connect', () => { s.destroy(); resolve() }) })
  assert.ok(seenIp.some((x) => x.startsWith('connect:')), `ip spy saw: ${seenIp.join(', ')}`)
})

test('domain verification tools: start issues a challenge, check refuses until the record is published', async () => {
  const { domainVerifyStartHandler, domainVerifyCheckHandler } = await import('../../src/scan-handlers.mjs')
  let published = []
  const verifier = new LocalDomainVerifier({
    storeFile: storeFile('tools'),
    resolveTxt: async () => published,
  })
  const started = JSON.parse(await domainVerifyStartHandler({ domain: 'Mine.Example' }, verifier))
  assert.equal(started.status, 'challenge_issued')
  assert.equal(started.txt_record_name, '_secscan-challenge.mine.example')
  assert.match(started.txt_record_value, /^secscan-verify-/)
  assert.equal(JSON.parse(await domainVerifyCheckHandler({ domain: 'mine.example' }, verifier)).status, 'not_verified')
  published = [[started.txt_record_value]]
  assert.equal(JSON.parse(await domainVerifyCheckHandler({ domain: 'mine.example' }, verifier)).status, 'verified')
})
