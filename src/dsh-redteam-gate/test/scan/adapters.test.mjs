// Per-request scope gate around the verbatim engines. Run with: node --import tsx --test test/scan/adapters.test.mjs
import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { fetchTarget, runSeclayerProbe, scanWebapp } from '../../src/scan-adapters.mjs'

const verifierWith = (verified = new Set()) => {
  const calls = []
  return { calls, async isVerified(d) { calls.push(d); return verified.has(d) } }
}

/** Records every call to the real fetch. The gate wraps global fetch, so its refusals never reach this spy. */
function spyFetch(t) {
  const original = globalThis.fetch
  const urls = []
  globalThis.fetch = async (input, init) => {
    urls.push(typeof input === 'string' ? input : input.url)
    return original(input, init)
  }
  t.after(() => { globalThis.fetch = original })
  return urls
}

/** Loopback lab targets need the VibeScan private-target allowance; scoped to the test. */
function allowPrivate(t) {
  const prev = process.env.ALLOW_PRIVATE_SCAN_TARGETS
  process.env.ALLOW_PRIVATE_SCAN_TARGETS = 'true'
  t.after(() => { if (prev === undefined) delete process.env.ALLOW_PRIVATE_SCAN_TARGETS; else process.env.ALLOW_PRIVATE_SCAN_TARGETS = prev })
}

function lab(t, handler) {
  const server = http.createServer(handler)
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => {
    t.after(() => server.close())
    resolve(server.address().port)
  }))
}

test('fetchTarget refuses an unverified domain and sends no request', async (t) => {
  const urls = spyFetch(t)
  const v = verifierWith()
  await assert.rejects(() => fetchTarget(v, 'https://not-mine.example/'), /not-mine\.example/)
  assert.deepEqual(urls, [], 'no outbound request for an unverified target')
})

test('scanWebapp refuses an unverified domain and sends no request', async (t) => {
  const urls = spyFetch(t)
  await assert.rejects(() => scanWebapp(verifierWith(), 'https://not-mine.example/', 'basic'))
  assert.deepEqual(urls, [])
})

test('runSeclayerProbe refuses an unverified target before any probe code runs', async (t) => {
  const urls = spyFetch(t)
  await assert.rejects(() => runSeclayerProbe(verifierWith(), 'sqlInjection', { url: 'https://not-mine.example/?id=1', fuzzHeaders: {} }))
  assert.deepEqual(urls, [])
})

test('runSeclayerProbe rejects an unknown probe name', async () => {
  await assert.rejects(() => runSeclayerProbe(verifierWith(), 'blindSsrf', { url: 'http://127.0.0.1/', fuzzHeaders: {} }), /not an active probe/)
})

test('fetchTarget reaches a loopback lab target', async (t) => {
  allowPrivate(t)
  const port = await lab(t, (req, res) => { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('lab') })
  const out = await fetchTarget(verifierWith(), `http://127.0.0.1:${port}/`)
  assert.ok(out, 'engine returned a result')
  assert.equal(out.status ?? out.statusCode, 200)
})

test('a redirect from a lab target to an unverified host is not followed', async (t) => {
  allowPrivate(t)
  const urls = spyFetch(t)
  const port = await lab(t, (req, res) => { res.writeHead(302, { location: 'https://not-mine.example/landing' }); res.end() })
  const out = await fetchTarget(verifierWith(), `http://127.0.0.1:${port}/start`)
  assert.equal(urls.filter((u) => u.includes('not-mine.example')).length, 0, 'the redirect hop was never sent')
  // The engine swallows the refused hop and reports no result for it.
  assert.equal(out, null)
})
