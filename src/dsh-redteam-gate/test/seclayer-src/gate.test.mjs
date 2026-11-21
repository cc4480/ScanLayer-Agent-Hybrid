// Scope-gate tests for the verbatim SecLayer copy. The gate must refuse non-lab hosts before any
// request is sent (spy fetch called zero times), and must allow a loopback lab target.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { createGatedFetch, ScopeDeniedError } from '../../src/engines/seclayer-glue/gate-adapter.mjs'

function spyFetch(impl) {
  const calls = []
  const fn = async (url, init) => {
    calls.push({ url, init })
    return impl(url, init)
  }
  return { fn, calls }
}

test('non-lab host is refused before any request (fail-closed default gate)', async () => {
  const spy = spyFetch(async () => new Response('should not happen', { status: 200 }))
  const gatedFetch = createGatedFetch({ fetchFn: spy.fn })
  await assert.rejects(gatedFetch('https://victim.example.org/?url=http://127.0.0.1:22'), (err) => {
    assert.ok(err instanceof ScopeDeniedError)
    assert.match(err.reason, /victim\.example\.org/)
    return true
  })
  assert.equal(spy.calls.length, 0)
})

test('non-lab host stays refused even when the gate reports unverified or throws', async () => {
  const spy = spyFetch(async () => new Response('x', { status: 200 }))
  const throwing = createGatedFetch({ fetchFn: spy.fn, gate: { isVerified: async () => { throw new Error('db down') } } })
  await assert.rejects(throwing('https://victim.example.org/'), ScopeDeniedError)
  const unverified = createGatedFetch({ fetchFn: spy.fn, gate: { isVerified: async () => false } })
  await assert.rejects(unverified('https://victim.example.org/'), ScopeDeniedError)
  assert.equal(spy.calls.length, 0)
})

test('non-lab host passes only when the injected gate verifies it', async () => {
  const spy = spyFetch(async () => new Response('ok', { status: 200 }))
  const gatedFetch = createGatedFetch({ fetchFn: spy.fn, gate: { isVerified: async (d) => d === 'victim.example.org' } })
  const res = await gatedFetch('https://victim.example.org/')
  assert.equal(res.status, 200)
  assert.equal(spy.calls.length, 1)
})

test('loopback lab target is allowed and reaches a local 127.0.0.1 server', async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('lab-ok')
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  try {
    const { port } = server.address()
    const spy = spyFetch(globalThis.fetch)
    const gatedFetch = createGatedFetch({ fetchFn: spy.fn })
    const res = await gatedFetch(`http://127.0.0.1:${port}/?q=1`, { redirect: 'manual' })
    assert.equal(res.status, 200)
    assert.equal(await res.text(), 'lab-ok')
    assert.equal(spy.calls.length, 1)
  } finally {
    await new Promise((r) => server.close(r))
  }
})

test('mixed lab and non-lab target in one call is refused and nothing is sent', async () => {
  const spy = spyFetch(async () => new Response('x', { status: 200 }))
  const gatedFetch = createGatedFetch({ fetchFn: spy.fn })
  await assert.rejects(gatedFetch('http://127.0.0.1:9/?next=https://victim.example.org/'), ScopeDeniedError)
  assert.equal(spy.calls.length, 0)
})
