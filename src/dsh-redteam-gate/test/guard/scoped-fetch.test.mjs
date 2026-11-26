import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { withScopedFetch, makeGuardedFetch, ScopeDeniedError } from '../../src/engines/guard/scoped-fetch.mjs'

const never = { isVerified: async () => false }

function labServer(handler) {
  return new Promise((resolve) => {
    const srv = createServer(handler)
    srv.listen(0, '127.0.0.1', () => resolve(srv))
  })
}

test('a loopback request goes through and the original fetch is restored afterwards', async () => {
  const srv = await labServer((req, res) => { res.end('hello') })
  const port = srv.address().port
  try {
    const original = globalThis.fetch
    const body = await withScopedFetch(never, async () => (await fetch(`http://127.0.0.1:${port}/`)).text())
    assert.equal(body, 'hello')
    assert.equal(globalThis.fetch, original)
  } finally {
    srv.close()
  }
})

test('a non-lab host is refused before any network call; the original fetch is never invoked', async () => {
  let calls = 0
  const spy = async () => { calls++; return new Response('x') }
  const guarded = makeGuardedFetch(never, spy)
  await assert.rejects(() => guarded('https://victim.example.org/'), ScopeDeniedError)
  await assert.rejects(() => guarded('http://8.8.8.8/'), ScopeDeniedError)
  assert.equal(calls, 0)
})

test('a redirect from the lab to a non-lab host is refused at the hop', async () => {
  const srv = await labServer((req, res) => {
    res.writeHead(302, { location: 'http://victim.example.org/steal' })
    res.end()
  })
  const port = srv.address().port
  try {
    await assert.rejects(
      () => withScopedFetch(never, () => fetch(`http://127.0.0.1:${port}/go`)),
      (err) => err instanceof ScopeDeniedError && /victim\.example\.org/.test(err.message),
    )
  } finally {
    srv.close()
  }
})

test('a verified domain is allowed through the gate (verifier spy says yes)', async () => {
  const yes = { isVerified: async (d) => d === 'example.com' }
  let calls = 0
  const spy = async () => { calls++; return new Response('ok') }
  const guarded = makeGuardedFetch(yes, spy)
  const res = await guarded('https://example.com/a')
  assert.equal(await res.text(), 'ok')
  assert.equal(calls, 1)
})

test('non-http schemes are refused', async () => {
  const guarded = makeGuardedFetch({ isVerified: async () => true }, async () => new Response('x'))
  await assert.rejects(() => guarded('file:///etc/passwd'), ScopeDeniedError)
  await assert.rejects(() => guarded('ftp://127.0.0.1/'), ScopeDeniedError)
})

test('runs are serialized, so two guarded runs never overlap', async () => {
  const order = []
  const gate = { isVerified: async () => false }
  const a = withScopedFetch(gate, async () => { order.push('a-start'); await new Promise((r) => setTimeout(r, 30)); order.push('a-end') })
  const b = withScopedFetch(gate, async () => { order.push('b-start'); order.push('b-end') })
  await Promise.all([a, b])
  assert.deepEqual(order, ['a-start', 'a-end', 'b-start', 'b-end'])
})

test('the original fetch is restored even when the guarded run throws', async () => {
  const original = globalThis.fetch
  await assert.rejects(() => withScopedFetch(never, async () => { throw new Error('boom') }), /boom/)
  assert.equal(globalThis.fetch, original)
})

test('a gate is required', () => {
  assert.throws(() => withScopedFetch(null, async () => {}), TypeError)
})

// A probe must be able to send an attacker URL as a PAYLOAD to a verified target:
// `?next=https://evil.example/` and `?url=http://169.254.169.254/` are the whole
// point of an open-redirect / SSRF test. The gate used to substring-scan the whole
// request URL for host-like tokens and refused every such request with "zero
// packets sent", which silently disabled those probes against every target (they
// reported "no signal" having sent nothing). Only the URL's own host may decide.
test('a payload host inside the query string does not deny a verified/lab target', async () => {
  let calls = 0
  const srv = await labServer((req, res) => { calls++; res.writeHead(302, { Location: '//evil.example/' }); res.end() })
  const port = srv.address().port
  try {
    await withScopedFetch(never, async () => {
      const a = await fetch(`http://127.0.0.1:${port}/?next=https%3A%2F%2Fevil.example%2F`, { redirect: 'manual' })
      const b = await fetch(`http://127.0.0.1:${port}/?url=http://169.254.169.254/latest/meta-data`, { redirect: 'manual' })
      assert.equal(a.status, 302)
      assert.equal(b.status, 302)
    })
    assert.equal(calls, 2, 'both payload requests must actually be sent')
  } finally {
    srv.close()
  }
})

test('the target host still decides: an unverified host is denied even when the query names a lab host', async () => {
  let calls = 0
  const spy = async () => { calls++; return new Response('x') }
  const original = globalThis.fetch
  globalThis.fetch = spy
  try {
    await assert.rejects(
      () => withScopedFetch(never, async () => fetch('https://evil.example/?next=http://127.0.0.1:4599/')),
      (e) => e instanceof ScopeDeniedError && /evil\.example/.test(e.message),
    )
    assert.equal(calls, 0, 'no packet may be sent to the unverified host')
  } finally {
    globalThis.fetch = original
  }
})

test('a bare public IP target is still denied', async () => {
  await assert.rejects(
    () => withScopedFetch(never, async () => fetch('http://169.254.169.254/latest/meta-data')),
    (e) => e instanceof ScopeDeniedError && /169\.254\.169\.254/.test(e.message),
  )
})
