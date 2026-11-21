// Tests for the secscan-network port: every outbound request of the copied network modules goes through
// withScopedFetch with the real scope policy (src/scope.mjs). The verifier is a FAKE that verifies nothing, so
// only loopback targets (127.0.0.1 / localhost / ::1) can run. The copies are not edited.
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest'
import { createServer } from 'node:http'
import { scanOsv, scanDnsTxt, scanFirebase } from '../../src/engines/secscan-network/adapter.mjs'

// Fake verifier: the SecScan server is not available here, so nothing is verified.
const fakeVerifier = { isVerified: async () => false }

// A fixture apiKey in the Firebase AIza shape. It is a test value made of zeros, not a credential.
const FAKE_FIREBASE_KEY = 'AIza' + '0'.repeat(35)
const FIREBASE_CONTENT = `const cfg = { apiKey: "${FAKE_FIREBASE_KEY}", projectId: "demo-project" };`

const ENV_KEYS = ['OSV_API_URL', 'DOH_ENDPOINT_URL', 'FIRESTORE_API_URL']
let savedEnv
beforeEach(() => { savedEnv = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]])) })
afterEach(() => {
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k]
    else process.env[k] = savedEnv[k]
  }
})

// Count every request that actually leaves through the (guarded) fetch. The guard captures whatever fetch is in
// place when withScopedFetch starts, so this counter sits underneath the guard: refused requests never reach it.
async function countSent(fn) {
  const real = globalThis.fetch
  const hits = []
  globalThis.fetch = async (input, init) => {
    hits.push(String(input instanceof Request ? input.url : input))
    return real(input, init)
  }
  try {
    return { result: await fn(), hits }
  } finally {
    globalThis.fetch = real
  }
}

let server
let base // http://127.0.0.1:<port>
let loopbackHits = []
beforeAll(async () => {
  server = createServer((req, res) => {
    loopbackHits.push(req.url)
    const url = new URL(req.url, 'http://127.0.0.1')
    // Fake OSV: POST /v1/query.
    if (url.pathname === '/v1/query') {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({
        vulns: [{
          id: 'GHSA-test-0001',
          aliases: ['CVE-2099-0001'],
          summary: 'fixture',
          severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/9.8' }],
        }],
      }))
      return
    }
    // Fake OSV redirect that points at a non-lab host: the guard must refuse the hop.
    if (url.pathname === '/redirect-to-victim') {
      res.writeHead(302, { Location: 'https://victim.example.org/v1/query' })
      res.end()
      return
    }
    // Fake Firestore: the 'users' collection returns one document; every other collection is empty.
    if (url.pathname === '/v1/projects/demo-project/databases/(default)/documents/users') {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ documents: [{ name: 'projects/demo-project/databases/(default)/documents/users/u1', fields: { email: { stringValue: 'a@example.test' } } }] }))
      return
    }
    // Fake DNS-over-HTTPS: an answer with one TXT record.
    if (url.pathname === '/dns-query') {
      res.writeHead(200, { 'Content-Type': 'application/dns-json' })
      res.end(JSON.stringify({ Status: 0, Answer: [{ name: 'lab.test.', type: 16, TTL: 300, data: '"v=spf1 -all"' }] }))
      return
    }
    res.writeHead(404)
    res.end()
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  base = `http://127.0.0.1:${server.address().port}`
})
afterAll(() => new Promise((resolve) => server.close(resolve)))

describe('refused targets: non-lab hosts never receive a request', () => {
  it('OSV pointed at a non-lab host is refused; the request count is zero and the run is incomplete', async () => {
    process.env.OSV_API_URL = 'https://victim.example.org/v1/query'
    const before = loopbackHits.length
    const { result, hits } = await countSent(() =>
      scanOsv(fakeVerifier, { packageName: 'left-pad-refused', version: '1.0.0', ecosystem: 'npm' }),
    )
    expect(hits.length).toBe(0)
    expect(loopbackHits.length).toBe(before)
    expect(result.value).toEqual([])
    expect(result.refusedHosts).toEqual(['victim.example.org'])
    expect(result.complete).toBe(false)
  })

  it('DNS over HTTPS pointed at a non-lab host is refused; the request count is zero', async () => {
    process.env.DOH_ENDPOINT_URL = 'https://victim.example.org/dns-query'
    const { result, hits } = await countSent(() => scanDnsTxt(fakeVerifier, 'refused.example.org'))
    expect(hits.length).toBe(0)
    expect(result.value.status).toBe(-1)
    expect(result.refusedHosts).toEqual(['victim.example.org'])
    expect(result.complete).toBe(false)
  })

  it('a dotted DNS query name is refused even on a loopback resolver, because the name is read as a target', async () => {
    process.env.DOH_ENDPOINT_URL = `${base}/dns-query`
    const { result, hits } = await countSent(() => scanDnsTxt(fakeVerifier, 'loopback.test'))
    expect(hits.length).toBe(0)
    expect(result.refusedHosts).toEqual(['loopback.test'])
    expect(result.complete).toBe(false)
  })

  it('a Firebase scan against a non-lab host sends nothing, and the incomplete flag is set', async () => {
    process.env.FIRESTORE_API_URL = 'https://victim.example.org'
    const { result, hits } = await countSent(() => scanFirebase(fakeVerifier, FIREBASE_CONTENT))
    expect(hits.length).toBe(0)
    expect(result.refusedHosts).toEqual(['victim.example.org'])
    expect(result.complete).toBe(false)
    // The copied module reports a refused probe as "no open collections" (see the restrictive-rules finding).
    // This assertion records that behaviour; callers must use `complete` rather than the finding list.
    const names = result.value.map((f) => f.name)
    expect(names).toContain('Firebase Backend Detected — Firestore Rules Appear Restrictive')
  })

  it('a redirect from a loopback target to a non-lab host is refused at the hop; the victim is never contacted', async () => {
    process.env.OSV_API_URL = `${base}/redirect-to-victim`
    const { result, hits } = await countSent(() =>
      scanOsv(fakeVerifier, { packageName: 'redirect-probe', version: '2.0.0', ecosystem: 'npm' }),
    )
    expect(hits.length).toBe(1) // the loopback request only
    expect(hits[0]).toContain('/redirect-to-victim')
    expect(result.value).toEqual([])
    expect(result.refusedHosts).toEqual(['victim.example.org'])
  })
})

describe('loopback targets run through the guard', () => {
  it('the OSV module returns the fixture vulnerability from a loopback mirror', async () => {
    process.env.OSV_API_URL = `${base}/v1/query`
    const { result, hits } = await countSent(() =>
      scanOsv(fakeVerifier, { packageName: 'loopback-pkg', version: '3.1.4', ecosystem: 'npm' }),
    )
    expect(hits.length).toBe(1)
    expect(result.value.map((v) => v.id)).toEqual(['GHSA-test-0001'])
    expect(result.refusedHosts).toEqual([])
    expect(result.complete).toBe(true)
  })

  it('the DNS-over-HTTPS module reads a TXT answer from a loopback resolver', async () => {
    process.env.DOH_ENDPOINT_URL = `${base}/dns-query`
    // The query name is part of the URL, and decideScope treats every dotted name in a URL as a target
    // (see the next describe block). 'localhost' has no dot, so it is not a target.
    const { result, hits } = await countSent(() => scanDnsTxt(fakeVerifier, 'localhost'))
    expect(hits.length).toBe(1)
    expect(result.value.status).toBe(0)
    expect(result.value.answers.map((a) => a.data)).toEqual(['"v=spf1 -all"'])
    expect(result.complete).toBe(true)
  })

  it('the Firebase scan on a loopback Firestore reports the open sensitive collection as critical', async () => {
    process.env.FIRESTORE_API_URL = base
    const { result, hits } = await countSent(() => scanFirebase(fakeVerifier, FIREBASE_CONTENT))
    expect(hits.length).toBeGreaterThan(0)
    expect(hits.every((h) => h.startsWith(base))).toBe(true)
    const critical = result.value.find((f) => f.severity === 'critical')
    expect(critical?.name).toBe('Firestore Security Rules Allow Unauthenticated Read Access')
    expect(result.refusedHosts).toEqual([])
    expect(result.complete).toBe(true)
  })

  it('global fetch is restored after a guarded run', async () => {
    const before = globalThis.fetch
    process.env.DOH_ENDPOINT_URL = `${base}/dns-query`
    await scanDnsTxt(fakeVerifier, 'restore.test')
    expect(globalThis.fetch).toBe(before)
  })
})
