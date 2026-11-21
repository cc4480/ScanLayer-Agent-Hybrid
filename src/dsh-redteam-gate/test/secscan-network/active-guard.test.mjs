// Guard tests for the ported active-scan HTTP client (http.ts scanFetch, via adapter.mjs scanTarget).
// The verifier is a FAKE that verifies nothing, so only the loopback lab target can run. Counting sits below the
// guard, so a refused request is never counted. Loopback runs need the self-hosted opt-out (ALLOW_PRIVATE_SCAN_TARGETS),
// which is set here for the lab tests only and restored afterwards. The lab fixture is a node:http server.
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { createServer } from 'node:http'
import { scanTarget } from '../../src/engines/secscan-network/adapter.mjs'

const fakeVerifier = { isVerified: async () => false }

const savedOptOut = process.env.ALLOW_PRIVATE_SCAN_TARGETS
let server
let base // http://127.0.0.1:<port>
let labHits = 0

beforeAll(async () => {
  server = createServer((req, res) => {
    labHits++
    const url = new URL(req.url, 'http://127.0.0.1')
    if (url.pathname === '/redirect-to-victim') {
      res.writeHead(302, { Location: 'https://victim.example.org/' })
      res.end()
      return
    }
    res.writeHead(200, { 'Content-Type': 'text/plain' })
    res.end('lab-page')
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  base = `http://127.0.0.1:${server.address().port}`
  process.env.ALLOW_PRIVATE_SCAN_TARGETS = 'true'
})

afterAll(async () => {
  if (savedOptOut === undefined) delete process.env.ALLOW_PRIVATE_SCAN_TARGETS
  else process.env.ALLOW_PRIVATE_SCAN_TARGETS = savedOptOut
  await new Promise((resolve) => server.close(resolve))
})

// Count every request that actually leaves through the (guarded) fetch.
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

describe('active client: non-lab targets are refused before any request', () => {
  it('a non-lab host is refused; the request count is zero and the run is incomplete', async () => {
    const before = labHits
    const { result, hits } = await countSent(() => scanTarget(fakeVerifier, 'https://victim.example.org/'))
    expect(hits.length).toBe(0)
    expect(labHits).toBe(before)
    expect(result.value).toBeNull()
    expect(result.refusedHosts).toEqual(['victim.example.org'])
    expect(result.complete).toBe(false)
  })

  it('a loopback target that redirects to a non-lab host: the hop is refused and the victim is never requested', async () => {
    const { result, hits } = await countSent(() => scanTarget(fakeVerifier, `${base}/redirect-to-victim`))
    expect(hits.length).toBe(1) // the loopback request only
    expect(hits[0]).toContain('/redirect-to-victim')
    expect(result.value).toBeNull()
    expect(result.refusedHosts).toEqual(['victim.example.org'])
    expect(result.complete).toBe(false)
  })
})

describe('active client: the lab target runs through the guard', () => {
  it('a loopback target returns the response, with one request and a complete run', async () => {
    const { result, hits } = await countSent(() => scanTarget(fakeVerifier, `${base}/`))
    expect(hits.length).toBe(1)
    expect(result.value.status).toBe(200)
    expect(result.value.body).toBe('lab-page')
    expect(result.refusedHosts).toEqual([])
    expect(result.complete).toBe(true)
  })

  it('global fetch is restored after a guarded run', async () => {
    const before = globalThis.fetch
    await scanTarget(fakeVerifier, `${base}/`)
    expect(globalThis.fetch).toBe(before)
  })
})
