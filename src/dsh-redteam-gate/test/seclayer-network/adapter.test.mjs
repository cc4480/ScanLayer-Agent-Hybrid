import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { createHash } from 'node:crypto'
import { runActiveProbe, runWeakSessionToken } from '../../src/engines/seclayer-network/adapter.mjs'
import { withScopedFetch, ScopeDeniedError } from '../../src/engines/guard/scoped-fetch.mjs'
import { probeFetch } from '../../src/engines/seclayer-network/server/redTeam/probeHttp.ts'

// Lab target: 127.0.0.1 only. The SecLayer SSRF guard blocks loopback unless SCAN_DEV_ALLOW_HOSTS names the
// exact host:port, so the lab port is listed for the duration of each test (the same mechanism the source tests use).
const never = { isVerified: async () => false }
const HEADERS = { 'User-Agent': 'lab-test' }

async function withLab(handler, fn) {
  let hits = 0
  const server = createServer((req, res) => {
    hits++
    handler(req, res)
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  const port = server.address().port
  const prev = process.env.SCAN_DEV_ALLOW_HOSTS
  process.env.SCAN_DEV_ALLOW_HOSTS = `127.0.0.1:${port}`
  try {
    await fn({ url: `http://127.0.0.1:${port}`, hits: () => hits })
  } finally {
    if (prev === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS
    else process.env.SCAN_DEV_ALLOW_HOSTS = prev
    await new Promise((r) => server.close(r))
  }
}

function html(res, body, type = 'text/html; charset=utf-8', status = 200) {
  res.writeHead(status, { 'Content-Type': type })
  res.end(body)
}

// Counts every fetch the guard let through. The guard wraps whatever globalThis.fetch is when withScopedFetch starts.
function spyFetch() {
  const spy = { calls: 0 }
  spy.fn = async () => {
    spy.calls++
    return new Response('should never be reached')
  }
  return spy
}

// ---- lab probes: a vulnerable lab reports, a hardened lab stays quiet ----

test('sqlInjection: a raw SQLite error on the injected quote is reported; the lab was probed', async () => {
  await withLab((req, res) => {
    const id = new URL(req.url, 'http://x').searchParams.get('id') || ''
    html(res, id.includes("'") ? `<pre>near "'": syntax error</pre>` : '<p>row 1</p>')
  }, async ({ url, hits }) => {
    const finding = await runActiveProbe('sqlInjection', { url, fuzzHeaders: HEADERS }, never)
    assert.ok(finding, 'expected a finding')
    assert.equal(finding.testName, 'Active SQL Injection Probe')
    assert.equal(finding.severity, 'critical')
    assert.ok(hits() >= 2, 'attack request and benign baseline both reached the lab')
  })
})

test('sqlInjection: an error already present on the benign page is suppressed by the baseline', async () => {
  await withLab((req, res) => html(res, '<pre>near "x": syntax error</pre>'), async ({ url }) => {
    assert.equal(await runActiveProbe('sqlInjection', { url, fuzzHeaders: HEADERS }, never), null)
  })
})

test('reflectedXss: a <script> marker reflected into an HTML body is reported', async () => {
  await withLab((req, res) => {
    const q = new URL(req.url, 'http://x').searchParams.get('q') || ''
    html(res, `<html><body>${q}</body></html>`)
  }, async ({ url, hits }) => {
    const finding = await runActiveProbe('reflectedXss', { url, fuzzHeaders: HEADERS }, never)
    assert.ok(finding, 'expected a finding')
    assert.equal(finding.testName, 'Active Reflected XSS Probe')
    assert.ok(hits() >= 1)
  })
})

test('reflectedXss: the same reflection in a JSON response is not XSS (execution gate)', async () => {
  await withLab((req, res) => {
    const q = new URL(req.url, 'http://x').searchParams.get('q') || ''
    html(res, JSON.stringify({ q }), 'application/json')
  }, async ({ url }) => {
    assert.equal(await runActiveProbe('reflectedXss', { url, fuzzHeaders: HEADERS }, never), null)
  })
})

test('commandInjection: the arithmetic oracle (computed sum) is reported', async () => {
  await withLab((req, res) => {
    const ping = new URL(req.url, 'http://x').searchParams.get('ping') || ''
    const m = /expr\s+(\d+)\s+\+\s+(\d+)/.exec(ping)
    html(res, m ? `<pre>${Number(m[1]) + Number(m[2])}</pre>` : '<pre>pong</pre>')
  }, async ({ url, hits }) => {
    const finding = await runActiveProbe('commandInjection', { url, fuzzHeaders: HEADERS }, never)
    assert.ok(finding, 'expected a finding')
    assert.equal(finding.testName, 'Active OS Command Injection')
    assert.match(finding.payload, /^; expr \d+ \+ \d+$/)
    assert.ok(hits() >= 1)
  })
})

test('commandInjection: a page that never evaluates input is not reported', async () => {
  await withLab((req, res) => html(res, '<pre>pong</pre>'), async ({ url }) => {
    assert.equal(await runActiveProbe('commandInjection', { url, fuzzHeaders: HEADERS }, never), null)
  })
})

test('ssrf: an SSH banner returned only for the url=127.0.0.1:22 request is reported', async () => {
  await withLab((req, res) => {
    const u = new URL(req.url, 'http://x').searchParams.get('url') || ''
    // Simulated vulnerable app: it returns the loopback SSH banner when asked for it. Nothing is fetched here.
    if (u.includes('127.0.0.1:22')) html(res, 'SSH-2.0-OpenSSH_9.6\n', 'text/plain')
    else html(res, '<p>home</p>')
  }, async ({ url }) => {
    const finding = await runActiveProbe('ssrf', { url, fuzzHeaders: HEADERS }, never)
    assert.ok(finding, 'expected a finding')
    assert.equal(finding.testName, 'Active Server-Side Request Forgery (SSRF)')
  })
})

test('ssrf: a banner already on the unparameterised page is suppressed by the baseline', async () => {
  await withLab((req, res) => html(res, '<pre>SSH-2.0-OpenSSH_9.6 example</pre>'), async ({ url }) => {
    assert.equal(await runActiveProbe('ssrf', { url, fuzzHeaders: HEADERS }, never), null)
  })
})

test('weak session token: a login that issues md5(username + timestamp) is reproduced through the guard', async () => {
  await withLab((req, res) => {
    if (req.method === 'POST' && req.url === '/login') {
      // The token is computed at request time, which falls inside the probe's timestamp window.
      const ts = Math.floor(Date.now() / 1000)
      const token = createHash('md5').update(`carlos${ts}`).digest('hex')
      html(res, JSON.stringify({ token }), 'application/json')
      return
    }
    html(res, 'not found', 'text/plain', 404)
  }, async ({ url }) => {
    const loginTarget = { url: `${url}/login`, method: 'POST', params: ['username', 'password'], source: 'form' }
    const finding = await runWeakSessionToken(loginTarget, { username: 'carlos', password: 'lab-only' }, HEADERS, never)
    assert.ok(finding, 'expected a finding')
    assert.equal(finding.testName, 'Predictable Session Token (Weak Seed Hash)')
  })
})

test('the global fetch is restored after a probe run', async () => {
  await withLab((req, res) => html(res, '<p>x</p>'), async ({ url }) => {
    const original = globalThis.fetch
    await runActiveProbe('sqlInjection', { url, fuzzHeaders: HEADERS }, never)
    assert.equal(globalThis.fetch, original)
  })
})

// ---- refusal: a non-lab target is refused before any request; the request count stays at zero ----

test('a non-lab IP target is refused by every ported probe before any request (count 0)', async () => {
  for (const name of ['sqlInjection', 'reflectedXss', 'commandInjection', 'ssrf']) {
    const spy = spyFetch()
    const original = globalThis.fetch
    globalThis.fetch = spy.fn
    try {
      await assert.rejects(
        () => runActiveProbe(name, { url: 'http://203.0.113.10', fuzzHeaders: HEADERS }, never),
        ScopeDeniedError,
        name,
      )
    } finally {
      globalThis.fetch = original
    }
    assert.equal(spy.calls, 0, `${name}: request count must be zero`)
  }
})

test('a non-lab hostname target is refused before the probe runs (count 0)', async () => {
  const spy = spyFetch()
  const original = globalThis.fetch
  globalThis.fetch = spy.fn
  try {
    await assert.rejects(
      () => runActiveProbe('sqlInjection', { url: 'https://victim.example.org', fuzzHeaders: HEADERS }, never),
      (err) => err instanceof ScopeDeniedError && /victim\.example\.org/.test(err.message),
    )
  } finally {
    globalThis.fetch = original
  }
  assert.equal(spy.calls, 0)
})

test('the guard itself refuses a probe-level request to a non-lab IP (count 0)', async () => {
  const spy = spyFetch()
  const original = globalThis.fetch
  globalThis.fetch = spy.fn
  try {
    await assert.rejects(
      () => withScopedFetch(never, () => probeFetch('http://203.0.113.10/?q=1', HEADERS)),
      ScopeDeniedError,
    )
  } finally {
    globalThis.fetch = original
  }
  assert.equal(spy.calls, 0)
})

test('a lab page that redirects to a non-lab IP is refused at the hop; only the lab was contacted', async () => {
  await withLab((req, res) => {
    if (req.url === '/go') {
      res.writeHead(302, { Location: 'http://203.0.113.10/steal' })
      res.end()
      return
    }
    html(res, '<p>x</p>')
  }, async ({ url, hits }) => {
    await assert.rejects(
      () => withScopedFetch(never, () => probeFetch(`${url}/go`, HEADERS)),
      (err) => err instanceof ScopeDeniedError && /203\.0\.113\.10/.test(err.message),
    )
    assert.equal(hits(), 1, 'only the first lab request was sent; the redirect hop was refused before sending')
  })
})
