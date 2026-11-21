import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { startLabServer } from './fixtures/lab-server.mjs'
import { decideScope } from '../../src/scope.mjs'
import { REDTEAM_MODULES, ScopeDeniedError } from '../../src/engines/seclayer/index.mjs'
import * as xss from '../../src/engines/seclayer/reflectedXss.mjs'
import * as sqli from '../../src/engines/seclayer/sqlInjection.mjs'
import * as ssrf from '../../src/engines/seclayer/ssrf.mjs'
import * as cmdi from '../../src/engines/seclayer/commandInjection.mjs'

let lab
before(async () => { lab = await startLabServer() })
after(async () => { await lab.close() })

const never = { isVerified: async () => false }

/** Spy fetch that must never be called when the gate denies. Returns a canned clean page. */
function spyFetch(body = '<html><body>clean</body></html>') {
  const calls = []
  const fn = async (url, init) => {
    calls.push(url)
    return new Response(body, { status: 200, headers: { 'content-type': 'text/html' } })
  }
  fn.calls = calls
  return fn
}

test('every module exports name, owaspCategory and run', () => {
  assert.equal(REDTEAM_MODULES.length, 4)
  for (const m of REDTEAM_MODULES) {
    assert.equal(typeof m.name, 'string')
    assert.equal(typeof m.owaspCategory, 'string')
    assert.equal(typeof m.run, 'function')
  }
})

test('reflected XSS: executable reflection is reported', async () => {
  const f = await xss.run(`${lab.base}/vuln`)
  assert.ok(f, 'expected a finding')
  assert.equal(f.module, 'reflected-xss')
  assert.match(f.payload, /^<script>xss_probe_[0-9a-f]{8}<\/script>$/)
  assert.equal(f.evidence.quote, f.payload)
  assert.equal(f.evidence.status, 200)
})

test('reflected XSS: escaped reflection is not reported', async () => {
  assert.equal(await xss.run(`${lab.base}/escaped`), null)
})

test('reflected XSS: reflection inside a JSON body is not reported', async () => {
  assert.equal(await xss.run(`${lab.base}/json`), null)
})

test('reflectionExecutes rejects comments and textarea context', () => {
  assert.equal(xss.reflectionExecutes('text/html', '<!-- <script>x</script> -->', 5), false)
  assert.equal(xss.reflectionExecutes('text/html', '<textarea><script>x</script></textarea>', 10), false)
  assert.equal(xss.reflectionExecutes('text/html', '<div><script>x</script></div>', 5), true)
})

test('SQL injection: raw database error is reported', async () => {
  const f = await sqli.run(`${lab.base}/vuln`)
  assert.ok(f, 'expected a finding')
  assert.equal(f.module, 'sql-injection')
  assert.equal(f.severity, 'critical')
  assert.match(f.evidence.quote, /SQL syntax;/)
})

test('SQL injection: error text that a benign request also returns is suppressed', async () => {
  assert.equal(await sqli.run(`${lab.base}/docs`), null)
})

test('SQL injection: a clean page is not reported', async () => {
  assert.equal(await sqli.run(`${lab.base}/escaped`), null)
})

test('SSRF: internal SSH banner is reported', async () => {
  const f = await ssrf.run(`${lab.base}/vuln`)
  assert.ok(f, 'expected a finding')
  assert.equal(f.module, 'ssrf')
  assert.match(f.evidence.quote, /^SSH-2\.0-/)
})

test('SSRF: banner quoted in static docs is suppressed by the baseline', async () => {
  assert.equal(await ssrf.run(`${lab.base}/docs`), null)
})

test('command injection: computed arithmetic oracle is reported', async () => {
  const f = await cmdi.run(`${lab.base}/vuln`)
  assert.ok(f, 'expected a finding')
  assert.equal(f.module, 'command-injection')
  assert.match(f.payload, /^; expr \d+ \+ \d+$/)
})

test('command injection: non-executing target is not reported', async () => {
  assert.equal(await cmdi.run(`${lab.base}/escaped`), null)
})

test('non-lab host: every module is refused before any request is sent', async () => {
  for (const m of REDTEAM_MODULES) {
    const fetchFn = spyFetch()
    await assert.rejects(
      m.run('https://victim.example.org', {}, fetchFn),
      (err) => err instanceof ScopeDeniedError && /victim\.example\.org/.test(err.reason),
      `${m.name} should be refused`,
    )
    assert.equal(fetchFn.calls.length, 0, `${m.name} must send zero packets`)
  }
})

test('non-lab public IP: refused even with a verifier that says yes', async () => {
  const fetchFn = spyFetch()
  await assert.rejects(
    xss.run('http://8.8.8.8', { gate: { isVerified: async () => true } }, fetchFn),
    ScopeDeniedError,
  )
  assert.equal(fetchFn.calls.length, 0)
})

test('a throwing verifier fails closed for red-team modules', async () => {
  const fetchFn = spyFetch()
  const throwing = { isVerified: async () => { throw new Error('network down') } }
  await assert.rejects(sqli.run('https://victim.example.org', { gate: throwing }, fetchFn), ScopeDeniedError)
  assert.equal(fetchFn.calls.length, 0)
})

test('verified domain passes the gate, and the injected fetch is the only transport', async () => {
  const fetchFn = spyFetch()
  const verified = { isVerified: async (d) => d === 'app.example.com' }
  const f = await xss.run('https://app.example.com', { gate: verified }, fetchFn)
  assert.equal(f, null)
  assert.equal(fetchFn.calls.length, 1)
  assert.ok(fetchFn.calls.every((u) => u.startsWith('https://app.example.com/')))
})

test('decideScope directly: non-lab hosts are denied for an active tool', async () => {
  const cases = [
    'https://victim.example.org/?q=x',
    'http://203.0.113.10/',
  ]
  for (const url of cases) {
    const r = await decideScope({ toolName: 'nuclei', arguments: { target: url } }, never)
    assert.equal(r.kind, 'deny', url)
  }
})

test('decideScope directly: the loopback lab is allowed', async () => {
  const r = await decideScope({ toolName: 'nuclei', arguments: { target: `${lab.base}/vuln/?q=x` } }, never)
  assert.equal(r.kind, 'allow')
})

test('non-http target is rejected before any request', async () => {
  const fetchFn = spyFetch()
  await assert.rejects(xss.run('ftp://127.0.0.1/', {}, fetchFn), TypeError)
  assert.equal(fetchFn.calls.length, 0)
})
