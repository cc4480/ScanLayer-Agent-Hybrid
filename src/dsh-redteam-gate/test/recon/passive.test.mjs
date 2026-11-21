import { test } from 'node:test'
import assert from 'node:assert/strict'
import { dnsRecords, certTransparency, subdomainsFromPublicRecords, CT_ENDPOINT } from '../../src/engines/recon/passive.mjs'

// Fake resolver: each method returns canned answers or throws a node-style error.
function fakeResolver(answers = {}) {
  const calls = []
  const make = (type) => async (domain) => {
    calls.push([type, domain])
    const a = answers[type]
    if (a instanceof Error) throw a
    if (a === undefined) throw Object.assign(new Error('queryX ENODATA'), { code: 'ENODATA' })
    return typeof a === 'function' ? a(domain) : a
  }
  return {
    calls,
    resolve4: make('A'),
    resolve6: make('AAAA'),
    resolveMx: make('MX'),
    resolveTxt: make('TXT'),
    resolveNs: make('NS'),
    resolveCname: make('CNAME'),
  }
}

// Fake fetch: records the URL and returns a Response-like object.
function fakeFetch(body, { ok = true, status = 200 } = {}) {
  const seen = []
  const fn = async (url, init) => {
    seen.push({ url, init })
    return { ok, status, json: async () => (body instanceof Error ? Promise.reject(body) : body) }
  }
  fn.seen = seen
  return fn
}

test('dnsRecords collects each record type and normalizes values', async () => {
  const resolver = fakeResolver({
    A: ['192.0.2.10'],
    AAAA: ['2001:db8::10'],
    MX: [{ exchange: 'MAIL.Example.com.', priority: 10 }],
    TXT: [['v=spf1 ', '-all']],
    NS: ['NS1.Example.com.'],
    CNAME: undefined,
  })
  const r = await dnsRecords('Example.com', resolver)
  assert.equal(r.domain, 'example.com')
  assert.deepEqual(Object.keys(r.records), ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'])
  assert.deepEqual(r.records.A, ['192.0.2.10'])
  assert.deepEqual(r.records.MX, [{ exchange: 'mail.example.com', priority: 10 }])
  assert.deepEqual(r.records.TXT, ['v=spf1 -all'])
  assert.deepEqual(r.records.NS, ['ns1.example.com'])
  assert.deepEqual(r.records.CNAME, [])
  assert.deepEqual(r.errors, {})
  assert.doesNotThrow(() => JSON.stringify(r))
  assert.equal(resolver.calls.length, 6)
})

test('dnsRecords treats ENODATA/ENOTFOUND as empty, other errors as errors', async () => {
  const resolver = fakeResolver({
    A: Object.assign(new Error('nope'), { code: 'ENOTFOUND' }),
    MX: Object.assign(new Error('refused'), { code: 'EREFUSED' }),
  })
  const r = await dnsRecords('example.com', resolver)
  assert.deepEqual(r.records.A, [])
  assert.deepEqual(r.errors, { MX: 'EREFUSED: refused' })
})

test('dnsRecords reports a missing resolver method instead of crashing', async () => {
  const r = await dnsRecords('example.com', { resolve4: async () => ['192.0.2.1'] })
  assert.deepEqual(r.records.A, ['192.0.2.1'])
  assert.equal(r.errors.MX, 'resolver has no resolveMx')
})

test('dnsRecords times out a hanging lookup', async () => {
  const resolver = { resolve4: () => new Promise(() => {}) }
  const r = await dnsRecords('example.com', resolver, { timeoutMs: 20 })
  assert.match(r.errors.A, /timed out after 20ms/)
})

test('dnsRecords refuses invalid domains before any lookup', async () => {
  const resolver = fakeResolver({ A: ['192.0.2.1'] })
  await assert.rejects(dnsRecords('10.0.0.1', resolver), TypeError)
  await assert.rejects(dnsRecords('example.com/x', resolver), TypeError)
  assert.equal(resolver.calls.length, 0)
})

test('certTransparency parses crt.sh JSON, strips wildcards, drops out-of-zone names', async () => {
  const fetchFn = fakeFetch([
    { name_value: 'www.example.com\n*.api.example.com', common_name: 'example.com' },
    { name_value: 'EXAMPLE.com', common_name: 'other.net' },
    { name_value: 'evil-example.com', common_name: 'x' },
    { name_value: 'not a host@example.com', common_name: '' },
  ])
  const r = await certTransparency('example.com', fetchFn)
  assert.deepEqual(r, {
    domain: 'example.com',
    source: 'crt.sh',
    names: ['api.example.com', 'example.com', 'www.example.com'],
  })
  assert.equal(fetchFn.seen.length, 1)
  assert.ok(fetchFn.seen[0].url.startsWith(CT_ENDPOINT))
  assert.equal(new URL(fetchFn.seen[0].url).searchParams.get('q'), '%.example.com')
  assert.equal(new URL(fetchFn.seen[0].url).searchParams.get('output'), 'json')
})

test('certTransparency returns an error object on HTTP failure, never throws', async () => {
  const r = await certTransparency('example.com', fakeFetch({}, { ok: false, status: 503 }))
  assert.deepEqual(r.names, [])
  assert.match(r.error, /status 503/)
})

test('certTransparency handles non-array bodies and fetch rejections', async () => {
  const bad = await certTransparency('example.com', fakeFetch({ error: 'x' }))
  assert.match(bad.error, /non-array/)
  const down = await certTransparency('example.com', async () => { throw new Error('offline') })
  assert.deepEqual(down.names, [])
  assert.equal(down.error, 'offline')
})

test('certTransparency refuses invalid domains without fetching', async () => {
  const fetchFn = fakeFetch([])
  await assert.rejects(certTransparency('https://example.com', fetchFn), TypeError)
  await assert.rejects(certTransparency('::1', fetchFn), TypeError)
  assert.equal(fetchFn.seen.length, 0)
})

test('subdomainsFromPublicRecords merges CT and DNS sources and excludes the apex', async () => {
  const resolver = fakeResolver({
    A: ['192.0.2.1'],
    MX: [{ exchange: 'mx1.example.com', priority: 10 }, { exchange: 'mail.provider.net', priority: 20 }],
    NS: ['ns1.example.com', 'ns2.example.com'],
    CNAME: undefined,
  })
  const fetchFn = fakeFetch([
    { name_value: 'example.com\nwww.example.com\nmx1.example.com', common_name: 'example.com' },
  ])
  const r = await subdomainsFromPublicRecords('example.com', { resolver, fetchFn })
  assert.equal(r.domain, 'example.com')
  assert.deepEqual(r.subdomains, [
    { name: 'mx1.example.com', sources: ['crt.sh', 'dns'] },
    { name: 'ns1.example.com', sources: ['dns'] },
    { name: 'ns2.example.com', sources: ['dns'] },
    { name: 'www.example.com', sources: ['crt.sh'] },
  ])
  assert.equal(r.ct.source, 'crt.sh')
  assert.ok(r.dns.records)
  assert.doesNotThrow(() => JSON.stringify(r))
})

test('subdomainsFromPublicRecords still returns DNS names when CT fails', async () => {
  const resolver = fakeResolver({ NS: ['ns1.example.com'] })
  const r = await subdomainsFromPublicRecords('example.com', {
    resolver,
    fetchFn: async () => { throw new Error('crt.sh down') },
  })
  assert.deepEqual(r.subdomains, [{ name: 'ns1.example.com', sources: ['dns'] }])
  assert.equal(r.ct.error, 'crt.sh down')
})

test('subdomainsFromPublicRecords refuses invalid domains', async () => {
  await assert.rejects(subdomainsFromPublicRecords('192.168.1.1', { resolver: fakeResolver(), fetchFn: fakeFetch([]) }), TypeError)
  await assert.rejects(subdomainsFromPublicRecords('example.com:8443', { resolver: fakeResolver(), fetchFn: fakeFetch([]) }), TypeError)
})
