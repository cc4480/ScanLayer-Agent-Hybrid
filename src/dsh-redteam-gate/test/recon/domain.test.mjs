import { test } from 'node:test'
import assert from 'node:assert/strict'
import { normalizeDomain, checkDomain } from '../../src/engines/recon/domain.mjs'

test('accepts a plain domain and lowercases it', () => {
  assert.equal(normalizeDomain('Example.COM'), 'example.com')
  assert.equal(normalizeDomain('a-b.sub.example.co.uk'), 'a-b.sub.example.co.uk')
  assert.equal(normalizeDomain('xn--bcher-kva.example'), 'xn--bcher-kva.example')
})

test('refuses IPv4 addresses', () => {
  assert.throws(() => normalizeDomain('8.8.8.8'), /IP address/)
  assert.throws(() => normalizeDomain('127.0.0.1'), /IP address/)
})

test('refuses IPv6 literals and bracketed hosts', () => {
  assert.throws(() => normalizeDomain('::1'), /not domains/)
  assert.throws(() => normalizeDomain('[::1]'), /not domains/)
  assert.throws(() => normalizeDomain('2001:db8::1'), /not domains/)
})

test('refuses paths, ports, URLs and userinfo', () => {
  for (const bad of ['example.com/path', 'example.com:443', 'https://example.com', 'user@example.com', 'example.com?q=1', 'example.com#frag']) {
    assert.throws(() => normalizeDomain(bad), TypeError, bad)
  }
})

test('refuses whitespace and wildcards', () => {
  for (const bad of [' example.com', 'example.com ', 'exa mple.com', '*.example.com', 'example.*']) {
    assert.throws(() => normalizeDomain(bad), TypeError, JSON.stringify(bad))
  }
})

test('refuses single labels, trailing dots and empty input', () => {
  assert.throws(() => normalizeDomain('localhost'), /two labels/)
  assert.throws(() => normalizeDomain('example.com.'), /trailing dot/)
  assert.throws(() => normalizeDomain(''), /empty/)
})

test('refuses malformed labels', () => {
  for (const bad of ['-bad.example.com', 'bad-.example.com', 'under_score.example.com', 'exa..mple.com', '.example.com']) {
    assert.throws(() => normalizeDomain(bad), TypeError, bad)
  }
  assert.throws(() => normalizeDomain(`${'a'.repeat(64)}.example.com`), /invalid label/)
})

test('refuses names longer than 253 characters and non-string input', () => {
  const long = Array(10).fill('a'.repeat(30)).join('.') + '.com'
  assert.throws(() => normalizeDomain(long), /253/)
  for (const v of [null, undefined, 42, {}, ['example.com']]) {
    assert.throws(() => normalizeDomain(v), TypeError)
  }
})

test('refuses invalid TLDs', () => {
  assert.throws(() => normalizeDomain('example.c'), /top-level/)
  assert.throws(() => normalizeDomain('example.c0m'), /top-level/)
})

test('checkDomain returns a result object instead of throwing', () => {
  assert.deepEqual(checkDomain('example.com'), { ok: true, domain: 'example.com' })
  const r = checkDomain('1.2.3.4')
  assert.equal(r.ok, false)
  assert.match(r.reason, /IP address/)
})
