import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mergeEngines, issueKey } from '../src/engine-merge.mjs'

test('the two engines name the same issue differently and still collapse to one', () => {
  // These are the real titles each engine emits for the same missing header.
  assert.equal(issueKey('Missing Content-Security-Policy (CSP)'), 'headers:csp')
  assert.equal(issueKey('Missing CSP Header'), 'headers:csp')
  assert.equal(
    issueKey('Cookie "sid" is set without the HttpOnly attribute'),
    'cookies:httponly',
  )
  assert.equal(issueKey('Session Cookie Missing HttpOnly Flag'), 'cookies:httponly')
})

test('SecScan is the base: a SecLayer duplicate is dropped, not merged', () => {
  const { merged, dropped } = mergeEngines([
    { engine: 'secscan', name: 'Missing Content-Security-Policy (CSP)', severity: 'high' },
    { engine: 'seclayer', name: 'Missing CSP Header', severity: 'medium' },
  ])
  assert.equal(merged.length, 1)
  assert.equal(merged[0].engine, 'secscan')
  assert.equal(dropped.length, 1)
  assert.equal(dropped[0].engine, 'seclayer')
  assert.match(dropped[0].reason, /already reported by SecScan/)
})

test('a SecLayer finding SecScan has no check for is always kept', () => {
  const { merged, dropped } = mergeEngines([
    { engine: 'secscan', name: 'Missing Content-Security-Policy (CSP)', severity: 'high' },
    { engine: 'seclayer', name: 'Active OS Command Injection', severity: 'critical' },
    { engine: 'seclayer', name: 'Blind Server-Side Request Forgery (out-of-band)', severity: 'critical' },
  ])
  assert.equal(dropped.length, 0)
  assert.deepEqual(merged.map((f) => f.engine), ['secscan', 'seclayer', 'seclayer'])
  assert.equal(merged.filter((f) => f.key === 'injection:cmdi').length, 1)
})

test('an unrecognised name is treated as SecLayer-only, never dropped', () => {
  // The safe direction: a mis-keyed finding is reported twice rather than lost.
  const { merged, dropped } = mergeEngines([
    { engine: 'secscan', name: 'Missing CSP Header', severity: 'high' },
    { engine: 'seclayer', name: 'Something Neither Map Knows About', severity: 'low' },
  ])
  assert.equal(dropped.length, 0)
  assert.equal(merged.length, 2)
  assert.equal(merged[1].key, null)
})

test('two SecLayer findings of the same kind collapse only if SecScan has that kind', () => {
  // No SecScan equivalent present → both SecLayer rows survive (different targets).
  const { merged, dropped } = mergeEngines([
    { engine: 'seclayer', name: 'Blind Server-Side Request Forgery (out-of-band)', severity: 'critical' },
    { engine: 'seclayer', name: 'Blind Server-Side Request Forgery (out-of-band)', severity: 'critical' },
  ])
  assert.equal(dropped.length, 0)
  assert.equal(merged.length, 2)

  // With a SecScan SSRF present, both SecLayer copies are dropped.
  const withBase = mergeEngines([
    { engine: 'secscan', name: 'Server-Side Request Forgery (SSRF)', severity: 'high' },
    { engine: 'seclayer', name: 'Blind Server-Side Request Forgery (out-of-band)', severity: 'critical' },
  ])
  assert.equal(withBase.merged.length, 1)
  assert.equal(withBase.dropped.length, 1)
})
