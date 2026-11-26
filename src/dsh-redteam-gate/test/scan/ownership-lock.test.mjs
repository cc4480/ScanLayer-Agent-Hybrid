// The ownership gate is a hard control: no environment variable, config value, or session flag can
// switch it off. This suite is the regression guard for that promise — it fails if anyone ever
// reintroduces an escape hatch (the old SCAN_SKIP_OWNERSHIP_GATE was removed 2026-11-25).
// Run with: node --import tsx --test test/scan/ownership-lock.test.mjs
import { test } from 'node:test'
import assert from 'node:assert/strict'
import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs'
import { gateScanTarget } from '../../src/scan-gate.mjs'
import { decideScope } from '../../src/scope.mjs'
import { generateScanReportHandler } from '../../src/scan-handlers.mjs'
import { LocalDomainVerifier } from '../../src/verifier.mjs'

const storeFile = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'lock-')), 'v.json')
// A verifier that always says no, so any "allowed" result could only come from a bypass.
const neverVerified = () => new LocalDomainVerifier({ storeFile: storeFile(), resolveTxt: async () => [] })

// Every legacy escape-hatch name, set to the value that used to mean "off", for the whole test.
const LEGACY_BYPASS_ENV = {
  SCAN_SKIP_OWNERSHIP_GATE: 'true',
  ALLOW_UNVERIFIED_ACTIVE_PROBES: 'true',
  DEV_SKIP_DOMAIN_VERIFICATION: 'true',
}

function withLegacyBypassEnv(fn) {
  const saved = {}
  for (const [k, v] of Object.entries(LEGACY_BYPASS_ENV)) { saved[k] = process.env[k]; process.env[k] = v }
  return (async () => {
    try { return await fn() } finally {
      for (const k of Object.keys(LEGACY_BYPASS_ENV)) {
        if (saved[k] === undefined) delete process.env[k]
        else process.env[k] = saved[k]
      }
    }
  })()
}

test('scan-gate-helpers exposes no bypass predicate any more', async () => {
  const helpers = await import('../../src/scan-gate-helpers.mjs')
  assert.equal(helpers.ownershipGateDisabled, undefined, 'the bypass predicate must not exist')
})

test('legacy bypass env vars: an unverified domain is still refused with zero packets', () => withLegacyBypassEnv(async () => {
  const gate = await gateScanTarget('https://not-mine.example/', neverVerified())
  assert.equal(gate.ok, false)
  assert.match(gate.reason, /not ownership-verified/)
  assert.match(gate.reason, /Zero packets sent/)
}))

test('legacy bypass env vars: a raw public IP is still refused', () => withLegacyBypassEnv(async () => {
  const gate = await gateScanTarget('http://203.0.113.9/', neverVerified())
  assert.equal(gate.ok, false)
  assert.match(gate.reason, /IP target/)
}))

test('legacy bypass env vars: the pre-execute scope hook still denies an unverified target', () => withLegacyBypassEnv(async () => {
  for (const toolName of ['webapp_scan', 'seclayer_scan', 'generate_scan_report', 'secscan_fetch']) {
    const d = await decideScope({ toolName, arguments: { url: 'https://not-mine.example/' } }, neverVerified())
    assert.equal(d.kind, 'deny', `${toolName} must stay denied`)
  }
}))

test('legacy bypass env vars: generate_scan_report refuses and writes no file', () => withLegacyBypassEnv(async () => {
  const written = []
  const out = JSON.parse(await generateScanReportHandler({ url: 'https://not-mine.example/', tier: 'deep', aggressive: true }, neverVerified(), { write: (l) => written.push(l) }))
  assert.equal(out.status, 'refused')
  assert.equal(out.reportPath, undefined)
  assert.deepEqual(written, [], 'nothing was streamed, because nothing ran')
}))

test('the documented lab exception still works without verification', () => withLegacyBypassEnv(async () => {
  for (const url of ['http://127.0.0.1:8080/', 'http://localhost:3000/', 'http://[::1]:9000/']) {
    const gate = await gateScanTarget(url, neverVerified())
    assert.equal(gate.ok, true, url)
    assert.equal(gate.lab, true, url)
  }
}))
