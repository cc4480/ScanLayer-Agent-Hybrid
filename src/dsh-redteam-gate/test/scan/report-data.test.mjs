// report-data.mjs calls the REAL SecLayer engine functions (compileStaticFindings, generateAiReport,
// compileScanEvidence, scoring.ts). DEEPSEEK_API_KEY is cleared for these tests so generateAiReport
// takes its own documented local-mode fallback path (no network call), which keeps this suite fast,
// deterministic, and runnable offline — the exact same code path the real app uses when no key is
// configured. Run with: node --import tsx --test test/scan/report-data.test.mjs
import { test } from 'node:test'
import assert from 'node:assert/strict'
import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs'
import { buildSeclayerReportData } from '../../src/report-data.mjs'

function withNoDeepSeekKey(fn) {
  const prev = process.env.DEEPSEEK_API_KEY
  delete process.env.DEEPSEEK_API_KEY
  return (async () => { try { return await fn() } finally { if (prev !== undefined) process.env.DEEPSEEK_API_KEY = prev } })()
}

/** A minimal-but-realistic DiagnosticResult. */
function diag(overrides = {}) {
  return {
    url: 'https://mine.example/', scannedAt: new Date().toISOString(), responseStatus: 200,
    sslSecure: true, headers: { server: 'nginx' }, missingHeaders: [], techLeaked: [],
    probedPaths: [], cookieIssues: [], cookieEvidence: {},
    sastFindings: [], scaLibraries: [], easmPerimeter: { subdomains: [], ip: '203.0.113.5', nameserver: 'ns1.example.test', protocol: 'HTTPS' },
    redTeamFindings: [], apiSecFindings: [], activeProbesSkipped: false,
    coverage: { totalChecks: 10, activeProbesRun: true, aggressiveProbesRun: false, items: [{ label: 'Headers', category: 'IAST', checks: 5, ran: true }] },
    ...overrides,
  }
}

test('a clean target (no findings) scores 100, grades A, postures SECURE, local-mode (no network)', () => withNoDeepSeekKey(async () => {
  const data = await buildSeclayerReportData('https://mine.example/', diag())
  assert.equal(data.aiReport.score, 100)
  assert.equal(data.grade, 'A')
  assert.equal(data.posture.postureRating, 'SECURE')
  assert.equal(data.aiReport.findings.length, 0)
  assert.ok(data.aiReport.aiSummary, 'local-mode still produces a summary string')
  assert.equal(data.aiReport.aiReasoning, undefined, 'local-mode never sets aiReasoning')
}))

test('a critical SAST finding drops the score and grade, and the pillar badge reflects it', () => withNoDeepSeekKey(async () => {
  const d = diag({ sastFindings: [{ file: 'config.js', issue: 'Hardcoded API key', severity: 'critical', fix: 'Move to env.', description: 'A live key leaked.' }] })
  const data = await buildSeclayerReportData('https://mine.example/', d)
  assert.ok(data.aiReport.score < 100, `score should drop, got ${data.aiReport.score}`)
  assert.notEqual(data.grade, 'A')
  assert.notEqual(data.posture.postureRating, 'SECURE')
  const sastFinding = data.aiReport.findings.find((f) => f.category === 'SAST')
  assert.ok(sastFinding, 'the SAST finding made it through compileStaticFindings')
  assert.equal(data.pillarBadge('SAST'), 'CRITICAL')
  assert.equal(data.pillarBadge('DAST'), 'SECURE', 'an untouched pillar stays SECURE')
}))

test('compileScanEvidence surfaces the real network facts (IP, nameserver, server header)', () => withNoDeepSeekKey(async () => {
  const data = await buildSeclayerReportData('https://mine.example/', diag())
  assert.equal(data.evidence.resolvedIp, '203.0.113.5')
  assert.equal(data.evidence.nameserver, 'ns1.example.test')
  assert.equal(data.evidence.serverHeader, 'nginx')
}))

test('coverage passes through from the engine result unchanged', () => withNoDeepSeekKey(async () => {
  const d = diag()
  const data = await buildSeclayerReportData('https://mine.example/', d)
  assert.equal(data.coverage, d.coverage)
}))

test('first scan of a host has no "what changed" baseline; a second scan reports the real delta', () => withNoDeepSeekKey(async () => {
  const host = `test-${Date.now()}.example`
  const url = `https://${host}/`
  const first = await buildSeclayerReportData(url, diag())
  assert.equal(first.change, null)

  const second = await buildSeclayerReportData(url, diag({ sastFindings: [{ file: 'a.js', issue: 'New leak', severity: 'high', fix: 'fix it', description: 'desc' }] }))
  assert.ok(second.change, 'second scan of the same host has a baseline to diff against')
  assert.equal(second.change.newCount, 1)
  assert.equal(second.change.resolvedCount, 0)
  assert.ok(second.change.scoreDelta < 0, 'score dropped, delta should be negative')
  assert.equal(second.change.newFindings[0].title, 'New leak')

  // cleanup the state sidecar so repeat test runs don't see a stale baseline
  const stateFile = path.join(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]):/, '$1:')), '..', '..', 'reports', '.state', `${host}.json`)
  fs.rmSync(stateFile, { force: true })
}))
