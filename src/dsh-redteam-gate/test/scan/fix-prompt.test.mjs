// The Complete Fix Prompt is the "paste this into your coding agent" deliverable. These tests pin the
// properties that make it usable: empty when there is nothing to fix, severity-ordered, scoped to the
// real target, and carrying the engine's own per-finding work-order text rather than a paraphrase.
// Run with: node --import tsx --test test/scan/fix-prompt.test.mjs
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildCompleteFixPrompt } from '../../src/fix-prompt.mjs'

function finding(overrides = {}) {
  return {
    id: 'f1',
    title: 'No Rate Limiting on Authentication-Code Verification',
    severity: 'high',
    category: 'RED_TEAM',
    owasp: 'A05:2021',
    description: 'A verification endpoint accepted repeated wrong codes without throttling.',
    fix: 'Add per-account and per-IP attempt counters with backoff.',
    impact: 'An attacker can brute-force the one-time code.',
    endpoint: 'https://mine.example/api/auth/verify-code',
    confidence: 'medium',
    agentPrompt: '# Security Fix Task — No Rate Limiting\n\nENGINE-WRITTEN BODY',
    ...overrides,
  }
}

test('nothing to fix means no prompt at all', () => {
  assert.equal(buildCompleteFixPrompt({ target: 'mine.example', findings: [] }), '')
  assert.equal(buildCompleteFixPrompt({ target: 'mine.example', findings: [{ ...finding(), isFalsePositive: true }] }), '')
})

test('the plan names the target, the score, and a severity breakdown', () => {
  const prompt = buildCompleteFixPrompt({
    target: 'https://mine.example/',
    score: 76,
    postureRating: 'MODERATE',
    findings: [finding(), finding({ id: 'f2', title: 'Info leak', severity: 'info' })],
  })
  assert.match(prompt, /^# Security Remediation Plan — mine\.example/)
  assert.match(prompt, /found 2 issues to fix/)
  assert.match(prompt, /- Target \(black-box\): mine\.example/)
  assert.match(prompt, /- Security score: 76\/100 \(MODERATE\)/)
  assert.match(prompt, /- Issues to fix: 2 — 1 high, 1 info/)
  assert.match(prompt, /## How to work this plan/)
})

test('issues are listed most severe first, and each carries the engine work-order verbatim', () => {
  const prompt = buildCompleteFixPrompt({
    target: 'mine.example',
    score: 50,
    findings: [
      finding({ id: 'low', title: 'Minor hygiene', severity: 'low', agentPrompt: 'LOW BODY' }),
      finding({ id: 'crit', title: 'Exposed .env', severity: 'critical', agentPrompt: 'CRIT BODY' }),
    ],
  })
  const list = prompt.slice(prompt.indexOf('## Issues, most severe first'))
  assert.ok(list.indexOf('Exposed .env') < list.indexOf('Minor hygiene'), 'critical must be listed before low')
  const critAt = prompt.indexOf('## Issue 1 of 2 — Exposed .env')
  const lowAt = prompt.indexOf('## Issue 2 of 2 — Minor hygiene')
  assert.ok(critAt > 0 && lowAt > critAt, 'work-orders follow the same severity order')
  assert.ok(prompt.includes('CRIT BODY'), 'the engine-written body is embedded, not paraphrased')
  assert.ok(prompt.includes('LOW BODY'))
})

test('a finding with no agentPrompt gets a complete synthesized work-order', () => {
  const prompt = buildCompleteFixPrompt({
    target: 'mine.example',
    score: 80,
    findings: [finding({ agentPrompt: undefined })],
  })
  assert.match(prompt, /## The issue/)
  assert.match(prompt, /## Recommended fix/)
  assert.match(prompt, /Add per-account and per-IP attempt counters with backoff\./)
  assert.match(prompt, /## Work it in this order/)
  assert.match(prompt, /## Guardrails/)
  assert.match(prompt, /## Done when/)
  assert.match(prompt, /Affected endpoint: https:\/\/mine\.example\/api\/auth\/verify-code/)
})

test('a false positive is excluded from the plan and from the issue count', () => {
  const prompt = buildCompleteFixPrompt({
    target: 'mine.example',
    score: 90,
    findings: [finding(), finding({ id: 'fp', title: 'Not real', isFalsePositive: true })],
  })
  assert.match(prompt, /found 1 issue to fix/)
  assert.ok(!prompt.includes('Not real'))
})
