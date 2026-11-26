// Report template + ticker tests. Run with: node --import tsx --test test/scan/report.test.mjs
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { renderScanReportHtml } from '../../src/report-template.mjs'
import { createTicker } from '../../src/scan-ticker.mjs'

test('ticker: SecLayer events become [CHANNEL] lines and are buffered', () => {
  const lines = []
  const ticker = createTicker({ write: (l) => lines.push(l) })
  ticker.onSeclayerEvent('probe', '→ SQL injection: firing ?id=1\' OR 1=1-- ...')
  ticker.onSeclayerEvent('system', 'Active red-team probes — firing real exploit payloads...')
  assert.equal(lines.length, 2)
  assert.match(lines[0], /^\[PROBE\] →/)
  assert.match(lines[1], /^\[SYSTEM\]/)
  assert.deepEqual(ticker.lines(), lines)
})

test('ticker: VibeScan test records become [CHECK] lines', () => {
  const lines = []
  const ticker = createTicker({ write: (l) => lines.push(l) })
  ticker.onVibeTest({ group: 'HTTP probes', name: 'Header analysis', status: 'ran', findings: 1, detail: '12 headers checked' })
  ticker.onVibeTest({ group: 'HTTP probes', name: 'TLS grade', status: 'skipped', findings: 0, reason: 'not https' })
  assert.match(lines[0], /^\[CHECK\] HTTP probes \/ Header analysis - ran - 1 finding\(s\) - 12 headers checked/)
  assert.match(lines[1], /skipped.*not https/)
})

test('report: renders with no engine data (degrades gracefully)', () => {
  const html = renderScanReportHtml({ target: 'example.test' })
  assert.match(html, /<!doctype html>/i)
  assert.match(html, /example\.test/)
  assert.match(html, /No active findings/)
  assert.match(html, /No ticker output captured/)
})

test('report: SecLayer findings appear with severity, evidence and fix', () => {
  const seclayer = {
    sastFindings: [{ file: 'config.js', issue: 'Hardcoded API key', severity: 'critical', fix: 'Move to env vars.', description: 'A live-looking key was found in source.', masked: 'sk-***1234' }],
    scaLibraries: [{ name: 'lodash', version: '4.0.0', status: 'vuln', severity: 'high', advisories: ['CVE-2020-8203'], description: 'Prototype pollution.', fix: 'Upgrade to 4.17.21+.' }],
    probedPaths: [{ path: '/.env', status: 200, exposed: true, meta: { title: 'Exposed .env file', severity: 'critical', description: 'Environment file is public.', fix: 'Block access.' } }],
    missingHeaders: ['Content-Security-Policy'],
    cookieIssues: ['session cookie missing Secure flag'],
    easmPerimeter: { subdomains: [], ip: '203.0.113.5', nameserver: 'ns1.example.test', protocol: 'HTTPS' },
    headers: { server: 'nginx' },
  }
  const html = renderScanReportHtml({ target: 'mine.example', seclayer })
  assert.match(html, /Hardcoded API key/)
  assert.match(html, /CRITICAL/)
  assert.match(html, /sk-\*\*\*1234/)
  assert.match(html, /lodash 4\.0\.0/)
  assert.match(html, /Exposed \.env file/)
  assert.match(html, /203\.0\.113\.5/)
  assert.match(html, /ns1\.example\.test/)
})

test('report: escapes attacker-controlled strings (no HTML injection from finding text)', () => {
  const seclayer = { sastFindings: [{ issue: '<script>alert(1)</script>', severity: 'high', description: '"><img src=x onerror=alert(1)>' }] }
  const html = renderScanReportHtml({ target: 'mine.example', seclayer })
  assert.ok(!html.includes('<script>alert(1)</script>'))
  assert.ok(html.includes('&lt;script&gt;'))
})

test('report: posture score drops with severity and findings sort worst-first', () => {
  const clean = renderScanReportHtml({ target: 'a.example' })
  assert.match(clean, />100</)
  const seclayer = { sastFindings: [{ issue: 'low one', severity: 'low' }, { issue: 'critical one', severity: 'critical' }] }
  const html = renderScanReportHtml({ target: 'b.example', seclayer })
  const criticalPos = html.indexOf('critical one')
  const lowPos = html.indexOf('low one')
  assert.ok(criticalPos > 0 && lowPos > 0 && criticalPos < lowPos, 'critical finding should render before the low one')
})

test('report: embeds the full ticker transcript', () => {
  const html = renderScanReportHtml({ target: 'mine.example', tickerLines: ['[SYSTEM] Starting scan...', '[PROBE] → SQLi: firing...'] })
  assert.match(html, /Starting scan/)
  assert.match(html, /SQLi: firing/)
  assert.match(html, /Live Scan Ticker \(2 line\(s\)\)/)
})
