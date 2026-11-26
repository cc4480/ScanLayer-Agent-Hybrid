// Report template + ticker tests (pure, no engine/network calls). Run with:
// node --import tsx --test test/scan/report.test.mjs
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

/** A Finding-shaped fixture matching server/src/types.ts's Finding interface. */
function finding(overrides = {}) {
  return {
    id: 'f_1', title: 'Hardcoded API key', description: 'A live-looking key was found in source.',
    severity: 'critical', category: 'SAST', fix: 'Move to env vars.', ...overrides,
  }
}

function fakeData(overrides = {}) {
  return {
    aiReport: { score: 100, severity: 'info', findings: [], aiSummary: undefined, executiveBreakdown: undefined },
    evidence: { resolvedIp: '203.0.113.5', nameserver: 'ns1.example.test', protocol: 'HTTPS', responseStatus: 200, serverHeader: 'nginx' },
    grade: 'A',
    posture: { postureRating: 'SECURE' },
    coverage: { totalChecks: 10, items: [{ category: 'IAST', label: 'Headers', checks: 5, ran: true }] },
    change: null,
    pillarBadge: () => 'SECURE',
    ...overrides,
  }
}

test('report: renders with no engine data (degrades gracefully)', () => {
  const html = renderScanReportHtml({ target: 'example.test' })
  assert.match(html, /<!doctype html>/i)
  assert.match(html, /example\.test/)
  assert.match(html, /No engine result for this target/)
  assert.match(html, /No ticker output captured/)
})

test('report: renders the score circle, grade and posture from data', () => {
  const data = fakeData({ aiReport: { score: 72, findings: [], aiSummary: 'All clear.' } })
  const html = renderScanReportHtml({ target: 'mine.example', data })
  assert.match(html, />72</)
  assert.match(html, /GRADE A/)
  assert.match(html, /POSTURE RATING: SECURE/)
  assert.match(html, /All clear\./)
})

test('report: findings render with severity, fix, impact and a copy-fix-prompt button', () => {
  const findings = [finding({ impact: 'An attacker could read customer data.', agentPrompt: '# Security Fix Task\n...' })]
  const data = fakeData({ aiReport: { score: 60, findings, aiSummary: 'Issues found.' }, pillarBadge: () => 'CRITICAL' })
  const html = renderScanReportHtml({ target: 'mine.example', data })
  assert.match(html, /Hardcoded API key/)
  assert.match(html, /CRITICAL/)
  assert.match(html, /An attacker could read customer data\./)
  assert.match(html, /Copy Fix Prompt/)
  assert.match(html, /copyFix\(/)
})

test('report: escapes attacker-controlled strings (no HTML injection from finding text)', () => {
  const findings = [finding({ title: '<script>alert(1)</script>', description: '"><img src=x onerror=alert(1)>' })]
  const data = fakeData({ aiReport: { score: 50, findings, aiSummary: '' } })
  const html = renderScanReportHtml({ target: 'mine.example', data })
  assert.ok(!html.includes('<script>alert(1)</script>'))
  assert.ok(html.includes('&lt;script&gt;'))
})

test('report: executive breakdown (risk areas, business impact, priority actions) renders verbatim', () => {
  const data = fakeData({
    aiReport: {
      score: 65, findings: [],
      aiSummary: 'Moderate posture.',
      executiveBreakdown: {
        overview: 'Two gaps found.',
        riskAreas: [{ area: 'Dynamic Exploit Surface', detail: '1 finding(s), including "X".' }],
        businessImpact: 'Unlikely to cause an immediate breach.',
        priorityActions: ['Do the first thing.', 'Do the second thing.'],
      },
    },
  })
  const html = renderScanReportHtml({ target: 'mine.example', data })
  assert.match(html, /Two gaps found\./)
  assert.match(html, /Dynamic Exploit Surface/)
  assert.match(html, /Unlikely to cause an immediate breach\./)
  assert.match(html, /Do the first thing\./)
  assert.match(html, /BUSINESS IMPACT/)
  assert.match(html, /Priority Actions \(Ranked\)/)
})

test('report: "What changed since last scan" renders deltas when provided, and omits them on a first scan', () => {
  const noChange = renderScanReportHtml({ target: 'mine.example', data: fakeData() })
  assert.match(noChange, /first recorded scan/)
  const withChange = renderScanReportHtml({ target: 'mine.example', data: fakeData({ change: { scoreDelta: -4, newCount: 1, resolvedCount: 0, newFindings: [{ title: 'Cross-Tenant Access', severity: 'medium' }] } }) })
  assert.match(withChange, /-4 score/)
  assert.match(withChange, /Cross-Tenant Access/)
})

test('report: the AI badge only appears when aiReasoning is present (a real DeepSeek call ran)', () => {
  const local = renderScanReportHtml({ target: 'mine.example', data: fakeData({ aiReport: { score: 100, findings: [], aiSummary: 'ok' } }) })
  assert.ok(!local.includes('AI analyst'))
  const ai = renderScanReportHtml({ target: 'mine.example', data: fakeData({ aiReport: { score: 100, findings: [], aiSummary: 'ok', aiReasoning: 'because...' } }) })
  assert.ok(ai.includes('AI analyst'))
})

test('report: pillar grid shows every category with its real count and badge', () => {
  const findings = [finding({ category: 'DAST', severity: 'high' }), finding({ category: 'DAST', severity: 'low', title: 'second' })]
  const data = fakeData({ aiReport: { score: 70, findings, aiSummary: 'ok' }, pillarBadge: (cat) => (cat === 'DAST' ? 'HIGH RISK' : 'SECURE') })
  const html = renderScanReportHtml({ target: 'mine.example', data })
  assert.match(html, /id="pillar-dast"/)
  assert.match(html, /id="pillar-api-sec"/)
  assert.match(html, /HIGH RISK/)
})

test('report: hardening-gaps box names the single most severe active finding', () => {
  const findings = [finding({ severity: 'low', title: 'minor' }), finding({ severity: 'critical', title: 'Exposed .env' })]
  const data = fakeData({ aiReport: { score: 40, findings, aiSummary: 'ok' }, posture: { postureRating: 'CRITICAL' } })
  const html = renderScanReportHtml({ target: 'mine.example', data })
  assert.match(html, /CRITICAL HARDENING GAPS/)
  assert.match(html, /Exposed \.env/)
})

test('report: embeds the full ticker transcript', () => {
  const html = renderScanReportHtml({ target: 'mine.example', tickerLines: ['[SYSTEM] Starting scan...', '[PROBE] → SQLi: firing...'] })
  assert.match(html, /Starting scan/)
  assert.match(html, /SQLi: firing/)
  assert.match(html, /Scan log \(2 line\(s\)\)/)
})

// The report used to open with the raw remediation prompt, then a score, then
// three summary panels, and only reached the findings several screens down. The
// order is now the one a reader expects: contents, summary, findings, remediation,
// coverage, attack surface, evidence, log.
test('report: sections are ordered and reachable from the contents rail', () => {
  const html = renderScanReportHtml({ target: 'mine.example', data: fakeData({ fixPrompt: '# plan', aiReport: { score: 70, findings: [finding()], aiSummary: 'x' } }), tickerLines: ['[SYSTEM] x'] })
  const order = ['id="summary"', 'id="findings"', 'id="fixplan"', 'id="coverage"', 'id="surface"', 'id="evidence"', 'id="log"']
  const positions = order.map((needle) => html.indexOf(needle))
  positions.forEach((p, i) => assert.ok(p > 0, `missing section ${order[i]}`))
  for (let i = 1; i < positions.length; i++) {
    assert.ok(positions[i - 1] < positions[i], `${order[i - 1]} must precede ${order[i]}`)
  }
  // The contents rail links to every section it names.
  for (const id of ['summary', 'findings', 'fixplan', 'coverage', 'surface', 'evidence', 'log']) {
    assert.match(html, new RegExp(`href="#${id}"`), `contents rail is missing #${id}`)
  }
})

test('report: the findings table lists every finding, severity-ordered, linked to its detail card', () => {
  const findings = [
    finding({ severity: 'low', title: 'Minor thing' }),
    finding({ severity: 'critical', title: 'Worst thing' }),
    finding({ severity: 'medium', title: 'Middle thing' }),
  ]
  const html = renderScanReportHtml({ target: 'mine.example', data: fakeData({ aiReport: { score: 40, findings, aiSummary: 'x' } }) })
  assert.match(html, /<table class="summary">/)
  assert.ok(html.indexOf('Worst thing') < html.indexOf('Middle thing'), 'most severe first')
  assert.ok(html.indexOf('Middle thing') < html.indexOf('Minor thing'), 'most severe first')
  assert.match(html, /href="#finding-1"/)
  assert.match(html, /id="finding-1"/)
  assert.match(html, /id="finding-3"/)
})

test('report: network/coverage panels use evidence and coverage, not raw seclayer fields', () => {
  const seclayer = { probedPaths: [{ path: '/.env', exposed: false }], crawl: { pagesVisited: 5, endpointsDiscovered: 2, paramsTested: 9 }, scaLibraries: [{ name: 'lodash', status: 'vuln' }], easmPerimeter: { subdomains: [{ domain: 'www.mine.example', status: 'live' }] }, headers: { server: 'nginx' } }
  const html = renderScanReportHtml({ target: 'mine.example', seclayer, data: fakeData() })
  assert.match(html, /1 probed, all locked down/)
  assert.match(html, /5 page\(s\), 2 endpoint\(s\)/)
  assert.match(html, /lodash/)
  assert.match(html, /www\.mine\.example/)
  assert.match(html, /nginx/)
})

test('report: the remediation prompt follows the findings and is copyable', () => {
  const prompt = '# Security Remediation Plan — mine.example\n\n- Issues to fix: 1 — 1 high'
  const html = renderScanReportHtml({ target: 'mine.example', data: fakeData({ fixPrompt: prompt, aiReport: { score: 70, findings: [finding()], aiSummary: 'x' } }) })
  assert.match(html, /Complete fix prompt/i)
  assert.match(html, /paste into any AI coding agent/)
  assert.match(html, /id="complete-fix-prompt"/)
  assert.match(html, /Security Remediation Plan/)
  // It is a remediation appendix now, not the first thing a reader sees: after
  // the findings it explains, and before the coverage/evidence sections.
  assert.ok(html.indexOf('id="findings"') < html.indexOf('id="fixplan"'), 'remediation follows the findings')
  assert.ok(html.indexOf('id="fixplan"') < html.indexOf('id="coverage"'), 'remediation precedes coverage')
})

test('report: no fix-prompt panel when the scan found nothing to fix', () => {
  const html = renderScanReportHtml({ target: 'mine.example', data: fakeData() })
  assert.ok(!html.includes('Complete Fix Prompt'))
  assert.ok(!html.includes('complete-fix-prompt'))
})

test('report: diagnostic evidence is grouped into explained blocks, not one header dump', () => {
  const seclayer = {
    url: 'https://mine.example/login?x=1', finalUrl: 'https://mine.example/login?x=1', scannedAt: '2026-11-26T05:00:00.000Z',
    responseStatus: 200, sslSecure: true, activeProbesSkipped: false,
    headers: { server: 'nginx', 'content-security-policy': "default-src 'self'", 'x-frame-options': 'DENY' },
    missingHeaders: ['strict-transport-security'],
    tls: { checked: true, reachable: true, protocol: 'TLSv1.3', subject: 'mine.example', issuer: 'WE1', validFromMs: 1793640257000, validToMs: 1801419852000 },
    easmPerimeter: { ip: '203.0.113.5', nameserver: 'ns1.example.test', protocol: 'HTTPS', subdomains: [{ domain: 'www.mine.example', status: 'live', port: '443' }, { domain: 'dev.mine.example', status: 'inactive', port: '0' }] },
    probedPaths: [{ path: '/.env', status: 404, exposed: false }, { path: '/backup.zip', status: 200, exposed: true }],
    redTeamFindings: [{ testName: 'No rate limiting', payload: 'x', severity: 'medium', description: 'd', fix: 'f', confidence: 'medium' }],
    apiSecFindings: [], sastFindings: [], scaLibraries: [], cookieIssues: ['session cookie without HttpOnly'], setCookies: ['sid=abc; Path=/'],
    crawl: { pagesVisited: 4, endpointsDiscovered: 0, paramsTested: 19, sampleEndpoints: [] },
  }
  const data = fakeData({
    evidence: {
      scannedAt: '2026-11-26T05:00:00.000Z', responseStatus: 200, protocol: 'HTTPS',
      resolvedIp: '203.0.113.5', nameserver: 'ns1.example.test', serverHeader: 'nginx',
      presentSecurityHeaders: ['content-security-policy', 'x-frame-options'],
      missingSecurityHeaders: ['strict-transport-security'],
      liveSubdomains: ['www.mine.example'], subdomainsChecked: 2, probedPaths: seclayer.probedPaths,
      detectedLibraries: [], crawl: seclayer.crawl, activeProbesRun: true,
    },
  })
  const html = renderScanReportHtml({ target: 'mine.example', seclayer, data })
  // one labelled block per evidence family, each with its explanatory caption
  for (const title of ['Captured scan trace', 'HTTP response headers', 'EASM', 'DAST', 'Red team', 'SAST / SCA / template checks', 'Cookies']) {
    assert.ok(html.includes(title), `missing diagnostic block: ${title}`)
  }
  assert.match(html, /GET \/login\?x=1 HTTP\/1\.1/)
  assert.match(html, /Content-Security|content-security-policy/)
  assert.match(html, /TLSv1\.3/)
  assert.match(html, /strict-transport-security.*missing/s)
  assert.match(html, /backup\.zip/)
  assert.match(html, /EXPOSED/)
  assert.match(html, /locked down/)
  assert.match(html, /No rate limiting/)
  assert.match(html, /session cookie without HttpOnly/)
  assert.match(html, /dev\.mine\.example/)
  // captions say what the block is, and every block explains itself
  assert.match(html, /class="diag-note"/)
})

test('report: skipped active probes are stated plainly in the diagnostic section', () => {
  const seclayer = { activeProbesSkipped: true, headers: {}, probedPaths: [], easmPerimeter: { subdomains: [] } }
  const html = renderScanReportHtml({ target: 'mine.example', seclayer, data: fakeData() })
  assert.match(html, /Active exploit probing was skipped/)
})

test('report: a worsened finding is shown in the change box', () => {
  const data = fakeData({ change: { scoreDelta: -6, newCount: 0, resolvedCount: 0, worsenedCount: 1, newFindings: [], worsenedFindings: [{ title: 'Cross-Tenant Access', severity: 'high', was: 'medium' }] } })
  const html = renderScanReportHtml({ target: 'mine.example', data })
  assert.match(html, /WORSENED/)
  assert.match(html, /SEVERITY INCREASED/)
  assert.match(html, /was medium/)
})
