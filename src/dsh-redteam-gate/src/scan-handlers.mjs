// Handlers behind the scan agent tools. No harness imports here, so these run and test without the
// harness build. The tool wrappers in scan-tools.mjs only add the harness schema.
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { gateScanTarget } from './scan-gate.mjs'
import { scanWebapp, scanSeclayer } from './scan-adapters.mjs'
import { normalizeDomain } from './verifier.mjs'
import { createTicker } from './scan-ticker.mjs'
import { renderScanReportHtml } from './report-template.mjs'
import { buildSeclayerReportData } from './report-data.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const REPORTS_DIR = path.join(HERE, '..', 'reports')

export function asText(value) {
  return JSON.stringify(value, (_k, v) => (v instanceof Error ? { error: v.message, code: v.code } : v), 2)
}

/** webapp_scan: VibeScan verbatim runScan, behind the ownership gate. Returns a JSON string. */
export async function webappScanHandler(args, verifier) {
  const gate = await gateScanTarget(args.url, verifier)
  if (!gate.ok) return asText({ status: 'refused', reason: gate.reason })
  const tier = args.tier === 'deep' ? 'deep' : 'basic'
  // Every request the engine makes is re-checked by the gate (per request and per redirect hop).
  const result = await scanWebapp(verifier, gate.url, tier)
  return asText({ status: 'complete', target: gate.host, lab: gate.lab, unverified: gate.unverified === true, tier, result })
}

/** seclayer_scan: SecLayer verbatim runDiagnostics, behind the ownership gate. Returns a JSON string. */
export async function seclayerScanHandler(args, verifier) {
  const gate = await gateScanTarget(args.url, verifier)
  if (!gate.ok) return asText({ status: 'refused', reason: gate.reason })
  const aggressive = args.aggressive === true || args.aggressive === 'true'
  const result = await scanSeclayer(verifier, gate.url, { aggressive })
  return asText({ status: 'complete', target: gate.host, lab: gate.lab, unverified: gate.unverified === true, aggressive, result })
}

/** domain_verify_start: issue the DNS TXT challenge the user publishes for a domain they own. */
export async function domainVerifyStartHandler(args, verifier) {
  const d = normalizeDomain(String(args.domain ?? ''))
  if (!d) return asText({ status: 'error', reason: 'not a usable domain (for example example.com)' })
  const c = await verifier.start(d)
  return asText({
    status: 'challenge_issued',
    domain: c.domain,
    txt_record_name: c.recordName,
    txt_record_value: c.token,
    next: 'Publish this TXT record in the DNS for the domain, then call domain_verify_check.',
  })
}

/** domain_verify_check: read the TXT record and record ownership when the token matches. */
export async function domainVerifyCheckHandler(args, verifier) {
  const d = normalizeDomain(String(args.domain ?? ''))
  if (!d) return asText({ status: 'error', reason: 'not a usable domain (for example example.com)' })
  const r = await verifier.check(d)
  return asText({ status: r.verified ? 'verified' : 'not_verified', domain: r.domain, reason: r.reason })
}

/**
 * generate_scan_report: runs the SecLayer diagnostics (and, unless skipped, the VibeScan check catalog)
 * against one target behind the ownership gate, streaming a live ticker from each engine's own progress
 * callback as it runs, then writes a single self-contained HTML report (dark dashboard style) to
 * reports/<host>-<timestamp>.html and returns its path plus a short summary. No SecLayer or SecScan
 * account or token is needed; the engines run locally, verbatim.
 */
export async function generateScanReportHandler(args, verifier, { write = (line) => console.log(line) } = {}) {
  const gate = await gateScanTarget(args.url, verifier)
  if (!gate.ok) return asText({ status: 'refused', reason: gate.reason })

  const aggressive = args.aggressive === true || args.aggressive === 'true'
  const includeWebapp = args.includeWebapp !== false && args.includeWebapp !== 'false'
  const tier = args.tier === 'deep' ? 'deep' : 'basic'

  const ticker = createTicker({ write })
  write(`[SYSTEM] Starting scan of ${gate.host} (SecLayer${includeWebapp ? ' + VibeScan' : ''})...`)

  const seclayer = await scanSeclayer(verifier, gate.url, { aggressive, emit: ticker.onSeclayerEvent })
  const vibescan = includeWebapp ? await scanWebapp(verifier, gate.url, tier, { onTest: ticker.onVibeTest }) : undefined
  write('[SYSTEM] Scan complete. Compiling findings and executive summary...')

  // Real score/grade/posture/executive-summary pipeline (compileStaticFindings, generateAiReport,
  // compileScanEvidence, scoring.ts) — not re-implemented here, just called.
  const data = await buildSeclayerReportData(gate.url, seclayer)
  write('[SYSTEM] Report ready.')

  const html = renderScanReportHtml({ target: gate.host, seclayer, vibescan, data, tickerLines: ticker.lines() })

  fs.mkdirSync(REPORTS_DIR, { recursive: true })
  const stamp = new Date().toISOString().replace(/[:.]/g, '-')
  const fileName = `${gate.host.replace(/[^a-z0-9.-]/gi, '_')}-${stamp}.html`
  const filePath = path.join(REPORTS_DIR, fileName)
  fs.writeFileSync(filePath, html, 'utf8')

  return asText({
    status: 'complete',
    target: gate.host,
    lab: gate.lab,
    unverified: gate.unverified === true,
    reportPath: filePath,
    tickerLineCount: ticker.lines().length,
  })
}
