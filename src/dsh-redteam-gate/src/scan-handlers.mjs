// Handlers behind the scan agent tools. No harness imports here, so these run and test without the
// harness build. The tool wrappers in scan-tools.mjs only add the harness schema.
import { gateScanTarget } from './scan-gate.mjs'
import { scanWebapp, scanSeclayer } from './scan-adapters.mjs'
import { normalizeDomain } from './verifier.mjs'

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
  return asText({ status: 'complete', target: gate.host, lab: gate.lab, tier, result })
}

/** seclayer_scan: SecLayer verbatim runDiagnostics, behind the ownership gate. Returns a JSON string. */
export async function seclayerScanHandler(args, verifier) {
  const gate = await gateScanTarget(args.url, verifier)
  if (!gate.ok) return asText({ status: 'refused', reason: gate.reason })
  const aggressive = args.aggressive === true || args.aggressive === 'true'
  const result = await scanSeclayer(verifier, gate.url, { aggressive })
  return asText({ status: 'complete', target: gate.host, lab: gate.lab, aggressive, result })
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
