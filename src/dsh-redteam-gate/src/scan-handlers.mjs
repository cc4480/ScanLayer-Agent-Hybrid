// Handlers behind the scan agent tools. No harness imports here, so these run and test without the
// harness build. The tool wrappers in scan-tools.mjs only add the harness schema.
import { gateScanTarget } from './scan-gate.mjs'

export function asText(value) {
  return JSON.stringify(value, (_k, v) => (v instanceof Error ? { error: v.message, code: v.code } : v), 2)
}

/** webapp_scan: VibeScan verbatim runScan, behind the ownership gate. Returns a JSON string. */
export async function webappScanHandler(args, verifier) {
  const gate = await gateScanTarget(args.url, verifier)
  if (!gate.ok) return asText({ status: 'refused', reason: gate.reason })
  const tier = args.tier === 'deep' ? 'deep' : 'basic'
  const { runScan } = await import('./engines/vibescan-core/artifacts/api-server/src/lib/scanner.ts')
  // The target passed the gate: active probes are allowed for this one scan.
  const result = await runScan(gate.url, tier, true, undefined, null, undefined, undefined)
  return asText({ status: 'complete', target: gate.host, lab: gate.lab, tier, result })
}

/** seclayer_scan: SecLayer verbatim runDiagnostics, behind the ownership gate. Returns a JSON string. */
export async function seclayerScanHandler(args, verifier) {
  const gate = await gateScanTarget(args.url, verifier)
  if (!gate.ok) return asText({ status: 'refused', reason: gate.reason })
  const aggressive = args.aggressive === true || args.aggressive === 'true'
  const { runDiagnostics } = await import('./engines/seclayer-core/server/scanner.ts')
  const result = await runDiagnostics(gate.url, undefined, { allowActiveProbes: true, allowAggressiveProbes: aggressive })
  return asText({ status: 'complete', target: gate.host, lab: gate.lab, aggressive, result })
}
