// Per-request scope gate around the verbatim scan cores.
//
// Every entry point runs its engine inside withScopedFetch, so each outbound request and each redirect
// hop is checked against the verified-scope gate before it is sent. assertScope runs first on the root
// target, so a refused target causes no request and no DNS lookup. Engines are TypeScript and load only
// under a TypeScript loader (tsx). The engine files are not edited.
import { withScopedFetch, assertScope } from './engines/guard/scoped-fetch.mjs'

const VIBESCAN_HTTP = './engines/vibescan-core/artifacts/api-server/src/lib/http.ts'
const VIBESCAN_SCANNER = './engines/vibescan-core/artifacts/api-server/src/lib/scanner.ts'
const SECLAYER_SCANNER = './engines/seclayer-core/server/scanner.ts'
const SECLAYER_PROBES = {
  sqlInjection: ['./engines/seclayer-core/server/redTeam/sqlInjection.ts', 'probeSqlInjection'],
  reflectedXss: ['./engines/seclayer-core/server/redTeam/reflectedXss.ts', 'probeReflectedXss'],
  commandInjection: ['./engines/seclayer-core/server/redTeam/commandInjection.ts', 'probeCommandInjection'],
  ssrf: ['./engines/seclayer-core/server/redTeam/ssrf.ts', 'probeSsrf'],
}

/**
 * Full VibeScan website scan (verbatim runScan). `tier` is "basic" or "deep".
 * `onTest`, when given, is the engine's own onTest callback: fired once per completed check
 * (see testLedger.ts's TestRecord), which is what drives a live ticker.
 */
export function scanWebapp(gate, url, tier, { onTest } = {}) {
  return withScopedFetch(gate, async () => {
    await assertScope(url, gate)
    const { runScan } = await import(VIBESCAN_SCANNER)
    return runScan(url, tier, true, undefined, null, onTest, undefined)
  })
}

/**
 * Full SecLayer diagnostics (verbatim runDiagnostics).
 * `emit`, when given, is the engine's own EmitFn (channel, text): fired for each recon/probe/system/
 * result step as it happens (see scanEvents.ts) — the exact live-ticker feed the product's own UI uses.
 */
export function scanSeclayer(gate, url, { aggressive = false, emit, oob } = {}) {
  return withScopedFetch(gate, async () => {
    await assertScope(url, gate)
    const { runDiagnostics } = await import(SECLAYER_SCANNER)
    return runDiagnostics(url, undefined, { allowActiveProbes: true, allowAggressiveProbes: aggressive, emit, oob })
  })
}

/** One HTTP fetch with the VibeScan active-scan client (verbatim scanFetch). */
export function fetchTarget(gate, url, options = {}) {
  return withScopedFetch(gate, async () => {
    await assertScope(url, gate)
    const { scanFetch } = await import(VIBESCAN_HTTP)
    return scanFetch(url, options)
  })
}

/** One SecLayer active probe (verbatim). Name is sqlInjection | reflectedXss | commandInjection | ssrf. */
export function runSeclayerProbe(gate, name, ctx) {
  const entry = SECLAYER_PROBES[name]
  if (!entry) return Promise.reject(new Error(`not an active probe: ${name}`))
  return withScopedFetch(gate, async () => {
    await assertScope(ctx.url, gate)
    const [file, fn] = entry
    const mod = await import(file)
    return mod[fn](ctx)
  })
}

export const ACTIVE_PROBE_NAMES = Object.freeze(Object.keys(SECLAYER_PROBES))
