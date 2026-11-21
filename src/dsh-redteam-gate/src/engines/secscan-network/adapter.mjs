// Glue for the byte-identical network copies in this folder. The copies (cveCheckOsv.ts, cveCheckCore.ts,
// dnsChecksCore.ts, firebase-probes.ts, supabase-probes-core.ts, baasDepth.ts, baasEndpoints.ts, baasExposure.ts,
// httpBody.ts, httpTypes.ts, httpContext.ts, appOrigin.ts) are NOT edited. All glue lives in this file.
//
// Every entry point below runs its copied module inside withScopedFetch, so each outbound request is checked by
// the verified-scope gate (src/scope.mjs decideScope) before it is sent, and every redirect hop is checked too.
//
// The copies are TypeScript and import each other without file extensions, so this module must be loaded by a
// TypeScript-aware loader (vitest/vite in this package). Plain `node` cannot load it.
//
// Limit: the copied modules catch their own errors. A scope refusal therefore looks like "no result" to the
// module. Each entry point returns `refusedHosts` and `complete`; callers must check `complete` before trusting
// an empty result. Refusals of IP-literal targets are decided by decideScope without asking the verifier, so they
// are not listed in refusedHosts.
import { withScopedFetch } from '../guard/scoped-fetch.mjs'
import { queryOsv } from './cveCheckOsv.ts'
import { dnsQuery } from './dnsChecksCore.ts'
import { runFirebaseProbes } from './firebase-probes.ts'
import { probeSupabaseAuth } from './baasDepth.ts'
import { scanFetch } from './http.ts'

/**
 * Wrap the verifier so every host it is asked about is recorded when refused. A verifier that throws is treated as
 * a refusal, the same way decideScope treats it (fail closed).
 * @param {{isVerified: (domain: string) => Promise<boolean>}} verifier
 */
function recordingGate(verifier) {
  const refused = []
  const gate = {
    isVerified: async (domain) => {
      let ok = false
      try {
        ok = (await verifier.isVerified(domain)) === true
      } catch {
        ok = false
      }
      if (!ok) refused.push(domain)
      return ok
    },
  }
  return { gate, refused }
}

// Production hard-off. The source's private-target opt-outs are lab tools. In production (NODE_ENV=production)
// they must never take effect, so a process that sets one of them refuses to scan at all. Fails closed.
const LAB_OPT_OUT_VARS = ['SCAN_DEV_ALLOW_HOSTS', 'ALLOW_PRIVATE_SCAN_TARGETS']

export function productionLockdown(env = process.env) {
  if (env.NODE_ENV !== 'production') return
  const set = LAB_OPT_OUT_VARS.filter((name) => (env[name] ?? '').trim() !== '')
  if (set.length > 0) {
    throw new Error(`production lockdown: ${set.join(', ')} is set; lab opt-outs are not allowed when NODE_ENV=production`)
  }
}

/**
 * Run fn with global fetch guarded by the verified-scope gate.
 * @template T
 * @param {{isVerified: (domain: string) => Promise<boolean>}} verifier - the fake or real verifier; must fail closed
 * @param {() => Promise<T>} fn
 * @returns {Promise<{ value: T, refusedHosts: string[], complete: boolean }>}
 */
export async function runScoped(verifier, fn) {
  if (!verifier || typeof verifier.isVerified !== 'function') {
    throw new TypeError('runScoped: a verifier with isVerified() is required')
  }
  productionLockdown()
  const { gate, refused } = recordingGate(verifier)
  const value = await withScopedFetch(gate, fn)
  const refusedHosts = [...new Set(refused)]
  return { value, refusedHosts, complete: refusedHosts.length === 0 }
}

/** OSV.dev vulnerability lookup (copied cveCheckOsv.queryOsv). Endpoint: OSV_API_URL, else https://api.osv.dev. */
export function scanOsv(verifier, { packageName, version, ecosystem }) {
  return runScoped(verifier, () => queryOsv(packageName, version, ecosystem))
}

/** DNS TXT lookup over DNS-over-HTTPS (copied dnsChecksCore.dnsQuery). Endpoint: DOH_ENDPOINT_URL, else cloudflare. */
export function scanDnsTxt(verifier, name) {
  return runScoped(verifier, () => dnsQuery(name, 'TXT'))
}

/** Firebase Firestore / Realtime Database probes (copied firebase-probes.runFirebaseProbes). Returns findings in `value`. */
export function scanFirebase(verifier, content) {
  return runScoped(verifier, async () => {
    const findings = []
    await runFirebaseProbes(content, findings)
    return findings
  })
}

/** Supabase Auth settings probe (copied baasDepth.probeSupabaseAuth). Returns findings in `value`. */
export function scanSupabaseAuth(verifier, baseUrl, anonKey) {
  return runScoped(verifier, async () => {
    const findings = []
    await probeSupabaseAuth(baseUrl, anonKey, findings)
    return findings
  })
}

/**
 * Fetch one scan target through the copied active-scan HTTP client (http.ts scanFetch). Every request, and every
 * redirect hop, goes through withScopedFetch via runScoped, so a non-lab host is refused before it is sent.
 * The client also applies its own target check (ssrfGuard, pinnedDispatcher). Returns { value, refusedHosts, complete }:
 * value is the HttpResult or null; check `complete` before trusting a null.
 */
export function scanTarget(verifier, url, options = {}) {
  return runScoped(verifier, () => scanFetch(url, options))
}
