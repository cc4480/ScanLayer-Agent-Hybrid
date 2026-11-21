// Glue for the verbatim SecLayer probes in ./server (byte-identical copies; see MANIFEST.json).
// This file lives OUTSIDE the copied tree on purpose: the probes are never edited.
//
// Every probe run is wrapped in withScopedFetch (src/engines/guard/scoped-fetch.mjs), so each HTTP request,
// and each redirect hop, is checked against the verified-scope gate before it is sent.
// Before any probe code runs, the probe's root target is checked with assertScope, so a refused target
// causes no request and no DNS lookup from ssrf.ts.
//
// The probes are TypeScript and import each other with ".js" paths. They load only under a TypeScript
// loader (tsx). The package has no TS loader in package.json, and package.json is not edited here.
import { withScopedFetch, assertScope } from '../guard/scoped-fetch.mjs'

// Probes that are NOT ported, with the reason. blindSsrf needs the out-of-band collaborator (ctx.oob),
// which is hosted on the Seclayer server. It is not faked here.
export const EXCLUDED = Object.freeze({
  blindSsrf: 'HOSTED: needs the out-of-band collaborator (ctx.oob); not ported and not faked',
})

async function loadActiveProbe(name) {
  switch (name) {
    case 'sqlInjection':
      return (await import('./server/redTeam/sqlInjection.ts')).probeSqlInjection
    case 'reflectedXss':
      return (await import('./server/redTeam/reflectedXss.ts')).probeReflectedXss
    case 'commandInjection':
      return (await import('./server/redTeam/commandInjection.ts')).probeCommandInjection
    case 'ssrf':
      return (await import('./server/redTeam/ssrf.ts')).probeSsrf
    default:
      throw new Error(`not a ported active probe: ${name}`)
  }
}

/**
 * Run one active probe (sqlInjection | reflectedXss | commandInjection | ssrf) under the scope gate.
 * @param {string} name
 * @param {{url: string, fuzzHeaders: Record<string,string>}} ctx
 * @param {{isVerified: (domain: string) => Promise<boolean>}} gate - must fail closed
 * @returns {Promise<object|null>} the probe's finding, or null
 * @throws {import('../guard/scoped-fetch.mjs').ScopeDeniedError} when the target is refused (no request sent)
 */
export function runActiveProbe(name, ctx, gate) {
  return withScopedFetch(gate, async () => {
    await assertScope(ctx.url, gate)
    const probe = await loadActiveProbe(name)
    return probe(ctx)
  })
}

/**
 * Run probeWeakSessionToken under the scope gate. The caller supplies the login target and the credentials.
 * @param {{url: string, method: string, params: string[], source: string, contentType?: string}} loginTarget
 * @param {{username: string, password: string}} credentials
 * @param {Record<string,string>} headers
 * @param {{isVerified: (domain: string) => Promise<boolean>}} gate - must fail closed
 */
export function runWeakSessionToken(loginTarget, credentials, headers, gate) {
  return withScopedFetch(gate, async () => {
    await assertScope(loginTarget.url, gate)
    const mod = await import('./server/redTeam/weakSessionToken.ts')
    return mod.probeWeakSessionToken(loginTarget, credentials, headers)
  })
}
