// Differential guard for signature-matching probes. A match only proves something if the
// signature was NOT already on the page before the attack. Fails closed: if the baseline cannot
// be fetched, the caller suppresses the finding. ScopeDeniedError is rethrown, never swallowed.

import { ScopeDeniedError } from './gate.mjs'

/**
 * @returns {Promise<boolean>} true when the signature is already present without the payload
 */
export async function signaturePreexists(get, baseUrl, signature) {
  try {
    const res = await get(baseUrl)
    // Fresh non-global copy so no lastIndex state leaks between calls.
    return new RegExp(signature.source, signature.flags.replace('g', '')).test(res.body)
  } catch (err) {
    if (err instanceof ScopeDeniedError) throw err
    return true
  }
}
