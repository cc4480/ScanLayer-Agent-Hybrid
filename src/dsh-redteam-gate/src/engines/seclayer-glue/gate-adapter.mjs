// Glue for the verbatim SecLayer copy (engines/seclayer-src). Lives OUTSIDE the copied tree on
// purpose: the copied files are byte-identical to the source and are never edited.
//
// Wraps an injected fetch-compatible function so every request first passes decideScope() from
// src/scope.mjs. A denied request throws before fetchFn is called, so no packet is sent.

import { decideScope } from '../../scope.mjs'

export const SCOPE_TOOL = 'nuclei'

const FAIL_CLOSED_GATE = Object.freeze({ isVerified: async () => false })

export class ScopeDeniedError extends Error {
  constructor(reason) {
    super(`scope denied: ${reason}`)
    this.name = 'ScopeDeniedError'
    this.reason = reason
  }
}

/**
 * @param {object} cfg
 * @param {(url: string, init?: object) => Promise<Response>} cfg.fetchFn real fetch-compatible function
 * @param {{isVerified: (domain: string) => Promise<boolean>}} [cfg.gate] must fail closed; default verifies nothing
 * @returns {(url: string, init?: object) => Promise<Response>}
 */
export function createGatedFetch({ fetchFn, gate = FAIL_CLOSED_GATE } = {}) {
  if (typeof fetchFn !== 'function') throw new TypeError('createGatedFetch: fetchFn is required')
  return async function gatedFetch(url, init = {}) {
    const decision = await decideScope({ toolName: SCOPE_TOOL, arguments: { target: String(url) } }, gate)
    if (decision.kind !== 'allow') throw new ScopeDeniedError(decision.reason)
    return fetchFn(url, init)
  }
}
