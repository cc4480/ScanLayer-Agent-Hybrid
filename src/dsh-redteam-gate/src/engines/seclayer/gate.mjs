// Scope-gated HTTP for the SecLayer red-team modules.
//
// Every request a module sends goes through decideScope() from src/scope.mjs before fetchFn is
// called. Loopback (lab) hosts pass; anything else must be verified through the injected gate,
// and the default gate fails closed (verifies nothing). A denied request throws ScopeDeniedError
// before any packet is sent. Modules never catch this error as "not vulnerable".

import { decideScope } from '../../scope.mjs'

// Scope checks use the active-tool branch of decideScope. Any ACTIVE_TOOLS member would do.
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
 * @param {typeof fetch} [cfg.fetchFn] fetch-compatible: (url, init) => Promise<Response-like>
 * @param {{isVerified: (domain: string) => Promise<boolean>}} [cfg.gate] must fail closed
 * @param {Record<string,string>} [cfg.headers]
 * @param {number} [cfg.timeoutMs]
 * @returns {(url: string) => Promise<{status: number, contentType: string, body: string}>}
 */
export function createScopedFetch({ fetchFn = globalThis.fetch, gate = FAIL_CLOSED_GATE, headers = {}, timeoutMs = 4000 } = {}) {
  return async function scopedGet(url) {
    const decision = await decideScope({ toolName: SCOPE_TOOL, arguments: { target: url } }, gate)
    if (decision.kind !== 'allow') throw new ScopeDeniedError(decision.reason)

    const ctl = new AbortController()
    const timer = setTimeout(() => ctl.abort(), timeoutMs)
    try {
      const res = await fetchFn(url, { headers, signal: ctl.signal, redirect: 'manual' })
      const body = await res.text()
      return { status: res.status, contentType: res.headers.get('content-type') ?? '', body }
    } finally {
      clearTimeout(timer)
    }
  }
}

/** Require an http(s) root URL and drop trailing slashes so probes can append "/?param=". */
export function normalizeTarget(target) {
  if (typeof target !== 'string' || !/^https?:\/\//i.test(target)) {
    throw new TypeError('target must be an http(s) URL')
  }
  return target.replace(/\/+$/, '')
}
