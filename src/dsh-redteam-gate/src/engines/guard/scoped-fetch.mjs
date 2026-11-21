// Scoped fetch guard: lets UNMODIFIED source modules that call global fetch run inside the verified-scope gate.
//
// withScopedFetch(gate, fn) swaps globalThis.fetch for a gated version for the duration of fn(), then restores it.
//   - Every request is checked with decideScope before it is sent. A denial throws ScopeDeniedError and sends nothing.
//   - Redirects are followed here, one hop at a time, and every hop is checked. fetch's own redirect following
//     would reach hosts the gate never saw, so it is not used for the 'follow' mode.
//   - Runs are serialized: the swap is process-wide, so two runs at once would gate each other's traffic.
//
// Limits (documented, not hidden): this covers global fetch and everything built on it (undici dispatchers
// included). It does NOT cover raw node:net / node:tls / node:dns / node:http sockets; modules that use those must
// be ported behind an explicit gate, not run through this guard.
import { decideScope } from '../../scope.mjs'

export class ScopeDeniedError extends Error {
  constructor(reason, url) {
    super(reason)
    this.name = 'ScopeDeniedError'
    this.code = 'SCOPE_DENIED'
    this.url = url
  }
}

const MAX_REDIRECTS = 10
let queue = Promise.resolve()

function urlOf(input) {
  if (typeof input === 'string') return input
  if (input instanceof URL) return input.href
  if (input && typeof input.url === 'string') return input.url
  throw new TypeError('fetch input must be a string, URL or Request')
}

/**
 * Check one URL against the gate. Throws ScopeDeniedError before any network activity.
 * @param {string} rawUrl
 * @param {{isVerified: (domain: string) => Promise<boolean>}} gate
 */
export async function assertScope(rawUrl, gate) {
  let u
  try {
    u = new URL(rawUrl)
  } catch {
    throw new ScopeDeniedError(`not a URL: ${rawUrl}`, rawUrl)
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new ScopeDeniedError(`scheme ${u.protocol} is not allowed`, rawUrl)
  }
  const decision = await decideScope({ toolName: 'nuclei', arguments: { target: rawUrl } }, gate)
  if (decision.kind === 'deny') throw new ScopeDeniedError(decision.reason, rawUrl)
}

/**
 * Build the gated fetch around an original fetch. Exported so tests can exercise it directly.
 * @param {{isVerified: (domain: string) => Promise<boolean>}} gate
 * @param {typeof fetch} original
 * @returns {typeof fetch}
 */
export function makeGuardedFetch(gate, original) {
  return async function guardedFetch(input, init) {
    const requestRedirect = input !== null && typeof input === 'object' && typeof input.redirect === 'string' ? input.redirect : undefined
    const callerRedirect = typeof init?.redirect === 'string' ? init.redirect : (requestRedirect ?? 'follow')
    let url = urlOf(input)
    await assertScope(url, gate)

    // The caller handles redirects itself ('manual') or wants fetch to fail on them ('error'): pass through,
    // and each caller-driven hop comes back through this guard anyway.
    if (callerRedirect !== 'follow') return original(input, init)

    let method = (init?.method ?? (input && input.method) ?? 'GET').toUpperCase()
    let body = init?.body
    let current = input
    for (let hop = 0; ; hop++) {
      const res = await original(current, { ...(init ?? {}), method, body, redirect: 'manual' })
      const location = res.headers.get('location')
      if (!(res.status >= 300 && res.status < 400 && location)) return res
      if (hop >= MAX_REDIRECTS) throw new Error(`too many redirects (>${MAX_REDIRECTS})`)
      const next = new URL(location, url).href
      await assertScope(next, gate)
      if (res.status === 303 || ((res.status === 301 || res.status === 302) && method === 'POST')) {
        method = 'GET'
        body = undefined
      }
      url = next
      current = next
    }
  }
}

/**
 * Run fn with global fetch guarded by the gate. Runs are serialized.
 * @template T
 * @param {{isVerified: (domain: string) => Promise<boolean>}} gate - must fail closed
 * @param {() => Promise<T>} fn
 * @returns {Promise<T>}
 */
export function withScopedFetch(gate, fn) {
  if (!gate || typeof gate.isVerified !== 'function') {
    throw new TypeError('withScopedFetch needs a gate with isVerified')
  }
  const run = queue.then(async () => {
    const original = globalThis.fetch
    globalThis.fetch = makeGuardedFetch(gate, original)
    try {
      return await fn()
    } finally {
      globalThis.fetch = original
    }
  })
  queue = run.catch(() => {})
  return run
}
