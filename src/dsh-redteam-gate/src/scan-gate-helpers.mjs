// Pure helpers for the scan gate (no I/O), kept separate so they can be unit-tested directly.
export const LOOPBACK = new Set(['localhost', '127.0.0.1', '::1'])

export function isLoopbackHostname(host) {
  const h = String(host ?? '').toLowerCase().replace(/^\[|\]$/g, '')
  return LOOPBACK.has(h) || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)
}

/** Lowercase domain without a trailing dot; null when the value is not a plausible hostname. */
export function normalizeDomain(host) {
  const h = String(host ?? '').trim().toLowerCase().replace(/\.$/, '')
  return /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/.test(h) ? h : null
}
