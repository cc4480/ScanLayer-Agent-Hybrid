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

// SCAN_SKIP_OWNERSHIP_GATE=true turns the DNS-TXT ownership gate OFF: the scanner then runs against any
// http/https target without verifying ownership first. This removes an authorization safety control, so
// it is for the operator's own authorized testing only. It is OFF unless the operator explicitly sets it,
// never a default, so the shipped code stays fail-closed and cannot be pointed at third-party sites by
// accident. Only an exact "true" (any case, trimmed) enables it.
export function ownershipGateDisabled(env = (typeof process !== 'undefined' ? process.env : {})) {
  return String(env.SCAN_SKIP_OWNERSHIP_GATE ?? '').trim().toLowerCase() === 'true'
}
