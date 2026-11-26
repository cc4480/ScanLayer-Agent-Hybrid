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

// There is deliberately NO environment-variable escape hatch here. The ownership gate used to be
// switchable with SCAN_SKIP_OWNERSHIP_GATE=true; that was removed on purpose (owner decision
// 2026-11-25) because an env var is not an authorization control: any process, profile, or session
// that inherited it could point active exploit probes at a domain nobody had proved they owned.
//
// The gate is now unconditionally fail-closed:
//   - loopback lab hosts are allowed (no real third-party target is reachable there), and
//   - every other domain must be ownership-verified by DNS TXT challenge.
//
// If a time-boxed bypass is ever needed for local development, it must not live in shipping code:
// point the tool at a loopback lab host instead, which needs no verification at all.
