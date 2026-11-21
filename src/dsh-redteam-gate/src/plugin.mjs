// Harness plugin: installs the native verified-scope gate as a tools/pre-execute hook.
import { decideScope } from './scope.mjs'
import { LocalDomainVerifier } from './verifier.mjs'
import { nativeTools } from './tools.mjs'
import { redteamTools } from './redteam-tools.mjs'

export const name = 'dsh-redteam-gate'
export const inject = ['tools']

/**
 * Bundle configuration. `labHosts` is the operator-visible form of the dev allowlist the ported
 * probes read from SCAN_DEV_ALLOW_HOSTS: the two guards below (the scope gate, which allows
 * loopback outright, and the SSRF guard inside the probes, which blocks it unless allowlisted)
 * only agree when the probe allowlist is set. apply() pushes this value into that variable so the
 * agreement comes from configuration instead of an ambient shell variable.
 */
export const Config = {
  labHosts: { type: 'array', items: { type: 'string' }, default: [] },
}

// Ownership is proven locally by DNS TXT challenge (scripts/verify-domain.mjs). No server, no MCP token.
// isVerified fails closed: an unreadable store or bad domain answers false.
const verifier = new LocalDomainVerifier()

// A lab host entry is "host" or "host:port": lowercase letters, digits, dots, hyphens, and an
// optional bracketed IPv6 literal. No scheme, path, credentials or whitespace.
const LAB_HOST_RE = /^(\[[0-9a-f:.]+\]|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::(\d{1,5}))?$/
const MAX_LAB_HOSTS = 32

/** Normalize and validate lab host entries. A malformed entry is dropped rather than guessed at. */
function normalizeLabHosts(raw) {
  if (!Array.isArray(raw)) return []
  const out = []
  for (const item of raw.slice(0, MAX_LAB_HOSTS)) {
    const host = String(item ?? '').trim().toLowerCase()
    const m = LAB_HOST_RE.exec(host)
    if (!m) continue
    // A port outside 1-65535 is a typo, not a host.
    if (m[2] !== undefined && (Number(m[2]) < 1 || Number(m[2]) > 65535)) continue
    out.push(host)
  }
  return [...new Set(out)]
}

export function apply(ctx, config = {}) {
  // Publish the declared lab hosts to the probe SSRF guard. Only additive: an operator who also
  // sets the variable out of band is not silently overridden when the bundle declares nothing.
  const labHosts = normalizeLabHosts(config?.labHosts)
  if (labHosts.length > 0) {
    process.env.SCAN_DEV_ALLOW_HOSTS = labHosts.join(',')
  }
  // Native scanners: each call still passes the scope gate below before it runs.
  for (const tool of nativeTools) ctx.tools.register(tool)
  // SecScan fetch, SecLayer probes, Metasploit scanner, passive recon. Each target-sending tool is gated inside its adapter.
  for (const tool of redteamTools(verifier)) ctx.tools.register(tool)
  ctx.on('tools/pre-execute', async (exec, next) => {
    const decision = await decideScope(
      { toolName: exec.name, arguments: exec.arguments ?? {} },
      verifier,
    )
    if (decision.kind === 'deny') return decision
    return next()
  })
}

export const plugin = { name, inject, Config, apply }
