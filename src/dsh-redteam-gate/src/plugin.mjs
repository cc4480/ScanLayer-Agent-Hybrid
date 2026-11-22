// Harness plugin: installs the native verified-scope gate as a tools/pre-execute hook.
import { decideScope } from './scope.mjs'
import { LocalDomainVerifier } from './verifier.mjs'
import { nativeTools } from './tools.mjs'
import { redteamTools } from './redteam-tools.mjs'
import { alterEgoScopeDecision } from './alterego-scope.mjs'
import { alterEgoTools } from './engines/alterego/registry.mjs'

export const name = 'dsh-redteam-gate'
export const inject = ['tools']

/**
 * Bundle configuration. `labHosts` is the operator-visible form of the dev allowlist the ported
 * probes read from SCAN_DEV_ALLOW_HOSTS: the two guards below (the scope gate, which allows
 * loopback outright, and the SSRF guard inside the probes, which blocks it unless allowlisted)
 * only agree when the probe allowlist is set. apply() pushes this value into that variable so the
 * agreement comes from configuration instead of an ambient shell variable.
 */
// The harness validates a plugin's Config through the Standard Schema interface ('~standard', see
// vendor/cordis resolveConfig). A plain object without it fails at load with "reading 'validate'" and
// the whole plugin does not activate. This object implements that interface directly, so the gate needs
// no schema library. The labHosts entries are checked again by normalizeLabHosts in apply().
export const Config = {
  '~standard': {
    version: 1,
    vendor: 'dsh-redteam-gate',
    validate(input) {
      const raw = input && typeof input === 'object' ? input : {}
      const labHosts = Array.isArray(raw.labHosts) ? raw.labHosts.map((h) => String(h ?? '')) : []
      return { value: { labHosts } }
    },
  },
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
  // AlterEgo tools (ae_ prefix, generated catalog). They run without an approval prompt; scope still applies.
  for (const tool of alterEgoTools()) ctx.tools.register(tool)
  ctx.on('tools/pre-execute', async (exec, next) => {
    const decision = await decideScope(
      { toolName: exec.name, arguments: exec.arguments ?? {} },
      verifier,
    )
    if (decision.kind === 'deny') return decision
    const aeDecision = await alterEgoScopeDecision(exec, verifier)
    if (aeDecision.kind === 'deny') return aeDecision
    return next()
  })
}

export const plugin = { name, inject, Config, apply }
