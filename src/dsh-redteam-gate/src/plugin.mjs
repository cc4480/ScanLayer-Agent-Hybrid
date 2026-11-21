// Harness plugin: installs the native verified-scope gate as a tools/pre-execute hook.
import { decideScope } from './scope.mjs'
import { LocalDomainVerifier } from './verifier.mjs'
import { nativeTools } from './tools.mjs'
import { redteamTools } from './redteam-tools.mjs'

export const name = 'dsh-redteam-gate'
export const inject = ['tools']

// Ownership is proven locally by DNS TXT challenge (scripts/verify-domain.mjs). No server, no MCP token.
// isVerified fails closed: an unreadable store or bad domain answers false.
const verifier = new LocalDomainVerifier()

export function apply(ctx) {
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

export const plugin = { name, inject, apply }
