// Harness tools for the red-team capabilities. Every tool that sends traffic to a target goes through an adapter that
// wraps the call in the verified-scope gate. The TypeScript adapters are loaded inside execute(), not at plugin load,
// so the plugin still loads when no TypeScript loader is present; a tool called without one returns an error.
import { defineTool } from '@deepseek-ai/dsh-tools'
import { checkDomain } from './engines/recon/domain.mjs'
import { dnsRecords, subdomainsFromPublicRecords } from './engines/recon/passive.mjs'
import { decideMsfScope } from './engines/metasploit/msf.mjs'

import { renderText } from './render.mjs'

const TEXT = { schema: { type: 'string' }, render: renderText }

/** Serialize a tool result. Errors come back as ok:false text, never as a thrown exception that hides the cause. */
function asText(value) {
  return JSON.stringify(value, (_k, v) => (v instanceof Error ? { error: v.message, code: v.code } : v), 2)
}

/** Parse "NAME=value NAME2=value2" into an options object. Values are validated later by the Metasploit grammar. */
export function parseOptionString(text) {
  const out = {}
  for (const tok of String(text ?? '').trim().split(/\s+/).filter(Boolean)) {
    const eq = tok.indexOf('=')
    if (eq <= 0) throw new Error(`option must be NAME=value, got ${tok}`)
    out[tok.slice(0, eq)] = tok.slice(eq + 1)
  }
  return out
}

/**
 * Build the tool list. `verifier` is the plugin's LocalDomainVerifier (must fail closed; it does).
 * @param {{isVerified: (domain: string) => Promise<boolean>}} verifier
 */
export function redteamTools(verifier) {
  const secscanFetch = defineTool({
    name: 'secscan_fetch',
    description: 'Fetch one target with the SecScan active-scan HTTP client (native). Every request and redirect hop is gated by verified scope. Returns the HTTP result, or complete=false with the refused hosts.',
    parameters: {
      url: { type: 'string', required: true, description: 'http(s) URL of a lab host or an ownership-verified domain.' },
    },
    output: TEXT,
    async execute(args) {
      const { scanTarget } = await import('./engines/secscan-network/adapter.mjs')
      return asText(await scanTarget(verifier, String(args.url)))
    },
  })

  const seclayerProbe = defineTool({
    name: 'seclayer_probe',
    description: 'Run one SecLayer active probe (sqlInjection | reflectedXss | commandInjection | ssrf) against a target URL, gated by verified scope. Returns the finding or null.',
    parameters: {
      probe: { type: 'string', required: true, description: 'One of: sqlInjection, reflectedXss, commandInjection, ssrf.' },
      url: { type: 'string', required: true, description: 'Target URL with the parameter to test, for example http://127.0.0.1:8080/item?id=1.' },
    },
    output: TEXT,
    async execute(args) {
      const { runActiveProbe } = await import('./engines/seclayer-network/adapter.mjs')
      const result = await runActiveProbe(String(args.probe), { url: String(args.url), fuzzHeaders: {} }, verifier)
      return asText(result)
    },
  })

  const metasploitScan = defineTool({
    name: 'msfconsole',
    description: 'Run one Metasploit auxiliary scanner module through msfconsole (native). Only auxiliary/scanner/* modules; every target option is gated by verified scope. Exploit, post and payload modules are refused.',
    parameters: {
      module: { type: 'string', required: true, description: 'Scanner module, for example auxiliary/scanner/portscan/tcp.' },
      options: { type: 'string', description: 'Space-separated NAME=value options, for example RHOSTS=127.0.0.1 PORTS=1-100.' },
    },
    output: TEXT,
    async execute(args) {
      const spec = { module: String(args.module), options: parseOptionString(args.options) }
      const decision = await decideMsfScope(spec, verifier)
      if (decision.kind !== 'allow') return asText({ status: 'denied', reason: decision.reason })
      const { runMsf } = await import('./engines/metasploit/msf.mjs')
      return asText(await runMsf(spec, { gate: verifier }))
    },
  })

  const reconPassive = defineTool({
    name: 'recon_passive',
    description: 'Passive reconnaissance for a domain: DNS records and certificate-transparency subdomains from public records. Sends no packets to the target itself.',
    parameters: {
      domain: { type: 'string', required: true, description: 'A bare domain name, for example example.com.' },
    },
    output: TEXT,
    async execute(args) {
      const checked = checkDomain(String(args.domain))
      if (!checked.ok) return asText({ error: checked.reason ?? 'not a valid domain' })
      const domain = checked.domain
      const [records, subdomains] = await Promise.all([dnsRecords(domain), subdomainsFromPublicRecords(domain)])
      return asText({ domain, records, subdomains })
    },
  })

  return [secscanFetch, seclayerProbe, metasploitScan, reconPassive]
}
