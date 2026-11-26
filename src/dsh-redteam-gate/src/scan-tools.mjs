// Harness tool wrappers for the scan handlers. The handlers hold the logic; this file only adds the
// harness schema, the same way redteam-tools.mjs does for its tools.
import { defineTool } from '@deepseek-ai/dsh-tools'
import { renderText } from './render.mjs'
import { webappScanHandler, seclayerScanHandler, domainVerifyStartHandler, domainVerifyCheckHandler, generateScanReportHandler } from './scan-handlers.mjs'

// defineTool requires output.render; without it every call fails with "userRender is not a function".
const TEXT = { schema: { type: 'string' }, render: renderText }

/**
 * @param {{isVerified: (domain: string) => Promise<boolean>}} verifier
 */
export function scanTools(verifier) {
  const webappScan = defineTool({
    name: 'webapp_scan',
    description: 'Scan a website for security issues using the built-in VibeScan check catalog. No SecScan account or token is needed. The target domain must first be ownership-verified with domain_verify_start and domain_verify_check (DNS TXT); otherwise nothing is sent. Returns every finding with its evidence.',
    parameters: {
      url: { type: 'string', required: true, description: 'http(s) URL or bare hostname of the site to check.' },
      tier: { type: 'string', description: '"basic" (default) or "deep".' },
    },
    output: TEXT,
    async execute(args) {
      return webappScanHandler(args, verifier)
    },
  })

  const seclayerScan = defineTool({
    name: 'seclayer_scan',
    description: 'Scan a website with the built-in SecLayer diagnostics (passive checks, then active probes for verified targets). No SecLayer account or token is needed. Unverified domains are refused with zero packets sent; verify with domain_verify_start and domain_verify_check first. aggressive=true enables the aggressive tier.',
    parameters: {
      url: { type: 'string', required: true, description: 'http(s) URL or bare hostname of the site to check.' },
      aggressive: { type: 'boolean', description: 'Enable the aggressive probe tier (default false).' },
    },
    output: TEXT,
    async execute(args) {
      return seclayerScanHandler(args, verifier)
    },
  })

  const verifyStart = defineTool({
    name: 'domain_verify_start',
    description: 'Start ownership verification for a domain the user owns. Returns a DNS TXT record (name and value) to publish. No account or token is needed. Required before any scan of that domain.',
    parameters: {
      domain: { type: 'string', required: true, description: 'Bare domain the user owns, for example example.com.' },
    },
    output: TEXT,
    async execute(args) {
      return domainVerifyStartHandler(args, verifier)
    },
  })

  const verifyCheck = defineTool({
    name: 'domain_verify_check',
    description: 'Check the published DNS TXT record for a domain. On a match the domain becomes verified for scanning. Call after the user has published the record from domain_verify_start.',
    parameters: {
      domain: { type: 'string', required: true, description: 'Bare domain the user owns.' },
    },
    output: TEXT,
    async execute(args) {
      return domainVerifyCheckHandler(args, verifier)
    },
  })

  const generateReport = defineTool({
    name: 'generate_scan_report',
    description: 'Run a full security scan (SecLayer diagnostics plus, by default, the VibeScan check catalog) against one website and produce a single self-contained HTML report file (dark dashboard style: posture score, risk areas, pillar breakdown, network/attack-surface details, every finding with evidence and fix, and the full live scan ticker transcript). While it runs, each check is printed live as it happens ("[PROBE] -> SQL injection: firing...", "[CHECK] ..."), the same way the product\'s own scan console shows progress. No SecLayer or SecScan account or token is needed. The target must first be ownership-verified with domain_verify_start and domain_verify_check (DNS TXT), or be a loopback lab host; otherwise nothing is sent. Returns the path to the written HTML file.',
    parameters: {
      url: { type: 'string', required: true, description: 'http(s) URL or bare hostname of the site to check.' },
      aggressive: { type: 'boolean', description: 'Enable the aggressive probe tier (default false).' },
      tier: { type: 'string', description: 'VibeScan tier: "basic" (default) or "deep".' },
      includeWebapp: { type: 'boolean', description: 'Also run the VibeScan check catalog (default true). Set false to run SecLayer diagnostics only.' },
    },
    output: TEXT,
    async execute(args) {
      return generateScanReportHandler(args, verifier)
    },
  })

  return [webappScan, seclayerScan, verifyStart, verifyCheck, generateReport]
}
