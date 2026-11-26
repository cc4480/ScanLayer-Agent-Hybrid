// Harness tool wrappers for the scan handlers. The handlers hold the logic; this file only adds the
// harness schema, the same way redteam-tools.mjs does for its tools.
import { defineTool } from '@deepseek-ai/dsh-tools'
import { webappScanHandler, seclayerScanHandler } from './scan-handlers.mjs'

const TEXT = { schema: { type: 'string' } }

/**
 * @param {{isVerified: (domain: string) => Promise<boolean>}} verifier
 */
export function scanTools(verifier) {
  const webappScan = defineTool({
    name: 'webapp_scan',
    description: 'Run the full VibeScan website check catalog against one URL (verbatim engine). The target must be ownership-verified (DNS TXT) or a loopback lab host; otherwise nothing is sent. Returns the scan result with every finding and its evidence.',
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
    description: 'Run the full SecLayer diagnostics (verbatim engine: passive checks, then active probes for verified targets) against one URL. Unverified targets are refused with zero packets sent. The aggressive tier requires aggressive=true.',
    parameters: {
      url: { type: 'string', required: true, description: 'http(s) URL or bare hostname of the site to check.' },
      aggressive: { type: 'boolean', description: 'Enable the aggressive probe tier (default false).' },
    },
    output: TEXT,
    async execute(args) {
      return seclayerScanHandler(args, verifier)
    },
  })

  return [webappScan, seclayerScan]
}
