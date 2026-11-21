#!/usr/bin/env node
// Operator tool for local domain ownership (no SecScan server, no MCP token).
//   node scripts/verify-domain.mjs start <domain>   -> prints the TXT record to publish
//   node scripts/verify-domain.mjs check <domain>   -> reads TXT; records verification on match
//   node scripts/verify-domain.mjs list             -> lists verified domains
import { LocalDomainVerifier, VerificationStore, defaultStoreFile } from '../src/verifier.mjs'

const [cmd, arg] = process.argv.slice(2)
const v = new LocalDomainVerifier()

if (cmd === 'start' && arg) {
  const c = await v.start(arg)
  console.log(`Publish this TXT record, then run: check ${c.domain}`)
  console.log(`  name:  ${c.recordName}`)
  console.log(`  value: ${c.token}`)
} else if (cmd === 'check' && arg) {
  const r = await v.check(arg)
  console.log(r.reason)
  process.exitCode = r.verified ? 0 : 1
} else if (cmd === 'list') {
  const doc = await new VerificationStore(defaultStoreFile()).load()
  const names = Object.keys(doc.verified).sort()
  console.log(names.length ? names.join('\n') : '(none)')
} else {
  console.error('usage: verify-domain.mjs start|check <domain> | list')
  process.exitCode = 2
}
