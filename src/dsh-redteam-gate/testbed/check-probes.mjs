// Run individual probes directly against the live testbed and show what each saw.
import { probeSqlInjection } from '../src/engines/seclayer-core/server/redTeam/sqlInjection.ts'
import { probeCommandInjection } from '../src/engines/seclayer-core/server/redTeam/commandInjection.ts'
import { probeSsrf } from '../src/engines/seclayer-core/server/redTeam/ssrf.ts'
import { probeReflectedXss } from '../src/engines/seclayer-core/server/redTeam/reflectedXss.ts'
import { probeOpenRedirect } from '../src/engines/seclayer-core/server/aggressive/openRedirect.ts'
import { probeNoSql } from '../src/engines/seclayer-core/server/aggressive/nosql.ts'
import { probePathTraversal } from '../src/engines/seclayer-core/server/aggressive/pathTraversal.ts'
import { probeSsti } from '../src/engines/seclayer-core/server/aggressive/ssti.ts'
import { probeCors } from '../src/engines/seclayer-core/server/aggressive/cors.ts'
import { probeHostHeaderInjection } from '../src/engines/seclayer-core/server/aggressive/hostHeaderInjection.ts'

process.env.SCAN_DEV_ALLOW_HOSTS = '127.0.0.1:4599'
const ctx = { url: 'http://127.0.0.1:4599/', fuzzHeaders: { 'User-Agent': 'probe-test' } }

const probes = [
  ['sqli', probeSqlInjection], ['xss', probeReflectedXss], ['cmdi', probeCommandInjection],
  ['ssrf', probeSsrf], ['redirect', probeOpenRedirect], ['nosql', probeNoSql],
  ['lfi', probePathTraversal], ['ssti', probeSsti], ['cors', probeCors],
  ['hostheader', probeHostHeaderInjection],
]
for (const [name, fn] of probes) {
  try {
    const f = await fn(ctx)
    console.log(`${name.padEnd(11)} ${f ? 'FINDING  ' + f.testName : 'null (no signal)'}`)
  } catch (e) {
    console.log(`${name.padEnd(11)} THREW ${e.message.slice(0, 90)}`)
  }
}
