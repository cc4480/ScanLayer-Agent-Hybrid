// Ground-truth harness: runs the SecLayer engine against the planted-bug testbed
// and reports, per planted bug, whether the engine actually fired.
//
//   node run.mjs            # dump every finding the engine produced
//   node run.mjs --check    # diff against expected.json and exit non-zero on a miss
//
// Loopback is the lab-host path in the scope gate, so no DNS ownership proof is
// involved and nothing leaves the machine.
import { spawn } from 'node:child_process'
import { readFileSync, existsSync, rmSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const PORT = Number(process.env.PORT || 4599)
const URL_BASE = `http://127.0.0.1:${PORT}`

// The engine's SSRF guard allows loopback only when it is named explicitly.
process.env.NODE_ENV = process.env.NODE_ENV || 'development'
const LOCAL = [PORT, PORT + 1, PORT + 2].map((p) => `127.0.0.1:${p}`).join(',')
process.env.SCAN_DEV_ALLOW_HOSTS = `${process.env.SCAN_DEV_ALLOW_HOSTS ? process.env.SCAN_DEV_ALLOW_HOSTS + ',' : ''}${LOCAL}`

const check = process.argv.includes('--check')

function startApp() {
  const child = spawn(process.execPath, [path.join(HERE, 'vulnapp.mjs')], {
    env: { ...process.env, PORT: String(PORT) },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  child.stderr.on('data', (d) => process.stderr.write(`[testbed] ${d}`))
  return child
}

async function waitFor(url, tries = 60) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(url)
      if (r.status) return true
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100))
  }
  throw new Error(`testbed did not start at ${url}`)
}

const { scanSeclayer } = await import('../src/scan-adapters.mjs')
const { gateScanTarget } = await import('../src/scan-gate.mjs')
const { compileStaticFindings } = await import('../src/engines/seclayer-core/server/scanner.ts')
const { createOobCollaborator } = await import('../src/engines/seclayer-core/server/oob.ts')

// Out-of-band collaborator for the blind checks (XXE, blind SSRF). The testbed
// appends every callback to oob-hits.log; the store reads that file instead of
// making its own HTTP request, because a fetch issued while the engine's scoped
// fetch guard is installed stalled for ~80s inside the XXE poll.
const HITS = path.join(HERE, 'oob-hits.log')
const oobStore = {
  async registerOobToken() { /* the testbed records whatever token it is called on */ },
  async getOobEvents(token) {
    try {
      return readFileSync(HITS, 'utf8')
        .split('\n')
        .filter(Boolean)
        .map((line) => JSON.parse(line))
        .filter((e) => e.token === token)
    } catch {
      return []
    }
  },
}
const oob = createOobCollaborator(oobStore, `http://127.0.0.1:${PORT + 2}`)
try { rmSync(HITS, { force: true }) } catch { /* first run */ }

const app = startApp()
// Two targets: the app itself, and its raw-socket CRLF proxy (which exists only
// because Node's http layer refuses to emit a header containing CR/LF).
// TESTBED_ONE=1 scans only the app — the comparable "one deep scan" number.
const TARGETS = process.env.TESTBED_ONE
  ? [`http://127.0.0.1:${PORT}`]
  : [`http://127.0.0.1:${PORT}`, `http://127.0.0.1:${PORT + 1}`]
const diags = []
const ticker = []
try {
  await waitFor(`${URL_BASE}/`)
  for (const target of TARGETS) {
    const gate = await gateScanTarget(target, { isVerified: async () => false })
    if (!gate.ok) throw new Error(`gate refused the lab target ${target}: ${gate.reason}`)
    const started = Date.now()
    diags.push(await scanSeclayer({ isVerified: async () => false }, gate.url, {
      aggressive: true,
      oob: process.env.TESTBED_NO_OOB ? undefined : oob,
      emit: (channel, text) => {
        ticker.push(`[${gate.host}] [${channel}] ${text}`)
        if (process.env.TESTBED_TRACE) console.error(`[t] ${gate.host} ${channel} ${text.slice(0, 80)}`)
      },
    }))
    console.error(`[timing] ${gate.host} scanned in ${((Date.now() - started) / 1000).toFixed(1)}s`)
  }
} finally {
  app.kill()
}

const rows = []
for (const diag of diags) {
  const compiled = compileStaticFindings(diag)
  for (const f of (compiled.findings ?? []).filter((f) => !f.isFalsePositive)) rows.push({ src: 'scored', name: f.title, sev: f.severity, conf: f.confidence ?? '' })
  for (const f of diag.redTeamFindings ?? []) rows.push({ src: 'redteam', name: f.testName, sev: f.severity, conf: f.confidence ?? '' })
  for (const f of diag.apiSecFindings ?? []) rows.push({ src: 'api', name: f.testName, sev: f.severity, conf: f.confidence ?? '' })
  for (const f of diag.templateFindings ?? []) rows.push({ src: 'template', name: f.title, sev: f.severity, conf: f.confidence ?? '' })
  for (const f of diag.sastFindings ?? []) rows.push({ src: 'sast', name: f.issue, sev: f.severity, conf: f.confidence ?? '' })
  for (const c of diag.cookieIssues ?? []) rows.push({ src: 'cookie', name: c, sev: '', conf: '' })
  for (const h of diag.missingHeaders ?? []) rows.push({ src: 'header', name: `missing ${h}`, sev: '', conf: '' })
  for (const p of diag.probedPaths ?? []) if (p.exposed) rows.push({ src: 'path', name: `exposed ${p.path}`, sev: '', conf: '' })
}

const pad = (s, n) => String(s ?? '').padEnd(n).slice(0, n)
console.log(`\n=== ${rows.length} finding(s) from the testbed ===\n`)
console.log(`${pad('source', 9)} ${pad('severity', 9)} ${pad('confidence', 11)} finding`)
console.log('-'.repeat(96))
for (const r of rows.sort((a, b) => a.src.localeCompare(b.src))) {
  console.log(`${pad(r.src, 9)} ${pad(r.sev, 9)} ${pad(r.conf, 11)} ${r.name}`)
}

const expectedFile = path.join(HERE, 'expected.json')
if (process.argv.includes('--ticker')) {
  console.log('\n=== engine ticker (probe lines) ===\n')
  for (const line of ticker.filter((l) => /PROBE|rate.?limit|SSRF|injection|XSS|aggressive/i.test(l))) {
    console.log(line)
  }
}

if (check && existsSync(expectedFile)) {
  const expected = JSON.parse(readFileSync(expectedFile, 'utf8'))
  const haystack = rows.map((r) => r.name).join('\n')
  let miss = 0
  let fp = 0
  console.log('\n=== expectations ===\n')
  for (const e of expected.detect ?? []) {
    const hit = new RegExp(e.match, 'i').test(haystack)
    if (!hit) miss++
    console.log(`${hit ? 'PASS' : 'MISS'}  ${pad(e.match, 46)} ${e.bug}`)
  }
  for (const e of expected.clean ?? []) {
    const bad = new RegExp(e.match, 'i').test(haystack)
    if (bad) fp++
    console.log(`${bad ? 'FALSE-POSITIVE' : 'PASS'}  ${pad(e.match, 46)} ${e.bug}`)
  }
  console.log(`\n${expected.detect?.length ?? 0} detection checks, ${miss} missed; ${expected.clean?.length ?? 0} controls, ${fp} false positives`)
  process.exitCode = miss || fp ? 1 : 0
} else {
  console.log('\n(no --check: dumping only)')
}
