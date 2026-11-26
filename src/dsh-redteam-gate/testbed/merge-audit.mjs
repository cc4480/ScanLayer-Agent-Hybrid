// Audit: print exactly what goes into the merge and what comes out.
import { spawn } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const PORT = 4599
process.env.NODE_ENV = 'development'
process.env.SCAN_DEV_ALLOW_HOSTS = '127.0.0.1:4599,127.0.0.1:4600,127.0.0.1:4601,127.0.0.1:4602'
process.env.ALLOW_PRIVATE_SCAN_TARGETS = 'true'

const child = spawn(process.execPath, [path.join(HERE, 'vulnapp.mjs')], { env: { ...process.env, PORT: String(PORT) }, stdio: ['ignore', 'pipe', 'pipe'] })
for (let i = 0; i < 60; i++) {
  try { const r = await fetch(`http://127.0.0.1:${PORT}/`); if (r.status) break } catch {}
  await new Promise((r) => setTimeout(r, 100))
}

const { scanSeclayer, scanWebapp } = await import('../src/scan-adapters.mjs')
const { gateScanTarget } = await import('../src/scan-gate.mjs')
const { compileStaticFindings } = await import('../src/engines/seclayer-core/server/scanner.ts')
const { mergeEngines, issueKey } = await import('../src/engine-merge.mjs')

const gate = await gateScanTarget(`http://127.0.0.1:${PORT}/`, { isVerified: async () => false })
const verifier = { isVerified: async () => false }

const vscan = await scanWebapp(verifier, gate.url, 'deep')
const diag = await scanSeclayer(verifier, gate.url, { aggressive: true })
child.kill()

// --- the two INPUTS -------------------------------------------------------
const secscan = (vscan.vulnerabilities ?? []).map((v) => ({ name: v.name, severity: v.severity, confidence: v.confidence, category: v.category }))
const seclayerScored = (compileStaticFindings(diag).findings ?? []).filter((f) => !f.isFalsePositive)
  .map((f) => ({ name: f.title, severity: f.severity, confidence: f.confidence }))

console.log('SECSCAN input: runScan().vulnerabilities[]  count =', secscan.length)
console.log('  sample:', JSON.stringify(secscan[0]))
console.log('  fields per item:', Object.keys(vscan.vulnerabilities?.[0] ?? {}).join(','))
console.log('SECLAYER input: compileStaticFindings().findings[]  count =', seclayerScored.length)
console.log('  sample:', JSON.stringify(seclayerScored[0]))
console.log('  fields per item:', Object.keys((compileStaticFindings(diag).findings ?? [])[0] ?? {}).join(','))

// --- what the merge sees --------------------------------------------------
const feed = [
  ...secscan.map((f) => ({ engine: 'secscan', name: f.name, severity: f.severity, confidence: f.confidence })),
  ...seclayerScored.map((f) => ({ engine: 'seclayer', name: f.name, severity: f.severity, confidence: f.confidence })),
]
const { merged, dropped } = mergeEngines(feed)
console.log('\nINPUTS: ', feed.length, '= secscan', secscan.length, '+ seclayer', seclayerScored.length)
console.log('OUTPUT: ', merged.length, 'merged,', dropped.length, 'dropped')

// --- concrete decisions ---------------------------------------------------
console.log('\n--- sample decisions (SecScan wins, SecLayer duplicate dropped) ---')
const seen = new Set()
for (const d of dropped) {
  if (seen.has(d.key) || seen.size >= 6) continue
  seen.add(d.key)
  const base = merged.find((m) => m.key === d.key && m.engine === 'secscan')
  console.log(`key ${d.key}`)
  console.log(`   kept   secscan : ${base?.name}  [${base?.severity}]`)
  console.log(`   dropped seclayer: ${d.name}  [${d.severity}]  -> ${d.reason}`)
}

console.log('\n--- SecLayer findings kept because SecScan has no such check ---')
for (const m of merged.filter((x) => x.engine === 'seclayer' && !x.key)) console.log('  (no key) ', m.name, `[${m.severity}]`)
for (const m of merged.filter((x) => x.engine === 'seclayer' && x.key)) console.log('  ', m.key.padEnd(24), m.name, `[${m.severity}]`)
process.exit(0)
