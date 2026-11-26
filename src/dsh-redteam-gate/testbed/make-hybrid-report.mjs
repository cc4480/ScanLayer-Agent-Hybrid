// Produce ONE HTML report from both engines and write it to hybrid-report.html.
// This is the interface half of the merge: one page, SecScan's catalog findings and
// SecLayer's exploit proofs, deduped, with the full description/evidence/fix.
import { spawn } from 'node:child_process'
import { writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const PORT = 4599
process.env.NODE_ENV = 'development'
process.env.SCAN_DEV_ALLOW_HOSTS = '127.0.0.1:4599,127.0.0.1:4600,127.0.0.1:4601,127.0.0.1:4602'
process.env.ALLOW_PRIVATE_SCAN_TARGETS = 'true'

const child = spawn(process.execPath, [path.join(HERE, 'vulnapp.mjs')], { env: { ...process.env, PORT: String(PORT) }, stdio: ['ignore', 'pipe', 'pipe'] })
for (let i = 0; i < 80; i++) {
  try { const r = await fetch(`http://127.0.0.1:${PORT}/`); if (r.status) break } catch {}
  await new Promise((r) => setTimeout(r, 100))
}

const { scanSeclayer, scanWebapp } = await import('../src/scan-adapters.mjs')
const { gateScanTarget } = await import('../src/scan-gate.mjs')
const { compileStaticFindings } = await import('../src/engines/seclayer-core/server/scanner.ts')
const { buildHybridReportData } = await import('../src/hybrid-report.mjs')
const { renderScanReportHtml } = await import('../src/report-template.mjs')

const verifier = { isVerified: async () => false }
const target = `http://127.0.0.1:${PORT}/`
const gate = await gateScanTarget(target, verifier)
if (!gate.ok) throw new Error(gate.reason)

const seclayer = await scanSeclayer(verifier, gate.url, { aggressive: true })
const vibescan = await scanWebapp(verifier, gate.url, 'deep')
child.kill()

const staticCompiled = compileStaticFindings(seclayer)
const hybrid = await buildHybridReportData({ seclayer, vibescan, staticFindings: staticCompiled.findings ?? [] })

const fixPrompt = hybrid.findings
  .filter((f) => f.fix)
  .map((f, i) => `${i + 1}. [${String(f.severity).toUpperCase()}] ${f.title}\n   ${f.fix}`)
  .join('\n\n')

const data = {
  aiReport: {
    score: hybrid.score,
    findings: hybrid.findings,
    aiSummary: `${hybrid.findings.length} findings from two independent engines: SecScan's ${vibescan.vulnerabilities?.length ?? 0} catalog results and SecLayer's ${(staticCompiled.findings ?? []).filter((f) => !f.isFalsePositive).length} compiled findings, merged with ${hybrid.dropped.length} overlaps removed. ${hybrid.findings.filter((f) => f.engine === 'seclayer').length} findings come from SecLayer alone.`,
    aiReasoning: 'hybrid-merge',
    executiveBreakdown: { overview: 'Merged report: SecScan (base) + SecLayer (unique active checks).', riskAreas: [], businessImpact: '', priorityActions: [] },
  },
  posture: hybrid.posture,
  grade: hybrid.grade,
  fixPrompt,
  pillarBadge: () => 'MODERATE',
}

const html = renderScanReportHtml({ target: 'testbed (hybrid)', seclayer, vibescan, data, tickerLines: [] })
writeFileSync(path.join(HERE, 'hybrid-report.html'), html, 'utf8')
console.log(`merged: ${hybrid.findings.length} findings (${hybrid.dropped.length} overlaps removed)`)
console.log(`  secscan: ${hybrid.findings.filter((f) => f.engine === 'secscan').length}`)
console.log(`  seclayer: ${hybrid.findings.filter((f) => f.engine === 'seclayer').length}`)
console.log(`  score ${hybrid.score} grade ${hybrid.grade} posture ${hybrid.posture.postureRating}`)
console.log('wrote hybrid-report.html')
process.exit(0)
