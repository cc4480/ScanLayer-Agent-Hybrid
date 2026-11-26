// Builds the real report data for one completed SecLayer scan (a DiagnosticResult) by calling the
// verbatim engine functions the product itself uses — nothing here re-implements scoring, grading, or
// the executive-summary prose:
//   - compileStaticFindings(diag): the deterministic score + severity + Finding[] the scanner computes.
//   - generateAiReport(url, diag, staticCompiled, apiKey): the DeepSeek-written executive summary,
//     detailed breakdown (risk areas / business impact / priority actions) and per-finding agentPrompt —
//     with a graceful, deterministic local-mode fallback (compileLocalSummary/compileLocalBreakdown,
//     called INSIDE generateAiReport itself) when no DeepSeek key is configured. Same function, same
//     prompt (reportPrompt.ts's buildReportPrompt), as the real product.
//   - compileScanEvidence(diag): network/header/evidence facts for the "Network & Attack Surface" panel.
//   - scoring.ts's gradeForScore / deriveSecurityPosture / riskLabelForSeverity / highestSeverity: the
//     one letter-grade and posture-label mapping used everywhere else in the product.
//
// Also tracks a tiny per-host sidecar file (reports/.state/<host>.json: {score, findingTitles[]}) so a
// second scan of the same target can report "What changed since last scan" the way the product does.
// First scan of a target has nothing to diff against; that section is then honestly omitted rather than
// fabricated.
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
// Relative import specifiers (not path.join'd absolute OS paths): a plain Windows path like
// "C:\...\scanner.ts" is not a valid URL for the ESM loader, so these must stay './...'-relative,
// resolved by the loader against this module's own URL, the same way scan-adapters.mjs's do.
const SECLAYER_SCANNER = './engines/seclayer-core/server/scanner.ts'
const SECLAYER_DEEPSEEK = './engines/seclayer-core/server/deepseek.ts'
const SECLAYER_SCORING = './engines/seclayer-core/server/scoring.ts'
const STATE_DIR = path.join(HERE, '..', 'reports', '.state')

function stateFile(host) {
  return path.join(STATE_DIR, `${host.replace(/[^a-z0-9.-]/gi, '_')}.json`)
}

/** Read the previous run's state for this host, or null if there isn't one (first scan). */
function readPreviousState(host) {
  try {
    return JSON.parse(fs.readFileSync(stateFile(host), 'utf8'))
  } catch {
    return null
  }
}

function writeState(host, state) {
  fs.mkdirSync(STATE_DIR, { recursive: true })
  fs.writeFileSync(stateFile(host), JSON.stringify(state, null, 2), 'utf8')
}

/** Delta between the current findings/score and the previous run's, or null on a first scan. */
function computeChangeSinceLastScan(host, score, findings) {
  const previous = readPreviousState(host)
  const currentTitles = new Set(findings.filter((f) => !f.isFalsePositive).map((f) => f.title))
  if (!previous) return null
  const previousTitles = new Set(previous.findingTitles ?? [])
  const newFindings = findings.filter((f) => !f.isFalsePositive && !previousTitles.has(f.title))
  const resolvedTitles = [...previousTitles].filter((t) => !currentTitles.has(t))
  return {
    scoreDelta: score - (previous.score ?? score),
    newCount: newFindings.length,
    resolvedCount: resolvedTitles.length,
    newFindings: newFindings.map((f) => ({ title: f.title, severity: f.severity })),
  }
}

/**
 * @param {string} url the target that was scanned (same URL passed to runDiagnostics)
 * @param {object} seclayer the DiagnosticResult from scanSeclayer
 * @returns {Promise<object>} everything the report template needs, already computed by the real engine
 */
export async function buildSeclayerReportData(url, seclayer) {
  const { compileStaticFindings, compileScanEvidence } = await import(SECLAYER_SCANNER)
  const { generateAiReport } = await import(SECLAYER_DEEPSEEK)
  const { gradeForScore, deriveSecurityPosture, riskLabelForSeverity, highestSeverity } = await import(SECLAYER_SCORING)

  const staticCompiled = compileStaticFindings(seclayer)
  // apiKey undefined -> resolveApiKey falls back to the environment/host-configured key; absent entirely,
  // generateAiReport itself degrades to its own deterministic local-mode summary (never throws for this).
  const aiReport = await generateAiReport(url, seclayer, staticCompiled, undefined)
  const evidence = compileScanEvidence(seclayer)
  const grade = gradeForScore(aiReport.score)
  const posture = deriveSecurityPosture(aiReport.findings)

  const host = (() => {
    try { return new URL(url.startsWith('http') ? url : `https://${url}`).hostname } catch { return url }
  })()
  const change = computeChangeSinceLastScan(host, aiReport.score, aiReport.findings)
  writeState(host, { score: aiReport.score, findingTitles: aiReport.findings.filter((f) => !f.isFalsePositive).map((f) => f.title), at: new Date().toISOString() })

  const pillarBadge = (category) => {
    const sev = highestSeverity(aiReport.findings.filter((f) => f.category === category))
    return riskLabelForSeverity(sev)
  }

  return { aiReport, evidence, grade, posture, coverage: seclayer.coverage, change, pillarBadge }
}
