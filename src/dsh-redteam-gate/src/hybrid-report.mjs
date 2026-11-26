// One report from both engines â€” the interface half of the merge.
//
// engine-merge.mjs decides WHICH findings appear. This module carries the FULL
// finding objects through that decision (description, evidence, fix, cwe, tier)
// and hands the merged set to the existing report template, so the page a user
// opens contains SecScan's catalog results and SecLayer's exploit proofs with no
// duplicate rows and no lost detail.
//
// Scoring runs over the MERGED set with scoring.ts's deriveSecurityPosture, so the
// score, grade and posture label describe what the reader can actually see.
import { mergeEngines } from './engine-merge.mjs'

const SECLAYER_SCORING = './engines/seclayer-core/server/scoring.ts'

/** SecScan vulnerability -> canonical finding. */
function fromSecscan(v) {
  return {
    engine: 'secscan',
    name: v.name,
    title: v.name,
    severity: v.severity,
    confidence: typeof v.confidence === 'number' ? v.confidence : v.confidence,
    category: v.category === 'Transport Security' ? 'EASM' : 'DAST',
    description: v.description,
    fix: v.solution,
    cwe: v.cweId,
    wstg: v.wstgId,
    evidence: v.evidence,
    raw: v,
  }
}

/** SecLayer compiled finding -> canonical finding. */
function fromSeclayer(f) {
  return {
    engine: 'seclayer',
    name: f.title,
    title: f.title,
    severity: f.severity,
    confidence: f.confidence,
    category: f.category ?? 'RED_TEAM',
    description: f.description,
    fix: f.fix,
    impact: f.impact,
    verification: f.verification,
    cwe: f.owasp,
    evidence: f.evidence,
    tier: f.tier,
    agentPrompt: f.agentPrompt,
    raw: f,
  }
}

/**
 * @param {{url: string, seclayer: object, vibescan?: object, staticFindings: object[]}} input
 * @returns {Promise<{findings: object[], dropped: object[], posture: object, grade: string, score: number}>}
 */
export async function buildHybridReportData({ seclayer, vibescan, staticFindings }) {
  const { deriveSecurityPosture, gradeForScore } = await import(SECLAYER_SCORING)

  const secscanFindings = (vibescan?.vulnerabilities ?? []).map(fromSecscan)
  const seclayerFindings = (staticFindings ?? []).filter((f) => !f.isFalsePositive).map(fromSeclayer)

  const { merged, dropped } = mergeEngines([...secscanFindings, ...seclayerFindings])

  // The template expects `title`/`category`/`severity`/`confidence`, and treats a
  // finding with `evidence` as having a receipt. Both shapes already satisfy that.
  const findings = merged.map((f) => ({
    id: `${f.engine}-${String(f.title).replace(/\W+/g, '-').toLowerCase()}`,
    title: f.engine === 'seclayer' ? `[SecLayer] ${f.title}` : f.title,
    category: f.category,
    severity: f.severity,
    confidence: typeof f.confidence === 'number' ? String(f.confidence) : f.confidence,
    description: f.description,
    fix: f.fix,
    impact: f.impact,
    verification: f.verification,
    agentPrompt: f.agentPrompt,
    evidence: f.evidence,
    engine: f.engine,
    issueKey: f.key,
  }))

  const posture = deriveSecurityPosture(findings.map((f) => ({ ...f })))
  return { findings, dropped, posture, grade: gradeForScore(posture.score), score: posture.score }
}
