// Builds the "Complete Fix Prompt" the product's audit workspace shows above the findings: one
// self-contained, provider-neutral remediation plan a developer pastes into any AI coding agent.
//
// It mirrors the console's own structure (see the screenshots of seclayer.app): a plan header with
// scan context, a severity-ordered issue list, then one work-order per issue. Per-issue bodies reuse
// the engine's own `agentPrompt` (server/agentPrompt.ts, optionally sharpened by DeepSeek in
// server/deepseek.ts) so the wording is the product's, not this file's; only when a finding carries
// none (a bare fixture, or an engine path that skipped it) does a compact local block get synthesized
// from the finding's own description/fix/impact.

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
const SEVERITY_LABEL = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'INFO' }

function severityRank(f) {
  return SEVERITY_ORDER[String(f?.severity ?? 'info').toLowerCase()] ?? 4
}

/** "1 high, 1 medium" — the scan-context line the product shows. */
function severityBreakdown(findings) {
  const counts = new Map()
  for (const f of findings) {
    const key = String(f?.severity ?? 'info').toLowerCase()
    counts.set(key, (counts.get(key) ?? 0) + 1)
  }
  return [...counts.entries()]
    .sort((a, b) => severityRank({ severity: a[0] }) - severityRank({ severity: b[0] }))
    .map(([sev, n]) => `${n} ${sev}`)
    .join(', ')
}

/** The workflow every work-order shares, used only when a finding has no engine-written agentPrompt. */
function localWorkOrder(finding, target) {
  const out = []
  out.push('## The issue', '', `- Finding: ${finding.title}`)
  const meta = [
    finding.severity ? `Severity: ${SEVERITY_LABEL[String(finding.severity).toLowerCase()] ?? String(finding.severity).toUpperCase()}` : '',
    finding.confidence ? `confidence: ${finding.confidence}` : '',
  ].filter(Boolean).join(' · ')
  if (meta) out.push(`- ${meta}`)
  const classification = [finding.category, finding.owasp ? `OWASP ${finding.owasp}` : ''].filter(Boolean).join(' · ')
  if (classification) out.push(`- Classification: ${classification}`)
  out.push(`- Scanned target (black-box): ${target}`)
  if (finding.endpoint) out.push(`- Affected endpoint: ${finding.endpoint}`)
  if (finding.description) out.push('', finding.description)
  if (finding.impact) out.push('', `Impact if left unfixed: ${finding.impact}`)
  if (finding.fix) out.push('', '## Recommended fix', '', finding.fix)

  const ev = finding.evidence
  if (ev?.reproduction || ev?.demonstration) {
    out.push('', '## Proof this is real (not theoretical)', '')
    if (ev.demonstration) out.push(ev.demonstration, '')
    if (ev.reproduction) out.push('Reproduce it yourself:', '', '```', ev.reproduction, '```')
  }

  out.push(
    '',
    '## Work it in this order',
    '1. Locate — this scan is black-box and never read your source, so start from the',
    '   behavior/endpoint above and search the codebase for the route, handler, or config',
    '   that produces it. Name the file(s) you believe are responsible.',
    '2. Confirm — reproduce the issue locally before changing anything. If it does NOT',
    '   actually apply here, stop and report it as a likely false positive with your',
    '   reasoning. Never invent a change just to satisfy this prompt.',
    '3. Fix the root cause using this project\'s existing stack and conventions; if the same',
    '   flaw pattern repeats elsewhere, fix every instance.',
    '4. Add a regression test that FAILS on the vulnerable code and PASSES after the fix.',
    '5. Verify — run the full test suite and re-exercise the affected request.',
    '',
    '## Guardrails',
    '- Do not disable, bypass, or loosen any other security control to make this pass.',
    '- Keep the diff minimal and reviewable; do not refactor unrelated code.',
    '- Never hardcode secrets or credentials.',
    '- If a safe fix is not possible without broader changes, stop and explain rather than guess.',
    '',
    '## Done when',
    '- [ ] Root cause fixed (not just this one symptom, if the pattern repeats).',
    '- [ ] Regression test added and passing.',
    '- [ ] Full test suite still green.',
    '- [ ] You have summarized what changed, which files, and how you verified it.',
  )
  return out.join('\n')
}

/**
 * @param {{target: string, score?: number, postureRating?: string, findings?: object[]}} input
 * @returns {string} a complete master prompt, or '' when there is nothing to fix
 */
export function buildCompleteFixPrompt({ target, score, postureRating, findings = [] }) {
  const active = findings.filter((f) => !f?.isFalsePositive)
  if (active.length === 0) return ''

  // Most severe first — the same order the console presents and the prompt tells the agent to follow.
  const ordered = active
    .map((f, i) => ({ f, i }))
    .sort((a, b) => severityRank(a.f) - severityRank(b.f) || a.i - b.i)
    .map(({ f }) => f)

  const count = ordered.length
  const breakdown = severityBreakdown(ordered)
  const host = (() => {
    try { return new URL(/^https?:\/\//i.test(target) ? target : `https://${target}`).hostname } catch { return target }
  })()

  const lines = []
  lines.push(
    `# Security Remediation Plan — ${host}`,
    '',
    'You are a senior application security engineer with full write access to this',
    `repository. A black-box security scan of ${host} found ${count} issue${count === 1 ? '' : 's'} to fix.`,
    'Work through them IN THE ORDER LISTED (most severe first), fixing each at the',
    'root cause without regressions or weakening any other control. This prompt is',
    'self-contained, provider-neutral, and portable: it works the same with any AI',
    'coding agent on any platform.',
    '',
    'Scan context:',
    `- Target (black-box): ${host}`,
  )
  if (typeof score === 'number') lines.push(`- Security score: ${score}/100${postureRating ? ` (${postureRating})` : ''}`)
  lines.push(`- Issues to fix: ${count}${breakdown ? ` — ${breakdown}` : ''}`)
  lines.push(
    '',
    '## How to work this plan',
    '1. Handle findings top-down (most severe first). For EACH finding:',
    '   a. Locate — this scan is black-box and never read your source, so search by',
    '      the described behavior/endpoint and name the responsible file(s).',
    '   b. Confirm — reproduce it before changing anything. If it does not actually',
    '      apply, mark it a likely false positive with your reasoning and move on.',
    '      Never invent a change just to satisfy this prompt.',
    '   c. Fix the root cause using the project\'s existing stack and conventions; if',
    '      the same flaw pattern repeats elsewhere, fix every instance.',
    '   d. Add a regression test that FAILS on the vulnerable code and PASSES after.',
    '2. When every finding is handled: run the full test suite, re-exercise each',
    '   affected request, and report what changed, which files, and how you verified it.',
    '',
    '## Issues, most severe first',
    '',
  )
  ordered.forEach((f, idx) => {
    const sev = SEVERITY_LABEL[String(f.severity ?? 'info').toLowerCase()] ?? 'INFO'
    lines.push(`${idx + 1}. [${sev}] ${f.title}${f.category ? ` (${f.category})` : ''}`)
  })

  ordered.forEach((f, idx) => {
    const sev = SEVERITY_LABEL[String(f.severity ?? 'info').toLowerCase()] ?? 'INFO'
    const confidence = f.confidence ? ` · confidence: ${f.confidence}` : ''
    const classification = [f.category, f.owasp ? `OWASP ${f.owasp}` : ''].filter(Boolean).join(' · ')
    lines.push(
      '',
      '---',
      '',
      `## Issue ${idx + 1} of ${count} — ${f.title}`,
      '',
      `- Severity: ${sev}${confidence}${classification ? ` · ${classification}` : ''}`,
    )
    if (f.endpoint) lines.push(`- Affected endpoint: ${f.endpoint}`)
    lines.push('')
    lines.push(typeof f.agentPrompt === 'string' && f.agentPrompt.trim() ? f.agentPrompt.trim() : localWorkOrder(f, target))
  })

  return lines.join('\n')
}
