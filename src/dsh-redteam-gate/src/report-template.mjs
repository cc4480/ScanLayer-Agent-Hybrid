// Self-contained HTML report renderer, matching the seclayer.app product's own dashboard layout
// (audit workspace header, complete fix prompt, posture score gauge, executive summary/breakdown,
// pillar grid, network and coverage panels, hardening-gaps callout, structured diagnostic evidence,
// live scan ticker). Pure string templating, no build step.
//
// Every number and sentence here comes from `data`, which report-data.mjs computes by calling the real
// SecLayer engine functions (compileStaticFindings, generateAiReport, compileScanEvidence, the scoring
// module's grade/posture helpers, and fix-prompt.mjs's remediation plan) — this file only lays the
// already-computed facts out. The only prose it writes itself is the short explanatory caption under
// each diagnostic block, which describes what the block contains (never a security verdict).

const PILLARS = [
  { key: 'SAST', label: 'SAST', sub: 'STATIC ANALYSIS' },
  { key: 'DAST', label: 'DAST', sub: 'DYNAMIC AUDIT' },
  { key: 'IAST', label: 'IAST', sub: 'INTERACTIVE POLICIES' },
  { key: 'SCA', label: 'SCA', sub: 'COMPOSITION REVIEW' },
  { key: 'EASM', label: 'EASM', sub: 'ATTACK SURFACE' },
  { key: 'API_SEC', label: 'API SEC', sub: 'API SECURITY TESTING' },
  { key: 'RED_TEAM', label: 'RED TEAM', sub: 'RED TEAM ACTIVE PROBES' },
];

const RISK_LABEL_CLASS = {
  SECURE: 'ok', INFO: 'info', 'LOW RISK': 'info', MODERATE: 'warn', 'HIGH RISK': 'bad', CRITICAL: 'bad',
};

// The five headers the engine scores, plus the advisory set it reports but does not score.
const SCORED_HEADERS = [
  'content-security-policy', 'strict-transport-security', 'x-frame-options',
  'x-content-type-options', 'referrer-policy',
];
const ADVISORY_HEADERS = ['permissions-policy', 'cross-origin-opener-policy', 'cross-origin-resource-policy'];

const SCANNER_UA = 'Mozilla/5.0 (compatible; Seclayer-Security-Scanner/2.0; +https://seclayer.app/bot)';

function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function anchorFor(category) {
  return `pillar-${category.toLowerCase().replace(/_/g, '-')}`;
}

function renderPillarChip(p, count) {
  return `<a class="chip" href="#${anchorFor(p.key)}">${esc(p.label)}${count > 0 ? ` <span class="chip-count">${count}</span>` : ''}</a>`;
}

/**
 * Pillar card. The bar is proportional to the share of this scan's findings that belong to the
 * pillar (capped at 100%), so the grid reads as a distribution instead of a fixed decoration.
 */
function renderPillarCard(p, count, badge, totalFindings) {
  const cls = RISK_LABEL_CLASS[badge] ?? 'ok';
  const pct = totalFindings > 0 ? Math.max(4, Math.round((count / totalFindings) * 100)) : 4;
  return `<div class="pillar" id="${anchorFor(p.key)}">
    <div class="pillar-head"><span class="pillar-name">${esc(p.label)}</span></div>
    <div class="pillar-sub">${esc(p.sub)}</div>
    <div class="pillar-status"><span class="status-word ${cls}">${esc(badge)}</span><span class="status-count">${count}</span></div>
    <div class="pillar-bar"><div class="pillar-bar-fill ${cls}" style="width:${pct}%"></div></div>
  </div>`;
}

function severityTag(sev) {
  const s = String(sev ?? 'info').toLowerCase();
  const label = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'INFO' }[s] ?? 'INFO';
  return `<span class="sev-tag sev-${s}">${label}</span>`;
}

function renderFindingCard(f, index = 1) {
  const sev = String(f.severity ?? 'info').toLowerCase();
  const agentPromptId = `prompt-${esc(f.id ?? Math.random().toString(36).slice(2))}`;
  return `<div class="finding sev-${sev}" id="finding-${index}">
    <div class="finding-head">
      ${severityTag(f.severity)}
      <span class="finding-title">${esc(f.title)}</span>
      <span class="finding-pillar">${esc(f.category)}${f.confidence ? ` &middot; ${esc(f.confidence)} confidence` : ''}</span>
    </div>
    ${f.description ? `<div class="finding-desc">${esc(f.description)}</div>` : ''}
    ${f.impact ? `<div class="finding-impact"><strong>Impact:</strong> ${esc(f.impact)}</div>` : ''}
    ${f.fix ? `<div class="finding-fix"><strong>Fix:</strong> ${esc(f.fix)}</div>` : ''}
    ${f.verification ? `<div class="finding-verify">${esc(f.verification)}</div>` : ''}
    ${f.agentPrompt && sev !== 'info' ? `
      <textarea id="${agentPromptId}" class="prompt-src">${esc(f.agentPrompt)}</textarea>
      <button type="button" class="copy-btn" onclick="copyFix('${agentPromptId}', this)">Copy Fix Prompt</button>
    ` : ''}
  </div>`;
}

/** The product's "Complete Fix Prompt" panel: one plan for every issue, ready to paste into an agent. */
function fixPromptPanel(fixPrompt, issueCount, n = '') {
  if (!fixPrompt) return '';
  return `<details class="panel" id="fixplan">
    <summary class="fixpanel-head">
      <span class="fixpanel-title">${n ? `<span class="n">${esc(n)}</span> ` : ''}Remediation &mdash; complete fix prompt</span>
      <span class="fixpanel-sub">${issueCount} issue${issueCount === 1 ? '' : 's'} &middot; one plan, most severe first &middot; paste into any AI coding agent</span>
    </summary>
    <div class="fixpanel-inner">
      <p class="fixpanel-note">Self-contained remediation plan covering every finding above. It names no files — the scanner is black-box — so the agent locates each root cause from the described behaviour.</p>
      <button type="button" class="copy-btn" onclick="copyFix('complete-fix-prompt', this)">Copy prompt</button>
      <textarea id="complete-fix-prompt" class="prompt-src">${esc(fixPrompt)}</textarea>
      <pre class="fixpanel-body">${esc(fixPrompt)}</pre>
    </div>
  </details>`;
}

function changeBox(change) {
  if (!change) {
    return `<div class="panel"><h2>What Changed Since Last Scan</h2><div class="empty">This is the first recorded scan of this target — no prior baseline to compare against.</div></div>`;
  }
  const deltaCls = change.scoreDelta > 0 ? 'ok' : change.scoreDelta < 0 ? 'bad' : '';
  const deltaSign = change.scoreDelta > 0 ? '+' : '';
  const worsened = change.worsenedCount ?? 0;
  return `<div class="panel">
    <h2>What Changed Since Last Scan</h2>
    <div class="change-row">
      <div class="change-stat"><div class="change-num bad">${change.newCount}</div><div class="change-lbl">NEW</div></div>
      <div class="change-stat"><div class="change-num ok">${change.resolvedCount}</div><div class="change-lbl">RESOLVED</div></div>
      <div class="change-stat"><div class="change-num ${worsened > 0 ? 'bad' : ''}">${worsened}</div><div class="change-lbl">WORSENED</div></div>
      <div class="change-delta ${deltaCls}">${deltaSign}${change.scoreDelta} score</div>
    </div>
    ${change.newFindings?.length ? `<div class="new-findings"><div class="tag">NEW FINDINGS</div>${change.newFindings.map((f) => `<div class="new-finding-row">${severityTag(f.severity)} ${esc(f.title)}</div>`).join('')}</div>` : ''}
    ${change.worsenedFindings?.length ? `<div class="new-findings"><div class="tag">SEVERITY INCREASED</div>${change.worsenedFindings.map((f) => `<div class="new-finding-row">${severityTag(f.severity)} ${esc(f.title)} <span class="dim-note">(was ${esc(f.was || 'unknown')})</span></div>`).join('')}</div>` : ''}
  </div>`;
}

function hardeningGapsBox(posture, findings) {
  const active = findings.filter((f) => !f.isFalsePositive);
  // "INFO" and "SECURE" both mean nothing actionable was found: an info note is
  // scan context (surface mapped, probe skipped), not a weakness. Painting those
  // amber would contradict the gauge right above it.
  if (active.length === 0 || posture.postureRating === 'SECURE' || posture.postureRating === 'INFO') {
    return `<div class="gaps-box ok"><span class="tag">NO ACTIONABLE FINDINGS</span><div style="margin-top:4px;">Nothing in this scan needs remediation.${active.length ? ` ${active.length} informational note${active.length === 1 ? '' : 's'} recorded as context only.` : ''}</div></div>`;
  }
  // Keyed off the posture LABEL, not raw severity: the label already accounts for
  // whether the worst finding was confirmed, so this line cannot call a site
  // "high risk" that the gauge beside it rates MODERATE.
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const top = [...active].sort((a, b) => (order[a.severity] ?? 4) - (order[b.severity] ?? 4))[0];
  const urgency = {
    CRITICAL: 'a serious exposure that should be remediated immediately',
    'HIGH RISK': 'a serious exposure that should be remediated soon',
    MODERATE: 'a defense-in-depth gap worth scheduling for remediation, not an emergency',
    'LOW RISK': 'a minor hygiene item, not urgent',
    INFO: 'informational context, not an action item',
  }[posture.postureRating] ?? 'worth reviewing';
  return `<div class="gaps-box warn">
      <span class="tag">${esc(posture.postureRating)} HARDENING GAPS</span>
      <div style="margin-top:4px;">${active.length} finding(s) detected. The most significant is a ${esc(String(top.severity ?? 'info').toUpperCase())}-severity issue ("${esc(top.title)}") — ${esc(urgency)}.</div>
    </div>`;
}

/* ------------------------------------------------------------------------------------------------
 * Diagnostic evidence
 *
 * The console shows the scan's raw output as labelled, explained blocks rather than one header dump:
 * the captured request/response trace, the full header set with the scored ones marked, the DNS and
 * perimeter facts, every probed path with its verdict, each active probe's outcome, and the cookie
 * state. Everything below is read straight off the DiagnosticResult; nothing is synthesized.
 * ---------------------------------------------------------------------------------------------- */

function diagBlock(title, count, caption, bodyHtml) {
  return `<section class="diag-block">
    <h3>${esc(title)}${count !== undefined ? ` <span class="diag-count">${esc(count)}</span>` : ''}</h3>
    ${bodyHtml}
    ${caption ? `<p class="diag-note">${esc(caption)}</p>` : ''}
  </section>`;
}

function kvTable(rows) {
  return `<table class="diag-table kv">${rows
    .filter(Boolean)
    .map(([k, v]) => `<tr><td class="k">${esc(k)}</td><td class="v">${v}</td></tr>`)
    .join('')}</table>`;
}

function verdictCell(ok, okText, badText) {
  return ok ? `<span class="verdict ok">${esc(okText)}</span>` : `<span class="verdict bad">${esc(badText)}</span>`;
}

function renderTrace(seclayer, evidence) {
  const url = seclayer?.finalUrl ?? seclayer?.url ?? '';
  let path = '/';
  let host = '';
  try { const u = new URL(url); path = `${u.pathname}${u.search}`; host = u.host } catch { /* keep defaults */ }
  const tls = seclayer?.tls;
  const proto = evidence?.protocol ?? (seclayer?.sslSecure ? 'HTTPS' : 'HTTP');
  const lines = [
    `GET ${path} HTTP/1.1`,
    `Host: ${host || '-'}`,
    `User-Agent: ${SCANNER_UA}`,
    `Accept: text/html`,
    '',
    `← HTTP ${seclayer?.responseStatus ?? evidence?.responseStatus ?? '-'} over ${proto}`,
    `Final URL: ${url || '-'}`,
    `Scanned at: ${seclayer?.scannedAt ?? evidence?.scannedAt ?? '-'}`,
    `Server: ${evidence?.serverHeader ?? '-'}`,
  ];
  if (tls?.reachable) {
    lines.push(`TLS: ${tls.protocol ?? '-'} — subject ${tls.subject ?? '-'}, issued by ${tls.issuer ?? '-'}`)
    if (tls.validFromMs && tls.validToMs) {
      lines.push(`Certificate validity: ${new Date(tls.validFromMs).toISOString().slice(0, 10)} → ${new Date(tls.validToMs).toISOString().slice(0, 10)}`)
    }
  } else if (tls?.checked) {
    lines.push('TLS: handshake could not be completed')
  }
  return `<pre class="trace">${esc(lines.join('\n'))}</pre>`;
}

function renderHeaderBlocks(seclayer, evidence) {
  const headers = seclayer?.headers ?? {};
  const scored = SCORED_HEADERS.concat(ADVISORY_HEADERS);
  const scoredRows = scored.map((name) => {
    const value = headers[name];
    const present = typeof value === 'string' && value.length > 0;
    const scored_ = SCORED_HEADERS.includes(name);
    return `<tr>
      <td class="k">${esc(name)}</td>
      <td class="v mono">${present ? esc(value) : '<span class="dim-note">—</span>'}</td>
      <td>${verdictCell(present, 'present', 'missing')}${scored_ ? '<span class="dim-note"> scored</span>' : '<span class="dim-note"> advisory</span>'}</td>
    </tr>`;
  }).join('')

  const other = Object.keys(headers).filter((h) => !scored.includes(h)).sort()
  const otherRows = other.length
    ? other.map((h) => `<tr><td class="k">${esc(h)}</td><td class="v mono">${esc(headers[h])}</td><td><span class="dim-note">—</span></td></tr>`).join('')
    : '<tr><td class="k">—</td><td class="v">no other headers captured</td><td></td></tr>'

  const missing = evidence?.missingSecurityHeaders ?? seclayer?.missingHeaders ?? []
  return `<table class="diag-table">
      <thead><tr><th>header</th><th>observed value</th><th>state</th></tr></thead>
      <tbody>${scoredRows}${otherRows}</tbody>
    </table>
    <p class="diag-note">${missing.length
      ? `Scored defensive headers missing on this response: ${esc(missing.join(', '))}. Each absence is reported as a scored finding above.`
      : 'All five scored defensive headers were present on this response.'} Advisory headers are listed for completeness; their absence is not scored.</p>`;
}

function renderPerimeter(seclayer, evidence) {
  const subdomains = seclayer?.easmPerimeter?.subdomains ?? []
  const live = subdomains.filter((s) => s.status === 'live')
  const inactive = subdomains.filter((s) => s.status !== 'live')
  const rows = [
    ['Resolved IP', esc(evidence?.resolvedIp ?? seclayer?.easmPerimeter?.ip ?? '-')],
    ['Nameserver', esc(evidence?.nameserver ?? seclayer?.easmPerimeter?.nameserver ?? '-')],
    ['Protocol / status', `${esc(evidence?.protocol ?? seclayer?.easmPerimeter?.protocol ?? '-')} &middot; HTTP ${esc(evidence?.responseStatus ?? seclayer?.responseStatus ?? '-')}`],
    ['TLS', esc(seclayer?.tls?.protocol ?? (seclayer?.sslSecure ? 'secure' : 'not secure'))],
    ['Subdomains probed', `${subdomains.length} candidate name(s)`],
    ['Live subdomains', live.length
      ? live.map((s) => `<span class="sub-live">${esc(s.domain)}</span>${s.port && s.port !== '0' ? ` <span class="dim-note">:${esc(s.port)}</span>` : ''}`).join(', ')
      : '<span class="dim-note">none answered</span>'],
  ]
  if (inactive.length) {
    rows.push(['Inactive subdomains', `<span class="dim-note">${esc(inactive.map((s) => s.domain).join(', '))}</span>`])
  }
  return kvTable(rows)
}

function renderPaths(evidence, seclayer) {
  const paths = evidence?.probedPaths ?? seclayer?.probedPaths ?? []
  if (!paths.length) return '<div class="empty">No sensitive paths were probed on this target.</div>'
  const exposed = paths.filter((p) => p.exposed).length
  const rows = paths.map((p) => `<tr>
      <td class="k mono">${esc(p.path)}</td>
      <td class="v">HTTP ${esc(p.status)}</td>
      <td>${p.exposed ? verdictCell(false, '', 'EXPOSED') : verdictCell(true, 'locked down', '')}</td>
    </tr>`).join('')
  return `<table class="diag-table">
      <thead><tr><th>path</th><th>response</th><th>verdict</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <p class="diag-note">${paths.length} path(s) requested directly: ${exposed === 0
      ? 'every one answered 4xx/3xx, so none of them served a file.'
      : `${exposed} answered with a body — see the findings above.`}</p>`
}

function findingRows(items, labelOf) {
  return items.map((f) => `<tr>
      <td class="k">${esc(labelOf(f))}</td>
      <td class="v">${severityTag(f.severity ?? 'info')}</td>
      <td class="v dim-note">${esc(f.confidence ? `confidence: ${f.confidence}` : (f.verification ?? ''))}</td>
    </tr>`).join('')
}

function renderActiveProbes(seclayer) {
  const red = seclayer?.redTeamFindings ?? []
  const api = seclayer?.apiSecFindings ?? []
  const all = [
    ...red.map((f) => ({ ...f, _label: f.testName ?? 'red-team probe' })),
    ...api.map((f) => ({ ...f, _label: f.testName ?? 'API probe', _endpoint: f.endpoint })),
  ]
  if (seclayer?.activeProbesSkipped) {
    return '<div class="empty">Active exploit probing was skipped for this target (ownership was not verified at scan time), so no probe results exist.</div>'
  }
  if (!all.length) {
    return `<div class="diag-empty-ok">No active probe produced a confirmed signal.</div>
      <p class="diag-note">${(seclayer?.crawl?.paramsTested ?? 0)} parameter(s) were fuzzed and the root URL was probed for SQL injection, reflected XSS, command injection, SSRF and blind SSRF. "No signal" means the target resisted — it is not proof the check could never fire.</p>`
  }
  const rows = all.map((f) => `<tr>
      <td class="k">${esc(f._label)}${f._endpoint ? `<br><span class="dim-note mono">${esc(f._endpoint)}</span>` : ''}</td>
      <td class="v">${severityTag(f.severity ?? 'info')}</td>
      <td class="v dim-note">${esc(f.confidence ? `confidence: ${f.confidence}` : (f.verification ?? ''))}</td>
    </tr>`).join('')
  return `<table class="diag-table">
      <thead><tr><th>probe</th><th>result</th><th>confidence</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <p class="diag-note">Only probes that produced a signal are listed. A probe that stayed silent is reported as "no signal" in the live ticker below.</p>`
}

function renderStaticFindings(seclayer) {
  const sast = seclayer?.sastFindings ?? []
  const sca = (seclayer?.scaLibraries ?? []).filter((l) => l.status === 'vuln')
  const templates = seclayer?.templateFindings ?? []
  if (!sast.length && !sca.length && !templates.length) {
    return '<div class="diag-empty-ok">No leaked secrets, vulnerable libraries, or template signatures were detected.</div>'
  }
  const parts = []
  if (sast.length) {
    parts.push(`<div class="diag-sub">Exposed secrets / SAST <span class="diag-count">${sast.length}</span></div>
      <table class="diag-table"><tbody>${sast.map((f) => `<tr><td class="k">${esc(f.issue)}<br><span class="dim-note mono">${esc(f.file)}</span></td><td class="v">${severityTag(f.severity)}</td><td class="v mono">${esc(f.masked ?? '')}</td></tr>`).join('')}</tbody></table>`)
  }
  if (sca.length) {
    parts.push(`<div class="diag-sub">Vulnerable libraries <span class="diag-count">${sca.length}</span></div>
      <table class="diag-table"><tbody>${sca.map((l) => `<tr><td class="k">${esc(l.name)} ${esc(l.version ?? '')}</td><td class="v">${severityTag(l.severity)}</td></tr>`).join('')}</tbody></table>`)
  }
  if (templates.length) {
    parts.push(`<div class="diag-sub">Template matches <span class="diag-count">${templates.length}</span></div>
      <table class="diag-table"><tbody>${templates.map((f) => `<tr><td class="k">${esc(f.title)}</td><td class="v">${severityTag(f.severity)}</td></tr>`).join('')}</tbody></table>`)
  }
  return parts.join('')
}

function renderCookies(seclayer) {
  const issues = seclayer?.cookieIssues ?? []
  const setCookies = seclayer?.setCookies ?? []
  if (!issues.length && !setCookies.length) return '<div class="diag-empty-ok">No cookies were set on the root response.</div>'
  const rows = issues.map((msg) => `<tr><td class="k">${esc(msg)}</td><td class="v"><span class="verdict bad">flagged</span></td></tr>`).join('')
  const sets = setCookies.length
    ? `<div class="diag-sub">Set-Cookie lines <span class="diag-count">${setCookies.length}</span></div>
       <pre class="trace small">${esc(setCookies.join('\n'))}</pre>`
    : ''
  return `<table class="diag-table"><tbody>${rows || '<tr><td class="k">No insecure cookie attributes detected.</td><td class="v"><span class="verdict ok">clean</span></td></tr>'}</tbody></table>${sets}
    <p class="diag-note">Cookie values are redacted; only the attributes the scanner judged are shown.</p>`
}

function renderDiagnostics({ seclayer, evidence, vibescan, n = '' }) {
  if (!seclayer && !vibescan) {
    return `<section class="panel" id="evidence"><h2><span class="n">${esc(n)}</span> Evidence</h2><div class="empty">No diagnostic data was captured for this target.</div></section>`
  }
  const blocks = []
  blocks.push(diagBlock('Captured scan trace', undefined,
    'The scanner sends one unauthenticated GET per mapped page. A 200 here means the origin answered — not that the page is safe.',
    renderTrace(seclayer, evidence)))
  blocks.push(diagBlock('HTTP response headers', `${Object.keys(seclayer?.headers ?? {}).length} captured`,
    undefined,
    renderHeaderBlocks(seclayer, evidence)))
  blocks.push(diagBlock('EASM — DNS & perimeter', undefined,
    'Resolved addresses, the authoritative nameserver, and which of the probed subdomain candidates answer.',
    renderPerimeter(seclayer, evidence)))
  blocks.push(diagBlock('DAST — sensitive path probes', `${(evidence?.probedPaths ?? seclayer?.probedPaths ?? []).length} probed`,
    undefined,
    renderPaths(evidence, seclayer)))
  blocks.push(diagBlock('Red team — active exploit probes', undefined,
    'Confirmed exploit signals only. Absence of a signal means the payload was refused, not that the class is impossible.',
    renderActiveProbes(seclayer)))
  blocks.push(diagBlock('SAST / SCA / template checks', undefined,
    'Exposed-secret signatures, vulnerable dependency manifests, and known template fingerprints.',
    renderStaticFindings(seclayer)))
  blocks.push(diagBlock('Cookies & session', undefined,
    undefined,
    renderCookies(seclayer)))

  return `<details class="diag" open id="evidence">
    <summary>${n ? `<span class="n">${esc(n)}</span> ` : ''}Evidence &mdash; raw headers and outputs</summary>
    <div class="diag-body">
      <p class="diag-intro">The exact evidence captured during this scan — resolved network data, per-path probe results, and observed header state. Everything below is real output from this run.</p>
      ${blocks.join('\n')}
    </div>
  </details>`
}

/**
 * @param {{
 *   target: string,
 *   seclayer?: object,      // raw SecLayer DiagnosticResult (crawl/probedPaths/scaLibraries/easmPerimeter)
 *   vibescan?: object,      // raw VibeScan ScanResult, optional
 *   data?: object,          // report-data.mjs's buildSeclayerReportData() output, when seclayer ran
 *   tickerLines?: string[],
 *   generatedAt?: Date,
 * }} input
 * @returns {string} a complete, self-contained HTML document
 */
export function renderScanReportHtml({ target, seclayer, vibescan, data, tickerLines = [], generatedAt = new Date() }) {
  const aiReport = data?.aiReport;
  const findings = aiReport?.findings?.filter((f) => !f.isFalsePositive) ?? [];
  const score = aiReport?.score ?? 100;
  const grade = data?.grade ?? (score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F');
  const posture = data?.posture ?? { postureRating: findings.length ? 'MODERATE' : 'SECURE' };
  const scoreCls = score >= 90 ? '' : score >= 70 ? 'warn' : 'bad';
  // "Proven" means the engine attached a replayable exploit receipt — NOT merely
  // that a finding carries an evidence block (an observation receipt is evidence
  // but proves nothing). report-data.mjs stamps each finding with scoring.ts's own
  // resultTier(), so the counts here can never overstate what was proven.
  const provenCount = findings.filter((f) => f.tier === 'PROVEN').length;
  const confirmedCount = findings.filter((f) => f.tier === 'CONFIRMED').length;
  const toVerifyCount = findings.filter((f) => f.tier === 'NEEDS VERIFICATION').length;
  const statusOf = (f) => ({
    PROVEN: 'proven', CONFIRMED: 'confirmed', 'NEEDS VERIFICATION': 'needs verification', PASS: 'pass',
  }[f.tier] ?? 'needs verification');
  const fixPrompt = data?.fixPrompt ?? '';

  // One ordering and one set of counts for the whole document: the summary table,
  // the detail cards and the tally must never disagree about severity.
  const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const ordered = [...findings].sort(
    (a, b) => (SEV_ORDER[String(a.severity ?? 'info').toLowerCase()] ?? 9) - (SEV_ORDER[String(b.severity ?? 'info').toLowerCase()] ?? 9),
  );
  const countSev = (s) => findings.filter((f) => String(f.severity ?? 'info').toLowerCase() === s).length;
  const worstSev = ordered.length ? String(ordered[0].severity ?? 'info').toLowerCase() : null;
  const verdictLine = findings.length === 0
    ? 'No findings were reported against this target by either engine.'
    : `${findings.length} finding${findings.length === 1 ? '' : 's'} reported, worst ${worstSev.toUpperCase()}; ${provenCount} proven, ${confirmedCount} confirmed, ${toVerifyCount} still need${toVerifyCount === 1 ? 's' : ''} human verification.`;

  // One list drives both the contents rail and the section numbers, so a section
  // that is absent (no remediation prompt to show) cannot leave a numbering gap
  // or a link to an anchor that was never rendered.
  const sections = [
    { id: 'summary', title: 'Summary' },
    { id: 'findings', title: 'Findings', count: findings.length },
    ...(fixPrompt ? [{ id: 'fixplan', title: 'Remediation' }] : []),
    { id: 'coverage', title: 'Coverage' },
    { id: 'surface', title: 'Attack surface' },
    { id: 'evidence', title: 'Evidence' },
    { id: 'log', title: 'Scan log' },
  ].map((s, i) => ({ ...s, n: String(i + 1).padStart(2, '0') }));
  const num = (id) => sections.find((s) => s.id === id)?.n ?? '';
  const toc = sections.map((s) => `<a href="#${s.id}"><span class="n">${s.n}</span>${esc(s.title)}${s.count ? ` <span class="count-pill">${s.count}</span>` : ''}</a>`).join('');

  const pillarCounts = Object.fromEntries(PILLARS.map((p) => [p.key, findings.filter((f) => f.category === p.key).length]));
  const pillarBadges = Object.fromEntries(PILLARS.map((p) => [p.key, data?.pillarBadge ? data.pillarBadge(p.key) : (pillarCounts[p.key] > 0 ? 'MODERATE' : 'SECURE')]));

  const evidence = data?.evidence;
  const coverage = data?.coverage;
  const groups = coverage ? new Set(coverage.items.map((i) => i.category)) : null;
  const ranGroups = coverage ? new Set(coverage.items.filter((i) => i.ran).map((i) => i.category)) : null;

  const exposedPaths = (seclayer?.probedPaths ?? []).filter((p) => p.exposed).length;
  const totalPaths = (seclayer?.probedPaths ?? []).length;
  const vulnLibs = (seclayer?.scaLibraries ?? []).filter((l) => l.status === 'vuln');
  const liveSubdomains = (seclayer?.easmPerimeter?.subdomains ?? []).filter((s) => s.status === 'live').map((s) => s.domain);

  const overview = aiReport?.executiveBreakdown?.overview;
  const riskAreas = aiReport?.executiveBreakdown?.riskAreas ?? [];
  const businessImpact = aiReport?.executiveBreakdown?.businessImpact;
  const priorityActions = aiReport?.executiveBreakdown?.priorityActions ?? [];
  const usedRealAi = typeof aiReport?.aiReasoning === 'string' && aiReport.aiReasoning.length > 0;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Report — ${esc(target)}</title>
<style>
  :root {
    --bg: #0a0d10; --panel: #11161b; --panel-2: #0d1116; --border: #1e262d;
    --text: #d7dee3; --dim: #7c8894; --accent: #22c55e; --accent-dim: #16331f;
    --warn: #eab308; --bad: #ef4444; --info: #3b82f6;
    --mono: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text); font-family: var(--mono); font-size: 13px; line-height: 1.5; }
  .wrap { max-width: 1100px; margin: 0 auto; padding: 28px 20px 60px; }
  header.top { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 20px; }
  header.top .brand { font-weight: 700; color: var(--accent); letter-spacing: 0.02em; }
  header.top .meta { color: var(--dim); font-size: 12px; text-align: right; }
  .breadcrumb { color: var(--dim); font-size: 11px; margin-bottom: 10px; }
  .score-row { display: flex; gap: 20px; align-items: stretch; margin-bottom: 20px; flex-wrap: wrap; }
  .score-circle { width: 120px; height: 120px; border-radius: 50%; border: 6px solid var(--accent); display: flex; flex-direction: column; align-items: center; justify-content: center; flex-shrink: 0; }
  .score-circle.warn { border-color: var(--warn); } .score-circle.bad { border-color: var(--bad); }
  .score-circle .num { font-size: 26px; font-weight: 700; } .score-circle .grade { font-size: 11px; color: var(--dim); }
  .score-info { flex: 1; min-width: 260px; background: var(--panel); border: 1px solid var(--border); border-radius: 6px; padding: 16px; }
  .score-info .target { font-size: 15px; font-weight: 700; margin-bottom: 4px; }
  .score-info .posture { font-weight: 700; }
  .score-info .posture.ok { color: var(--accent); }
  .score-info .posture.info { color: var(--info); }
  .score-info .posture.warn { color: var(--warn); }
  .score-info .posture.bad { color: var(--bad); }
  .score-info .findings-bar-lbl { color: var(--dim); font-size: 11px; margin-top: 8px; }
  .chips { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 20px; }
  .chip { display: inline-flex; align-items: center; gap: 6px; background: var(--panel-2); border: 1px solid var(--border); border-radius: 4px; padding: 5px 10px; font-size: 11px; color: var(--dim); text-decoration: none; }
  .chip-count { background: var(--accent-dim); color: var(--accent); border-radius: 3px; padding: 0 5px; font-size: 10px; }
  .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 6px; padding: 16px; margin-bottom: 16px; }
  .panel h2 { font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--dim); margin: 0 0 12px; display: flex; align-items: center; gap: 8px; }
  .ai-badge { background: var(--accent-dim); color: var(--accent); font-size: 9px; padding: 2px 6px; border-radius: 3px; text-transform: none; letter-spacing: 0; }
  .change-row { display: flex; gap: 24px; align-items: center; margin-bottom: 10px; }
  .change-stat { text-align: center; } .change-num { font-size: 22px; font-weight: 700; } .change-num.ok { color: var(--accent); } .change-num.bad { color: var(--bad); }
  .change-lbl { font-size: 10px; color: var(--dim); }
  .change-delta { margin-left: auto; font-weight: 700; } .change-delta.ok { color: var(--accent); } .change-delta.bad { color: var(--bad); }
  .new-finding-row { font-size: 12px; margin-top: 4px; }
  .risk-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }
  .risk-card { background: var(--panel-2); border: 1px solid var(--border); border-radius: 4px; padding: 12px; }
  .risk-card .t { font-weight: 700; margin-bottom: 4px; } .risk-card .d { color: var(--dim); font-size: 12px; }
  .impact-box { background: #1a1308; border: 1px solid #3d2f0a; border-radius: 4px; padding: 12px; margin-top: 12px; }
  .impact-box .tag { color: var(--warn); font-weight: 700; font-size: 11px; }
  .priority-list { margin: 10px 0 0; padding-left: 18px; } .priority-list li { margin-bottom: 6px; font-size: 12px; }
  .pillar-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; }
  .pillar { background: var(--panel-2); border: 1px solid var(--border); border-radius: 4px; padding: 10px 12px; scroll-margin-top: 16px; }
  .pillar-head { display: flex; justify-content: space-between; align-items: center; }
  .pillar-name { font-size: 12px; font-weight: 700; } .pillar-sub { font-size: 9px; color: var(--dim); margin-bottom: 8px; }
  .pillar-status { display: flex; justify-content: space-between; align-items: baseline; }
  .status-word { font-size: 10px; font-weight: 700; } .status-word.ok { color: var(--accent); } .status-word.info { color: var(--info); } .status-word.warn { color: var(--warn); } .status-word.bad { color: var(--bad); }
  .status-count { font-size: 16px; font-weight: 700; }
  .pillar-bar { height: 3px; background: var(--border); border-radius: 2px; margin-top: 6px; overflow: hidden; }
  .pillar-bar-fill { height: 100%; transition: width 200ms ease; } .pillar-bar-fill.ok { background: var(--accent); } .pillar-bar-fill.info { background: var(--info); } .pillar-bar-fill.warn { background: var(--warn); } .pillar-bar-fill.bad { background: var(--bad); }
  .kv-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .kv-table { width: 100%; border-collapse: collapse; } .kv-table td { padding: 4px 0; font-size: 12px; }
  .kv-table td:first-child { color: var(--dim); } .kv-table td:last-child { text-align: right; color: var(--text); }
  .kv-table td.sub-link { color: var(--warn); }
  .gaps-box { border-radius: 4px; padding: 12px; } .gaps-box.warn { background: #1a1308; border: 1px solid #3d2f0a; } .gaps-box.ok { background: var(--accent-dim); border: 1px solid #1f4d2a; }
  .gaps-box .tag { font-weight: 700; font-size: 11px; color: var(--warn); } .gaps-box.ok .tag { color: var(--accent); }
  .findings-list .finding { border-left: 3px solid var(--dim); background: var(--panel-2); border-radius: 0 4px 4px 0; padding: 10px 12px; margin-bottom: 10px; }
  .finding.sev-critical, .finding.sev-high { border-left-color: var(--bad); }
  .finding.sev-medium { border-left-color: var(--warn); }
  .finding.sev-low, .finding.sev-info { border-left-color: var(--info); }
  .finding-head { display: flex; gap: 8px; align-items: center; margin-bottom: 4px; flex-wrap: wrap; }
  .sev-tag { font-size: 9px; font-weight: 700; padding: 1px 6px; border-radius: 3px; }
  .sev-tag.sev-critical, .sev-tag.sev-high { background: #3d1414; color: var(--bad); }
  .sev-tag.sev-medium { background: #3d2f0a; color: var(--warn); }
  .sev-tag.sev-low, .sev-tag.sev-info { background: #0e2440; color: var(--info); }
  .finding-title { font-weight: 700; } .finding-pillar { margin-left: auto; color: var(--dim); font-size: 10px; }
  .finding-desc, .finding-verify { color: var(--dim); font-size: 12px; margin-bottom: 4px; }
  .finding-impact, .finding-fix { font-size: 12px; margin-bottom: 4px; } .finding-fix { color: var(--accent); }
  .prompt-src { position: absolute; left: -9999px; }
  .copy-btn { background: var(--panel); border: 1px solid var(--border); color: var(--text); border-radius: 3px; padding: 4px 10px; font-size: 11px; font-family: var(--mono); cursor: pointer; }
  .copy-btn:hover { border-color: var(--accent); color: var(--accent); }
  .fixpanel { border-color: #2b3a45; }
  .fixpanel-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .fixpanel-title { font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text); font-weight: 700; }
  .fixpanel-sub { font-size: 11px; color: var(--dim); }
  .fixpanel-head .copy-btn { margin-left: auto; }
  .fixpanel-note { color: var(--dim); font-size: 11px; margin: 8px 0 10px; }
  .fixpanel-body { background: #050708; border: 1px solid var(--border); border-radius: 4px; padding: 12px; margin: 0; max-height: 320px; overflow: auto; font-size: 11px; line-height: 1.45; white-space: pre-wrap; word-break: break-word; color: var(--text); }
  details.diag, details.raw, details.ticker { background: var(--panel); border: 1px solid var(--border); border-radius: 6px; margin-bottom: 16px; }
  details.diag summary, details.raw summary, details.ticker summary { cursor: pointer; padding: 14px 16px; color: var(--dim); font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; font-weight: 700; }
  .diag-body { padding: 0 16px 16px; }
  .diag-intro { color: var(--dim); font-size: 11px; margin: 0 0 14px; }
  .diag-block { border-top: 1px solid var(--border); padding: 14px 0 4px; }
  .diag-block h3 { font-size: 10px; text-transform: uppercase; letter-spacing: 0.07em; color: var(--accent); margin: 0 0 8px; display: flex; align-items: center; gap: 8px; }
  .diag-count { color: var(--dim); font-size: 10px; text-transform: none; letter-spacing: 0; }
  .diag-sub { color: var(--dim); font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; margin: 10px 0 6px; }
  .diag-table { width: 100%; border-collapse: collapse; font-size: 11px; }
  .diag-table th { text-align: left; color: var(--dim); font-weight: 400; font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em; padding: 0 8px 4px 0; border-bottom: 1px solid var(--border); }
  .diag-table td { padding: 4px 8px 4px 0; vertical-align: top; border-bottom: 1px solid #141a20; }
  .diag-table td.k { color: var(--dim); width: 38%; }
  .diag-table.kv td.k { width: 30%; }
  .diag-table td.v { color: var(--text); }
  .diag-table td:last-child { text-align: right; white-space: nowrap; }
  .mono { font-family: var(--mono); }
  .dim-note { color: var(--dim); font-size: 10px; }
  .verdict { font-size: 9px; font-weight: 700; padding: 1px 6px; border-radius: 3px; text-transform: uppercase; }
  .verdict.ok { background: var(--accent-dim); color: var(--accent); }
  .verdict.bad { background: #3d1414; color: var(--bad); }
  .diag-note { color: var(--dim); font-size: 10px; margin: 6px 0 0; }
  .diag-empty-ok { color: var(--accent); font-size: 11px; }
  .trace { background: #050708; border: 1px solid var(--border); border-radius: 4px; padding: 10px 12px; margin: 0; font-size: 11px; line-height: 1.5; white-space: pre-wrap; word-break: break-word; color: var(--text); }
  .trace.small { font-size: 10px; }
  .ticker-body { max-height: 420px; overflow-y: auto; padding: 0 16px 16px; font-size: 12px; }
  .ticker-line { color: var(--accent); white-space: pre-wrap; }
  .empty { color: var(--dim); font-style: italic; }
  footer { color: var(--dim); font-size: 11px; text-align: center; margin-top: 30px; }
  /* ---- document structure: title block, contents, numbered sections ---- */
  html { scroll-behavior: smooth; }
  section[id], details[id], div[id^="finding-"] { scroll-margin-top: 14px; }
  .brand-sub { color: var(--dim); font-weight: 400; }
  .titleblock { margin: 2px 0 16px; }
  .kicker { font-size: 9px; letter-spacing: 0.2em; color: var(--accent); text-transform: uppercase; }
  .titleblock h1 { font-size: 21px; margin: 6px 0 3px; letter-spacing: -0.01em; font-weight: 700; word-break: break-all; }
  .subtitle { color: var(--dim); font-size: 12px; }
  .toc { display: flex; flex-wrap: wrap; gap: 4px; margin: 0 0 18px; padding: 8px; background: var(--panel-2); border: 1px solid var(--border); border-radius: 6px; }
  .toc a { color: var(--dim); text-decoration: none; font-size: 11px; padding: 5px 9px; border-radius: 4px; border: 1px solid transparent; }
  .toc a:hover { color: var(--text); border-color: var(--border); background: var(--panel); }
  .toc a .n { color: var(--accent); margin-right: 5px; }
  summary .n { color: var(--accent); margin-right: 8px; font-variant-numeric: tabular-nums; }
  section.panel { padding: 18px; }
  section.panel > h2 { margin-bottom: 14px; font-size: 11px; }
  .panel h2 .n { color: var(--accent); font-variant-numeric: tabular-nums; letter-spacing: 0; }
  .tally { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 16px; }
  .tally-item { flex: 1; min-width: 88px; background: var(--panel-2); border: 1px solid var(--border); border-radius: 5px; padding: 9px 12px; }
  .tally-item .n { font-size: 19px; font-weight: 700; line-height: 1.15; }
  .tally-item .l { font-size: 9px; letter-spacing: 0.1em; color: var(--dim); text-transform: uppercase; }
  .tally-item.bad .n { color: var(--bad); } .tally-item.warn .n { color: var(--warn); }
  .tally-item.info .n { color: var(--info); } .tally-item.ok .n { color: var(--accent); }
  .verdict-line { margin: 14px 0 0; padding: 11px 13px; border-left: 3px solid var(--accent); background: var(--panel-2); border-radius: 0 4px 4px 0; font-size: 12px; }
  .verdict-line .gaps-box { border: 0; padding: 0; background: none; }
  table.summary { width: 100%; border-collapse: collapse; margin-bottom: 18px; font-size: 12px; }
  table.summary th { text-align: left; color: var(--dim); font-weight: 400; font-size: 9px; text-transform: uppercase; letter-spacing: 0.09em; padding: 0 10px 6px 0; border-bottom: 1px solid var(--border); }
  table.summary td { padding: 7px 10px 7px 0; border-bottom: 1px solid #141a20; vertical-align: middle; }
  table.summary tr:hover td { background: var(--panel-2); }
  table.summary td a { color: var(--text); text-decoration: none; }
  table.summary td a:hover { color: var(--accent); text-decoration: underline; }
  table.summary td.area { color: var(--dim); font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; }
  table.summary td.conf { color: var(--dim); font-size: 11px; }
  .count-pill { display: inline-block; min-width: 18px; text-align: center; border-radius: 3px; padding: 0 5px; font-size: 10px; font-weight: 700; background: var(--panel); border: 1px solid var(--border); }
  details.panel > summary { cursor: pointer; list-style: none; }
  details.panel > summary::-webkit-details-marker { display: none; }
  .fixpanel-inner { padding-top: 4px; }
  details.panel[open] > summary.fixpanel-head { margin-bottom: 12px; }
  .empty-ok { color: var(--accent); font-size: 12px; }

  @media (max-width: 720px) { .kv-grid { grid-template-columns: 1fr; } .change-row { flex-wrap: wrap; gap: 14px; } }
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <div class="brand">[sec]layer <span class="brand-sub">// ScanLayer Hybrid</span></div>
    <div class="meta">Generated ${esc(generatedAt.toISOString().slice(0, 16).replace('T', ' '))} UTC<br>VibeScan + SecLayer engines (verbatim)</div>
  </header>

  <div class="titleblock">
    <div class="kicker">Security assessment</div>
    <h1>${esc(target)}</h1>
    <div class="subtitle">Black-box assessment of the public surface — unauthenticated and non-destructive, with every finding tied to the evidence that produced it.</div>
  </div>

  <nav class="toc">${toc}</nav>

  <section id="summary" class="panel">
    <h2><span class="n">${num('summary')}</span> Summary</h2>

    <div class="score-row">
      <div class="score-circle ${scoreCls}">
        <div class="num">${score}<span style="font-size:12px;color:var(--dim);">/100</span></div>
        <div class="grade">GRADE ${esc(grade)}</div>
      </div>
      <div class="score-info">
        <div class="target">${esc(target)}</div>
        <div class="posture ${RISK_LABEL_CLASS[posture.postureRating] ?? 'warn'}">POSTURE RATING: ${esc(posture.postureRating)}</div>
        <div class="findings-bar-lbl">${provenCount} proven &middot; ${confirmedCount} confirmed &middot; ${toVerifyCount} to verify</div>
      </div>
    </div>

    <div class="tally">
      <div class="tally-item ${countSev('critical') + countSev('high') > 0 ? 'bad' : ''}"><div class="n">${countSev('critical') + countSev('high')}</div><div class="l">Critical + high</div></div>
      <div class="tally-item ${countSev('medium') > 0 ? 'warn' : ''}"><div class="n">${countSev('medium')}</div><div class="l">Medium</div></div>
      <div class="tally-item ${countSev('low') > 0 ? 'info' : ''}"><div class="n">${countSev('low')}</div><div class="l">Low</div></div>
      <div class="tally-item ${countSev('info') > 0 ? 'ok' : ''}"><div class="n">${countSev('info')}</div><div class="l">Info</div></div>
    </div>

    <p class="verdict-line">${esc(verdictLine)}</p>

    ${hardeningGapsBox(posture, findings)}

    <h2 style="margin-top:18px;">Executive summary ${usedRealAi ? '<span class="ai-badge">AI analyst</span>' : ''}</h2>
    ${aiReport?.aiSummary ? `<div>${esc(aiReport.aiSummary)}</div>` : '<div class="empty">No engine result for this target.</div>'}

    ${(overview || riskAreas.length || businessImpact || priorityActions.length) ? `
    <details class="panel" style="margin:16px 0 0;background:var(--panel-2)">
      <summary style="cursor:pointer;color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:0.08em;font-weight:700;">Detailed breakdown &amp; priority actions</summary>
      <div style="padding-top:12px;">
        ${overview ? `<div style="margin-bottom:12px;">${esc(overview)}</div>` : ''}
        ${riskAreas.length ? `<div style="color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:0.06em;margin-bottom:8px;">Key Risk Areas</div><div class="risk-grid">${riskAreas.map((r) => `<div class="risk-card"><div class="t">${esc(r.area)}</div><div class="d">${esc(r.detail)}</div></div>`).join('')}</div>` : ''}
        ${businessImpact ? `<div class="impact-box"><div class="tag">BUSINESS IMPACT</div><div style="margin-top:4px;">${esc(businessImpact)}</div></div>` : ''}
        ${priorityActions.length ? `<div style="color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:0.06em;margin-top:12px;">Priority Actions (Ranked)</div><ol class="priority-list">${priorityActions.map((a) => `<li>${esc(a)}</li>`).join('')}</ol>` : ''}
      </div>
    </details>` : ''}
  </section>

  ${changeBox(data?.change)}

  <section id="findings" class="panel">
    <h2><span class="n">${num('findings')}</span> Findings</h2>
    ${ordered.length ? `
    <table class="summary">
      <thead><tr><th>Severity</th><th>Finding</th><th>Area</th><th>Confidence</th><th>Status</th></tr></thead>
      <tbody>${ordered.map((f, i) => `<tr>
        <td>${severityTag(f.severity)}</td>
        <td><a href="#finding-${i + 1}">${esc(f.title)}</a></td>
        <td class="area">${esc(f.category)}</td>
        <td class="conf">${esc(f.confidence ?? 'unrated')}</td>
        <td class="conf">${esc(statusOf(f))}</td>
      </tr>`).join('')}</tbody>
    </table>
    <div class="findings-list">${ordered.map((f, i) => renderFindingCard(f, i + 1)).join('')}</div>`
    : '<div class="empty-ok">No findings. Every check that could run came back clean.</div>'}
  </section>

  ${fixPromptPanel(fixPrompt, findings.length, num('fixplan'))}

  <section id="coverage" class="panel">
    <h2><span class="n">${num('coverage')}</span> Coverage</h2>
    <div class="chips" style="margin-bottom:14px;">${PILLARS.map((p) => renderPillarChip(p, pillarCounts[p.key])).join('')}</div>
    <div class="pillar-grid">${PILLARS.map((p) => renderPillarCard(p, pillarCounts[p.key], pillarBadges[p.key], findings.length)).join('')}</div>
    <div class="panel" style="margin:16px 0 0;background:var(--panel-2)">
      <h2>Dynamic coverage (DAST)</h2>
      <table class="kv-table">
        <tr><td>Sensitive paths</td><td>${totalPaths} probed, ${exposedPaths === 0 ? 'all locked down' : `${exposedPaths} exposed`}</td></tr>
        <tr><td>Crawl coverage</td><td>${seclayer?.crawl?.pagesVisited ?? vibescan?.pagesScanned?.length ?? 0} page(s), ${seclayer?.crawl?.endpointsDiscovered ?? 0} endpoint(s)</td></tr>
        <tr><td>Params fuzzed</td><td>${seclayer?.crawl?.paramsTested ?? 0}</td></tr>
        <tr><td>Detected libraries</td><td>${vulnLibs.length ? esc(vulnLibs.map((l) => l.name).join(', ')) : 'none flagged'}</td></tr>
      </table>
    </div>
    <details class="raw" style="margin-top:16px;margin-bottom:0;">
      <summary>Check-by-check coverage${coverage ? ` &middot; ${coverage.totalChecks} checks &middot; ${ranGroups.size}/${groups.size} groups` : ''}</summary>
      <div class="diag-body">${coverage ? `<table class="diag-table"><tbody>${coverage.items.map((i) => `<tr><td class="k">${i.ran ? '<span class="verdict ok">ran</span>' : '<span class="dim-note">skipped</span>'} ${esc(i.label)}</td><td class="v dim-note">${esc(i.category)}</td><td class="v">${esc(i.checks)} check${i.checks === 1 ? '' : 's'}${i.note ? ` <span class="dim-note">— ${esc(i.note)}</span>` : ''}</td></tr>`).join('')}</tbody></table>` : 'No coverage record.'}</div>
    </details>
  </section>

  <section id="surface" class="panel">
    <h2><span class="n">${num('surface')}</span> Attack surface</h2>
    <table class="kv-table">
      <tr><td>Resolved IP</td><td>${esc(evidence?.resolvedIp ?? '-')}</td></tr>
      <tr><td>Nameserver</td><td>${esc(evidence?.nameserver ?? '-')}</td></tr>
      <tr><td>Protocol / status</td><td>${esc(evidence?.protocol ?? '-')} &middot; HTTP ${esc(evidence?.responseStatus ?? '-')}</td></tr>
      <tr><td>Server header</td><td>${esc(evidence?.serverHeader ?? '-')}</td></tr>
      <tr><td>Live subdomains</td><td>${liveSubdomains.length ? esc(liveSubdomains.join(', ')) : '<span class="dim-note">none of the probed candidates answered</span>'}</td></tr>
    </table>
  </section>

  ${renderDiagnostics({ seclayer, evidence, vibescan, n: num('evidence') })}

  <details class="ticker" id="log">
    <summary><span class="n">${num('log')}</span> Scan log (${tickerLines.length} line(s))</summary>
    <div class="ticker-body">${tickerLines.length ? tickerLines.map((l) => `<div class="ticker-line">${esc(l)}</div>`).join('') : '<div class="empty">No ticker output captured.</div>'}</div>
  </details>

  <footer>Generated by ScanLayer Hybrid (VibeScan + SecLayer engines, verbatim) &mdash; for the target's own owner only.</footer>
</div>
<script>
function copyFix(id, btn) {
  var el = document.getElementById(id);
  if (!el) return;
  var text = el.value;
  var done = function () { var old = btn.textContent; btn.textContent = 'Copied!'; setTimeout(function () { btn.textContent = old; }, 1500); };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done).catch(function () { el.style.position = 'static'; el.select(); document.execCommand('copy'); el.style.position = 'absolute'; done(); });
  } else {
    el.style.position = 'static'; el.select(); document.execCommand('copy'); el.style.position = 'absolute'; done();
  }
}
</script>
</body>
</html>`;
}
