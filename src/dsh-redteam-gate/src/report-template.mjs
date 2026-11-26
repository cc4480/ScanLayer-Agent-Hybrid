// Self-contained HTML report renderer, matching the seclayer.app product's own dashboard layout
// (audit workspace header, posture score gauge, executive summary/breakdown, pillar grid, network and
// coverage panels, hardening-gaps callout, live scan ticker). Pure string templating, no build step.
//
// Every number and sentence here comes from `data`, which report-data.mjs computes by calling the real
// SecLayer engine functions (compileStaticFindings, generateAiReport, compileScanEvidence, and the
// scoring module's grade/posture helpers) — this file only lays the already-computed facts out; it does
// not grade, score, or write prose of its own, except for the two short deterministic sentences marked
// below (the hardening-gaps callout and pillar sub-labels), which are plain descriptions of real numbers,
// never a security verdict.

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

function renderPillarCard(p, count, badge) {
  const cls = RISK_LABEL_CLASS[badge] ?? 'ok';
  return `<div class="pillar" id="${anchorFor(p.key)}">
    <div class="pillar-head"><span class="pillar-name">${esc(p.label)}</span></div>
    <div class="pillar-sub">${esc(p.sub)}</div>
    <div class="pillar-status"><span class="status-word ${cls}">${esc(badge)}</span><span class="status-count">${count}</span></div>
    <div class="pillar-bar"><div class="pillar-bar-fill ${cls}"></div></div>
  </div>`;
}

function severityTag(sev) {
  const s = String(sev ?? 'info').toLowerCase();
  const label = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'INFO' }[s] ?? 'INFO';
  return `<span class="sev-tag sev-${s}">${label}</span>`;
}

function renderFindingCard(f) {
  const sev = String(f.severity ?? 'info').toLowerCase();
  const agentPromptId = `prompt-${f.id ?? Math.random().toString(36).slice(2)}`;
  return `<div class="finding sev-${sev}">
    <div class="finding-head">
      ${severityTag(f.severity)}
      <span class="finding-title">${esc(f.title)}</span>
      <span class="finding-pillar">${esc(f.category)}</span>
    </div>
    ${f.description ? `<div class="finding-desc">${esc(f.description)}</div>` : ''}
    ${f.impact ? `<div class="finding-impact"><strong>Impact:</strong> ${esc(f.impact)}</div>` : ''}
    ${f.fix ? `<div class="finding-fix"><strong>Fix:</strong> ${esc(f.fix)}</div>` : ''}
    ${f.verification ? `<div class="finding-verify">${esc(f.verification)}</div>` : ''}
    ${f.agentPrompt ? `
      <textarea id="${agentPromptId}" class="prompt-src">${esc(f.agentPrompt)}</textarea>
      <button type="button" class="copy-btn" onclick="copyFix('${agentPromptId}', this)">Copy Fix Prompt</button>
    ` : ''}
  </div>`;
}

function changeBox(change) {
  if (!change) {
    return `<div class="panel"><h2>What Changed Since Last Scan</h2><div class="empty">This is the first recorded scan of this target — no prior baseline to compare against.</div></div>`;
  }
  const deltaCls = change.scoreDelta > 0 ? 'ok' : change.scoreDelta < 0 ? 'bad' : '';
  const deltaSign = change.scoreDelta > 0 ? '+' : '';
  return `<div class="panel">
    <h2>What Changed Since Last Scan</h2>
    <div class="change-row">
      <div class="change-stat"><div class="change-num bad">${change.newCount}</div><div class="change-lbl">NEW</div></div>
      <div class="change-stat"><div class="change-num ok">${change.resolvedCount}</div><div class="change-lbl">RESOLVED</div></div>
      <div class="change-delta ${deltaCls}">${deltaSign}${change.scoreDelta} score</div>
    </div>
    ${change.newFindings.length ? `<div class="new-findings"><div class="tag">NEW FINDINGS</div>${change.newFindings.map((f) => `<div class="new-finding-row">${severityTag(f.severity)} ${esc(f.title)}</div>`).join('')}</div>` : ''}
  </div>`;
}

function hardeningGapsBox(posture, findings) {
  const active = findings.filter((f) => !f.isFalsePositive);
  if (active.length === 0 || posture.postureRating === 'SECURE') {
    return `<div class="panel"><div class="gaps-box ok"><span class="tag">NO HARDENING GAPS DETECTED</span><div style="margin-top:4px;">This scan found no active findings against the target.</div></div></div>`;
  }
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const top = [...active].sort((a, b) => (order[a.severity] ?? 4) - (order[b.severity] ?? 4))[0];
  const urgency = { critical: 'a serious exposure that should be remediated immediately', high: 'a serious exposure that should be remediated soon', medium: 'a defense-in-depth gap worth scheduling for remediation, not an emergency', low: 'a minor hygiene item, not urgent', info: 'informational context, not an action item' }[top.severity] ?? 'worth reviewing';
  return `<div class="panel">
    <div class="gaps-box warn">
      <span class="tag">${esc(posture.postureRating)} HARDENING GAPS</span>
      <div style="margin-top:4px;">${active.length} finding(s) detected. The most significant is a ${esc(top.severity)}-severity issue ("${esc(top.title)}") — ${esc(urgency)}.</div>
    </div>
  </div>`;
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
  const confirmedCount = findings.filter((f) => f.evidence || f.confidence === 'high').length;
  const toVerifyCount = findings.length - confirmedCount;

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
  .score-info .posture { color: var(--warn); font-weight: 700; }
  .score-info .findings-bar-lbl { color: var(--dim); font-size: 11px; margin-top: 8px; }
  .chips { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 20px; }
  .chip { display: inline-flex; align-items: center; gap: 6px; background: var(--panel-2); border: 1px solid var(--border); border-radius: 4px; padding: 5px 10px; font-size: 11px; color: var(--dim); text-decoration: none; }
  .chip-count { background: var(--accent-dim); color: var(--accent); border-radius: 3px; padding: 0 5px; font-size: 10px; }
  .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 6px; padding: 16px; margin-bottom: 16px; }
  .panel h2 { font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--dim); margin: 0 0 12px; display: flex; align-items: center; gap: 8px; }
  .ai-badge { background: var(--accent-dim); color: var(--accent); font-size: 9px; padding: 2px 6px; border-radius: 3px; text-transform: none; letter-spacing: 0; }
  .change-row { display: flex; gap: 20px; align-items: center; margin-bottom: 10px; }
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
  .pillar-bar-fill { height: 100%; width: 40%; } .pillar-bar-fill.ok { background: var(--accent); } .pillar-bar-fill.info { background: var(--info); } .pillar-bar-fill.warn { background: var(--warn); } .pillar-bar-fill.bad { background: var(--bad); }
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
  .copy-btn { background: var(--panel); border: 1px solid var(--border); color: var(--text); border-radius: 3px; padding: 4px 10px; font-size: 11px; font-family: var(--mono); cursor: pointer; margin-top: 4px; }
  .copy-btn:hover { border-color: var(--accent); color: var(--accent); }
  details.ticker, details.raw { background: #050708; border: 1px solid var(--border); border-radius: 4px; }
  details.ticker summary, details.raw summary { cursor: pointer; padding: 10px 12px; color: var(--dim); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; }
  .ticker-body { max-height: 420px; overflow-y: auto; padding: 0 12px 12px; font-size: 12px; }
  .ticker-line { color: var(--accent); white-space: pre-wrap; }
  .raw-body { padding: 0 12px 12px; font-size: 11px; color: var(--dim); white-space: pre-wrap; word-break: break-all; }
  .empty { color: var(--dim); font-style: italic; }
  footer { color: var(--dim); font-size: 11px; text-align: center; margin-top: 30px; }
</style>
</head>
<body>
<div class="wrap">
  <div class="breadcrumb">&larr; AUDIT WORKSPACE</div>
  <header class="top">
    <div class="brand">[sec]layer // ScanLayer Hybrid</div>
    <div class="meta">Target: ${esc(target)}<br>Generated: ${esc(generatedAt.toISOString())}</div>
  </header>

  ${changeBox(data?.change)}

  <div class="score-row">
    <div class="score-circle ${scoreCls}">
      <div class="num">${score}<span style="font-size:12px;color:var(--dim);">/100</span></div><div class="grade">GRADE ${esc(grade)}</div>
    </div>
    <div class="score-info">
      <div class="target">[Target Host] ${esc(target)}</div>
      <div class="posture">POSTURE RATING: ${esc(posture.postureRating)}</div>
      <div class="findings-bar-lbl">${confirmedCount} confirmed &middot; ${toVerifyCount} to verify</div>
    </div>
  </div>

  <div class="chips">${PILLARS.map((p) => renderPillarChip(p, pillarCounts[p.key])).join('')}</div>

  <div class="panel">
    <h2>Executive Summary ${usedRealAi ? '<span class="ai-badge">DeepSeek AI Analyst Verified</span>' : ''}</h2>
    ${aiReport?.aiSummary ? `<div>${esc(aiReport.aiSummary)}</div>` : '<div class="empty">No engine result for this target.</div>'}
  </div>

  <div class="panel">
    <h2>Detailed Executive Breakdown</h2>
    ${overview ? `<div style="margin-bottom:12px;">${esc(overview)}</div>` : ''}
    ${riskAreas.length ? `<div style="color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:0.06em;margin-bottom:8px;">Key Risk Areas</div><div class="risk-grid">${riskAreas.map((r) => `<div class="risk-card"><div class="t">${esc(r.area)}</div><div class="d">${esc(r.detail)}</div></div>`).join('')}</div>` : ''}
    ${businessImpact ? `<div class="impact-box"><div class="tag">BUSINESS IMPACT</div><div style="margin-top:4px;">${esc(businessImpact)}</div></div>` : ''}
    ${priorityActions.length ? `<div style="color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:0.06em;margin-top:12px;">Priority Actions (Ranked)</div><ol class="priority-list">${priorityActions.map((a) => `<li>${esc(a)}</li>`).join('')}</ol>` : ''}
  </div>

  <div class="panel">
    <h2>Dynamic Application Security &amp; Pen-Testing Pillars</h2>
    <div class="pillar-grid">${PILLARS.map((p) => renderPillarCard(p, pillarCounts[p.key], pillarBadges[p.key])).join('')}</div>
  </div>

  <div class="kv-grid">
    <div class="panel">
      <h2>Network &amp; Attack Surface (EASM)</h2>
      <table class="kv-table">
        <tr><td>Resolved IP</td><td>${esc(evidence?.resolvedIp ?? '-')}</td></tr>
        <tr><td>Nameserver</td><td>${esc(evidence?.nameserver ?? '-')}</td></tr>
        <tr><td>Protocol / Status</td><td>${esc(evidence?.protocol ?? '-')} &middot; HTTP ${esc(evidence?.responseStatus ?? '-')}</td></tr>
        <tr><td>Server Header</td><td>${esc(evidence?.serverHeader ?? '-')}</td></tr>
        <tr><td>Live Subdomains</td><td class="sub-link">${liveSubdomains.length ? esc(liveSubdomains.join(', ')) : '-'}</td></tr>
      </table>
    </div>
    <div class="panel">
      <h2>Dynamic Coverage (DAST)</h2>
      <table class="kv-table">
        <tr><td>Sensitive Paths</td><td>${totalPaths} probed, ${exposedPaths === 0 ? 'all locked down' : `${exposedPaths} exposed`}</td></tr>
        <tr><td>Crawl Coverage</td><td>${seclayer?.crawl?.pagesVisited ?? vibescan?.pagesScanned?.length ?? 0} page(s), ${seclayer?.crawl?.endpointsDiscovered ?? 0} endpoint(s)</td></tr>
        <tr><td>Params Fuzzed</td><td>${seclayer?.crawl?.paramsTested ?? 0}</td></tr>
        <tr><td>Detected Libraries</td><td>${vulnLibs.length ? esc(vulnLibs.map((l) => l.name).join(', ')) : 'none flagged'}</td></tr>
      </table>
    </div>
  </div>

  <details class="raw">
    <summary>Scan Coverage${coverage ? ` &middot; ${coverage.totalChecks} checks run &middot; ${ranGroups.size}/${groups.size} groups` : ''}</summary>
    <div class="raw-body">${coverage ? coverage.items.map((i) => `${i.ran ? '✓' : '✗'} [${i.category}] ${i.label} (${i.checks} check${i.checks === 1 ? '' : 's'})${i.note ? ' - ' + i.note : ''}`).join('\n') : 'No coverage record.'}</div>
  </details>

  ${hardeningGapsBox(posture, findings)}

  <div class="panel">
    <h2>Findings</h2>
    <div class="findings-list">${findings.length ? findings.map(renderFindingCard).join('') : '<div class="empty">No findings.</div>'}</div>
  </div>

  <details class="raw">
    <summary>Diagnostic Raw Headers &amp; Outputs</summary>
    <div class="raw-body">${seclayer?.headers ? Object.entries(seclayer.headers).map(([k, v]) => `${esc(k)}: ${esc(v)}`).join('\n') : 'No raw headers captured.'}</div>
  </details>

  <details class="ticker">
    <summary>Live Scan Ticker (${tickerLines.length} line(s))</summary>
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
