// Self-contained HTML report renderer, in the dark console/dashboard style the seclayer.app product
// itself uses (posture score, pillar grid, risk areas, network/attack-surface panels, live ticker
// transcript). Pure string templating, no build step, no external assets: one HTML file an operator
// can open directly or attach to an email.
//
// Input is the combined result of a SecLayer scan (server/scanner.ts's DiagnosticResult) and, optionally,
// a VibeScan scan (api-server's ScanResult) run against the same target. Either may be omitted; the
// report degrades gracefully to "no data" for the pillars that fed from the missing engine.

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEVERITY_LABEL = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'INFO' };

function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function severityWeight(sev) {
  return SEVERITY_ORDER[String(sev ?? 'info').toLowerCase()] ?? 4;
}

/** Collapse SecLayer's several finding arrays and VibeScan's vulnerabilities into one normalized list. */
function collectFindings(seclayer, vibescan) {
  const out = [];
  for (const f of seclayer?.sastFindings ?? []) {
    out.push({ pillar: 'SAST', title: f.issue, severity: f.severity, description: f.description, fix: f.fix, evidence: f.masked });
  }
  for (const f of seclayer?.scaLibraries ?? []) {
    if (f.status !== 'vuln') continue;
    out.push({ pillar: 'SCA', title: `${f.name} ${f.version}`, severity: f.severity, description: f.description, fix: f.fix, evidence: (f.advisories ?? []).join(', ') });
  }
  for (const p of seclayer?.probedPaths ?? []) {
    if (!p.exposed) continue;
    const m = p.meta;
    out.push({ pillar: 'DAST', title: m?.title ?? `Exposed path: ${p.path}`, severity: m?.severity ?? 'high', description: m?.description ?? `${p.path} returned HTTP ${p.status}.`, fix: m?.fix ?? 'Restrict or remove public access to this path.' });
  }
  for (const issue of seclayer?.cookieIssues ?? []) {
    out.push({ pillar: 'IAST', title: 'Cookie issue', severity: 'medium', description: issue });
  }
  for (const h of seclayer?.missingHeaders ?? []) {
    out.push({ pillar: 'IAST', title: `Missing header: ${h}`, severity: 'info', description: `The response did not set ${h}.` });
  }
  for (const f of seclayer?.redTeamFindings ?? []) {
    out.push({ pillar: 'RED_TEAM', title: f.title ?? f.name ?? 'Red-team finding', severity: f.severity ?? 'medium', description: f.description ?? '', evidence: f.evidence });
  }
  for (const f of seclayer?.apiSecFindings ?? []) {
    out.push({ pillar: 'API_SEC', title: f.testName, severity: f.severity, description: f.description, fix: f.fix, evidence: f.endpoint });
  }
  for (const v of vibescan?.vulnerabilities ?? []) {
    out.push({ pillar: 'DAST', title: v.name, severity: v.severity, description: v.description, fix: v.solution, evidence: v.evidence, cwe: v.cweId });
  }
  out.sort((a, b) => severityWeight(a.severity) - severityWeight(b.severity));
  return out;
}

function pillarCounts(findings) {
  const pillars = ['SAST', 'DAST', 'IAST', 'SCA', 'EASM', 'API_SEC', 'RED_TEAM'];
  const counts = Object.fromEntries(pillars.map((p) => [p, 0]));
  for (const f of findings) if (counts[f.pillar] !== undefined) counts[f.pillar] += 1;
  return counts;
}

function pillarStatus(count) {
  if (count === 0) return { label: 'SECURE', cls: 'ok' };
  if (count <= 2) return { label: 'MODERATE', cls: 'warn' };
  return { label: 'AT RISK', cls: 'bad' };
}

function postureScore(findings) {
  let score = 100;
  for (const f of findings) {
    const w = { critical: 25, high: 12, medium: 5, low: 2, info: 0 }[String(f.severity ?? 'info').toLowerCase()] ?? 0;
    score -= w;
  }
  return Math.max(0, Math.min(100, Math.round(score)));
}

function postureLabel(score) {
  if (score >= 90) return 'STRONG';
  if (score >= 70) return 'MODERATE';
  if (score >= 40) return 'WEAK';
  return 'CRITICAL';
}

function renderPillarCard(name, count) {
  const st = pillarStatus(count);
  return `<div class="pillar">
    <div class="pillar-head"><span class="pillar-name">${esc(name)}</span><span class="pillar-badge ${st.cls}">${st.label}</span></div>
    <div class="pillar-count">${count}</div>
  </div>`;
}

function renderFindingRow(f) {
  const sev = String(f.severity ?? 'info').toLowerCase();
  return `<div class="finding sev-${sev}">
    <div class="finding-head">
      <span class="sev-tag sev-${sev}">${SEVERITY_LABEL[sev] ?? 'INFO'}</span>
      <span class="finding-title">${esc(f.title)}</span>
      <span class="finding-pillar">${esc(f.pillar)}</span>
    </div>
    ${f.description ? `<div class="finding-desc">${esc(f.description)}</div>` : ''}
    ${f.evidence ? `<div class="finding-evidence"><code>${esc(typeof f.evidence === 'string' ? f.evidence : JSON.stringify(f.evidence))}</code></div>` : ''}
    ${f.fix ? `<div class="finding-fix"><strong>Fix:</strong> ${esc(f.fix)}</div>` : ''}
  </div>`;
}

/**
 * @param {{
 *   target: string,
 *   seclayer?: object,
 *   vibescan?: object,
 *   tickerLines?: string[],
 *   generatedAt?: Date,
 * }} input
 * @returns {string} a complete, self-contained HTML document
 */
export function renderScanReportHtml({ target, seclayer, vibescan, tickerLines = [], generatedAt = new Date() }) {
  const findings = collectFindings(seclayer, vibescan);
  const counts = pillarCounts(findings);
  const easmCount =
    (seclayer?.easmPerimeter?.subdomains ?? []).filter((s) => s.status === 'live').length > 6 ? 1 : 0;
  counts.EASM = easmCount;
  const score = postureScore(findings);
  const label = postureLabel(score);
  const topFindings = findings.slice(0, 3);
  const totalFindings = findings.length;
  const resolvedIp = seclayer?.easmPerimeter?.ip ?? '-';
  const nameserver = seclayer?.easmPerimeter?.nameserver ?? '-';
  const protocol = seclayer?.easmPerimeter?.protocol ?? (seclayer?.sslSecure ? 'HTTPS' : seclayer?.headers ? 'HTTP' : '-');
  const server = seclayer?.headers?.server ?? vibescan?.server ?? '-';
  const pagesScanned = vibescan?.pagesScanned?.length ?? seclayer?.crawl?.pagesVisited ?? 0;
  const endpointsFound = seclayer?.crawl?.endpointsDiscovered ?? 0;
  const paramsFuzzed = seclayer?.crawl?.paramsTested ?? 0;
  const libsFlagged = (seclayer?.scaLibraries ?? []).filter((l) => l.status === 'vuln').length;
  const checksRun = (vibescan?.tests?.length ?? 0) + (seclayer?.coverage?.checksRun ?? 0);
  const groupsRun = seclayer?.coverage?.groupsRun ?? '-';

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
  .score-row { display: flex; gap: 20px; align-items: stretch; margin-bottom: 20px; flex-wrap: wrap; }
  .score-circle { width: 120px; height: 120px; border-radius: 50%; border: 6px solid var(--accent); display: flex; flex-direction: column; align-items: center; justify-content: center; flex-shrink: 0; }
  .score-circle.warn { border-color: var(--warn); } .score-circle.bad { border-color: var(--bad); }
  .score-circle .num { font-size: 28px; font-weight: 700; } .score-circle .lbl { font-size: 10px; color: var(--dim); }
  .score-info { flex: 1; min-width: 260px; background: var(--panel); border: 1px solid var(--border); border-radius: 6px; padding: 16px; }
  .score-info .target { font-size: 15px; font-weight: 700; margin-bottom: 4px; }
  .score-info .posture { color: var(--warn); font-weight: 700; }
  .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 6px; padding: 16px; margin-bottom: 16px; }
  .panel h2 { font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--dim); margin: 0 0 12px; }
  .risk-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }
  .risk-card { background: var(--panel-2); border: 1px solid var(--border); border-radius: 4px; padding: 12px; }
  .risk-card .t { font-weight: 700; margin-bottom: 4px; } .risk-card .d { color: var(--dim); font-size: 12px; }
  .impact-box { background: #1a1308; border: 1px solid #3d2f0a; border-radius: 4px; padding: 12px; margin-top: 12px; }
  .impact-box .tag { color: var(--warn); font-weight: 700; font-size: 11px; }
  .pillar-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; }
  .pillar { background: var(--panel-2); border: 1px solid var(--border); border-radius: 4px; padding: 10px 12px; }
  .pillar-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
  .pillar-name { font-size: 11px; color: var(--dim); } .pillar-count { font-size: 20px; font-weight: 700; }
  .pillar-badge { font-size: 9px; padding: 1px 6px; border-radius: 3px; }
  .pillar-badge.ok { background: var(--accent-dim); color: var(--accent); }
  .pillar-badge.warn { background: #3d2f0a; color: var(--warn); }
  .pillar-badge.bad { background: #3d1414; color: var(--bad); }
  .kv-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .kv-table { width: 100%; border-collapse: collapse; } .kv-table td { padding: 4px 0; font-size: 12px; }
  .kv-table td:first-child { color: var(--dim); } .kv-table td:last-child { text-align: right; color: var(--text); }
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
  .finding-desc { color: var(--dim); font-size: 12px; margin-bottom: 4px; }
  .finding-evidence code { display: block; background: #050708; border: 1px solid var(--border); border-radius: 3px; padding: 6px 8px; font-size: 11px; color: var(--text); white-space: pre-wrap; word-break: break-all; margin-bottom: 4px; }
  .finding-fix { font-size: 12px; color: var(--accent); }
  details.ticker { background: #050708; border: 1px solid var(--border); border-radius: 4px; }
  details.ticker summary { cursor: pointer; padding: 10px 12px; color: var(--dim); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; }
  .ticker-body { max-height: 420px; overflow-y: auto; padding: 0 12px 12px; font-size: 12px; }
  .ticker-line { color: var(--accent); white-space: pre-wrap; }
  .empty { color: var(--dim); font-style: italic; }
  footer { color: var(--dim); font-size: 11px; text-align: center; margin-top: 30px; }
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <div class="brand">[sec]layer // ScanLayer Hybrid</div>
    <div class="meta">Target: ${esc(target)}<br>Generated: ${esc(generatedAt.toISOString())}</div>
  </header>

  <div class="score-row">
    <div class="score-circle ${label === 'STRONG' ? '' : label === 'MODERATE' ? 'warn' : 'bad'}">
      <div class="num">${score}</div><div class="lbl">/ 100</div>
    </div>
    <div class="score-info">
      <div class="target">${esc(target)}</div>
      <div class="posture">POSTURE: ${esc(label)}</div>
      <div style="color: var(--dim); margin-top: 6px;">${totalFindings} active finding(s) across ${Object.values(counts).filter((c) => c > 0).length} area(s).</div>
    </div>
  </div>

  <div class="panel">
    <h2>Key Risk Areas</h2>
    ${topFindings.length ? `<div class="risk-grid">${topFindings.map((f) => `<div class="risk-card"><div class="t">${esc(f.pillar)}</div><div class="d">${esc(f.title)}</div></div>`).join('')}</div>` : '<div class="empty">No active findings.</div>'}
    ${totalFindings > 0 ? `<div class="impact-box"><div class="tag">BUSINESS IMPACT</div><div style="margin-top:4px;">${totalFindings} finding(s) detected; review severity above before scheduling remediation.</div></div>` : ''}
  </div>

  <div class="panel">
    <h2>Dynamic Application Security &amp; Pen-Testing Pillars</h2>
    <div class="pillar-grid">${Object.entries(counts).map(([name, c]) => renderPillarCard(name, c)).join('')}</div>
  </div>

  <div class="kv-grid">
    <div class="panel">
      <h2>Network &amp; Attack Surface (EASM)</h2>
      <table class="kv-table">
        <tr><td>Resolved IP</td><td>${esc(resolvedIp)}</td></tr>
        <tr><td>Nameserver</td><td>${esc(nameserver)}</td></tr>
        <tr><td>Protocol / Status</td><td>${esc(protocol)}</td></tr>
        <tr><td>Server Header</td><td>${esc(server)}</td></tr>
      </table>
    </div>
    <div class="panel">
      <h2>Dynamic Coverage (DAST)</h2>
      <table class="kv-table">
        <tr><td>Pages Crawled</td><td>${esc(pagesScanned)}</td></tr>
        <tr><td>Endpoints Found</td><td>${esc(endpointsFound)}</td></tr>
        <tr><td>Params Fuzzed</td><td>${esc(paramsFuzzed)}</td></tr>
        <tr><td>Libraries Flagged</td><td>${esc(libsFlagged)}</td></tr>
      </table>
    </div>
  </div>

  <div class="panel">
    <h2>Scan Coverage</h2>
    <div style="color: var(--dim); font-size:12px;">${esc(checksRun)} checks run &middot; ${esc(groupsRun)} group(s)</div>
  </div>

  <div class="panel">
    <h2>Findings</h2>
    <div class="findings-list">${findings.length ? findings.map(renderFindingRow).join('') : '<div class="empty">No findings.</div>'}</div>
  </div>

  <details class="ticker">
    <summary>Live Scan Ticker (${tickerLines.length} line(s))</summary>
    <div class="ticker-body">${tickerLines.length ? tickerLines.map((l) => `<div class="ticker-line">${esc(l)}</div>`).join('') : '<div class="empty">No ticker output captured.</div>'}</div>
  </details>

  <footer>Generated by ScanLayer Hybrid (VibeScan + SecLayer engines, verbatim) &mdash; for the target's own owner only.</footer>
</div>
</body>
</html>`;
}
