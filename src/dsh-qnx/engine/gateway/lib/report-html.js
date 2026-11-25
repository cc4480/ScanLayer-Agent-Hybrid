'use strict';
// A signed report as a self-contained, printable HTML page: findings with their evidence and verification, what was
// left out and why, and everything a reader needs to check the signature cold. No scripts, no external resources.
const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function renderReportHtml(report, publicPem) {
  const t = report.target || {};
  const target = t.os === 'QNX' ? `QNX ${t.qnx_version || t.release} on ${t.machine}` : `${t.os} ${t.release} on ${t.machine} (stand-in target, not QNX)`;
  const kind = report.kind === 'verified' ? 'Verified findings' : 'Scan findings';
  const counts = report.counts || {};
  const sev = ['critical', 'high', 'medium', 'low', 'info'].filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`).join(', ') || 'none';
  const rows = (report.findings || []).map((f) => {
    const ev = (f.evidence || []).map((e) => `<div class="ev"><code>${esc([e.tool, ...(e.args || [])].join(' '))}</code> <span class="dim">receipt #${esc(e.seq)} ${esc(String(e.receipt).slice(0, 16))}…</span><pre>${esc(e.excerpt)}</pre></div>`).join('');
    const v = f.verification ? `<div class="ver">Reproduced independently by <b>${esc(f.verification.seat)}</b>: ${esc(f.verification.observed)}</div>` : '';
    return `<tr><td class="sev s-${esc(f.severity)}">${esc(f.severity)}</td><td><b>${esc(f.title)}</b><div class="dim">${esc(f.check)} · ${esc(f.id)}</div><p>${esc(f.detail)}</p>${ev}${v}</td></tr>`;
  }).join('');
  const excluded = report.board && report.board.excluded && report.board.excluded.length
    ? `<h2>Left out of this report</h2><p class="dim">Claims the independent verifier could not confirm never become findings.</p><ul>${report.board.excluded.map((x) => `<li><b>${esc(x.status)}</b> ${esc(x.id)}: ${esc(x.observed)}</li>`).join('')}</ul>` : '';
  const rejected = report.rejected && report.rejected.length
    ? `<h2>Dropped: no receipt</h2><ul>${report.rejected.map((r) => `<li>${esc(r.id)}: ${esc(r.reason)}</li>`).join('')}</ul>` : '';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>QNX agent report</title><style>
:root{color-scheme:light dark;--fg:#1b2430;--dim:#5b6878;--line:#d6dde4;--high:#c62828;--med:#b26a00;--ok:#0e7490;--bg:#fff}
@media (prefers-color-scheme:dark){:root{--fg:#dfe6ec;--dim:#93a1ad;--line:#33414d;--high:#f87171;--med:#f59e0b;--ok:#22d3ee;--bg:#141c23}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:980px;margin:0 auto;padding:32px 20px 56px}h1{font-size:26px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px}
.dim{color:var(--dim);font-size:13px}table{width:100%;border-collapse:collapse;margin-top:12px}td{border-top:1px solid var(--line);padding:12px 12px 12px 0;vertical-align:top}
.sev{font-weight:700;white-space:nowrap;width:70px}.s-high,.s-critical{color:var(--high)}.s-medium{color:var(--med)}.s-low,.s-info{color:var(--dim)}
p{margin:6px 0}code,pre{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}pre{white-space:pre-wrap;word-break:break-all;margin:4px 0 0;padding:8px 10px;border:1px solid var(--line);border-radius:6px}
.ev{margin-top:8px}.ver{margin-top:8px;padding:8px 10px;border-left:3px solid var(--ok);font-size:13.5px}
.facts{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;font-size:14px}.facts dt{color:var(--dim)}.facts dd{margin:0;overflow-wrap:anywhere}
@media print{body{background:#fff;color:#000}}
</style></head><body><main>
<h1>${esc(kind)}: ${esc(t.hostname)}</h1>
<div class="dim">${esc(target)} · generated ${esc(report.generated_at)} · ${esc(sev)}</div>
<dl class="facts" style="margin-top:16px">
<dt>Findings</dt><dd>${(report.findings || []).length}${report.kind === 'verified' ? ' (every one reproduced by a second, independent seat)' : ''}</dd>
<dt>Audit chain</dt><dd>${report.audit && report.audit.verified ? 'intact' : 'BROKEN'}, ${esc(report.audit && report.audit.entries)} entries, head <code>${esc(report.audit && report.audit.head)}</code></dd>
<dt>Signature</dt><dd>ed25519, key <code>${esc(report.signature.key_id)}</code><br><code>${esc(report.signature.sig)}</code></dd>
</dl>
<h2>Findings</h2>${rows ? `<table>${rows}</table>` : '<p>No findings: the target matches its image manifest.</p>'}
${excluded}${rejected}
<h2>Check this report yourself</h2>
<p class="dim">The signature covers the canonical JSON of the report (keys sorted, without the signature). Verify it with the engine's CLI against the saved JSON and this public key:</p>
<pre>node engine/gateway/cli.js verify-report &lt;report.json&gt; --pub signing.pub.pem</pre><pre>${esc(publicPem)}</pre>
</main></body></html>`;
}

module.exports = { renderReportHtml };
