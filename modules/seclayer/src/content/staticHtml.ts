// Builds the static HTML that a crawler gets before any JavaScript runs:
// the <noscript> body and the FAQPage structured data. Pure functions, so a
// test can check them without a browser or a build.
//
// vite injects the result into index.html (vite-plugin-static-fallback.ts). The
// text comes from siteContent.ts, the same module the visible React sections
// read, so the static copy and what a visitor sees cannot drift apart.

import {
  BETA_NOTE, CATEGORY_NOTE, FAQS, HOW_IT_WORKS, LINKS, NOSCRIPT_INTRO, PRICE_SUMMARY, QUICK_ANSWERS, WHAT_WE_TEST,
} from './siteContent.js';

export function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

const MCP_COMMAND = 'claude mcp add seclayer --env SECLAYER_API_KEY=YOUR_API_KEY -- npx -y @seclayer/mcp';

export function renderFallbackHtml(): string {
  const e = escapeHtml;
  const parts: string[] = [];
  parts.push('<h1>Seclayer — black-box penetration testing SaaS &amp; MCP server</h1>');
  for (const p of NOSCRIPT_INTRO) parts.push(`<p>${e(p)}</p>`);

  parts.push('<h2>Quick answers</h2>', '<ul>');
  for (const { q, a } of QUICK_ANSWERS) parts.push(`<li><strong>${e(q)}</strong> ${e(a)}</li>`);
  parts.push('</ul>');

  parts.push('<h2>How it works</h2>', '<ol>');
  for (const s of HOW_IT_WORKS) parts.push(`<li><strong>${e(s.name)}.</strong> ${e(s.text)}</li>`);
  parts.push('</ol>');

  parts.push('<h2>What we test</h2>');
  parts.push(`<p>${e(CATEGORY_NOTE)} <a href="${LINKS.pillars}">Read how each category works</a>.</p>`, '<ul>');
  for (const c of WHAT_WE_TEST) parts.push(`<li><strong>${e(c.key)} — ${e(c.name)}</strong> (${e(c.mode)}). ${e(c.what)}</li>`);
  parts.push('</ul>');

  parts.push('<h2>Pricing and credits</h2>');
  parts.push(`<p>${e(PRICE_SUMMARY)} ${e(BETA_NOTE)}</p>`);

  parts.push('<h2>MCP server integration</h2>');
  parts.push(`<p>Seclayer ships an official <a href="${LINKS.mcp}">MCP server</a>, <code>@seclayer/mcp</code>, for Claude Code, Cursor, Windsurf and any MCP-compatible client. In Claude Code:</p>`);
  parts.push(`<pre><code>${e(MCP_COMMAND)}</code></pre>`);

  parts.push('<h2>Frequently asked questions</h2>', '<dl>');
  for (const { q, a } of FAQS) parts.push(`<dt>${e(q)}</dt><dd>${e(a)}</dd>`);
  parts.push('</dl>');

  parts.push('<p>Seclayer needs JavaScript to run a scan interactively. These pages read fine without it:</p>');
  parts.push('<nav><ul>',
    '<li><a href="/">Home</a></li>',
    `<li><a href="${LINKS.docs}">Documentation — API and MCP server</a></li>`,
    '<li><a href="/privacy">Privacy policy</a></li>',
    '<li><a href="/terms">Terms of service</a></li>',
    '</ul></nav>');
  return parts.join('\n      ');
}

/** The FAQPage block, built from the same FAQS the visible accordion renders. */
export function renderFaqJsonLd(): string {
  const data = {
    '@context': 'https://schema.org',
    '@type': 'FAQPage',
    mainEntity: FAQS.map((item) => ({
      '@type': 'Question',
      name: item.q,
      acceptedAnswer: { '@type': 'Answer', text: item.a },
    })),
  };
  // "<" is escaped so no answer can close the script element early.
  const json = JSON.stringify(data, null, 2).replace(/</g, '\\u003c');
  return `<script type="application/ld+json">\n${json}\n    </script>`;
}
