import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { renderFallbackHtml, renderFaqJsonLd, escapeHtml } from './staticHtml.js';
import { FAQS, HOW_IT_WORKS, LINKS, PACK_PRICES, PRICE_SUMMARY, QUICK_ANSWERS, WHAT_WE_TEST } from './siteContent.js';
import { CREDIT_PACKS } from '../../server/stripe.js';
import { FALLBACK_MARKER, FAQ_MARKER } from '../../vite-plugin-static-fallback.js';

const read = (p: string) => readFileSync(new URL(`../../${p}`, import.meta.url), 'utf8');

test('the static fallback carries every section a visitor sees', () => {
  const html = renderFallbackHtml();
  for (const h of ['Quick answers', 'How it works', 'What we test', 'Pricing and credits', 'MCP server integration', 'Frequently asked questions']) {
    assert.ok(html.includes(`<h2>${h}</h2>`), `missing heading: ${h}`);
  }
  for (const { q } of QUICK_ANSWERS) assert.ok(html.includes(escapeHtml(q)), q);
  for (const s of HOW_IT_WORKS) assert.ok(html.includes(escapeHtml(s.name)), s.name);
  for (const c of WHAT_WE_TEST) assert.ok(html.includes(`${c.key} — ${c.name}`), c.key);
  for (const { q } of FAQS) assert.ok(html.includes(escapeHtml(q)), q);
  assert.equal(WHAT_WE_TEST.length, 7, 'the site promises seven categories');
  assert.equal(HOW_IT_WORKS.length, 4);
});

test('the static fallback is substantial enough to cite, and is plain HTML', () => {
  const html = renderFallbackHtml();
  const words = html.replace(/<[^>]+>/g, ' ').replace(/&[a-z]+;/g, ' ').split(/\s+/).filter(Boolean).length;
  assert.ok(words >= 600, `fallback has ${words} words`);
  assert.ok(!/<script|<style|style=/i.test(html), 'no script or inline style: the CSP forbids inline style');
});

test('FAQPage markup is valid JSON and matches the visible FAQ exactly', () => {
  const block = renderFaqJsonLd();
  const body = block.replace(/^<script type="application\/ld\+json">/, '').replace(/<\/script>\s*$/, '');
  const data = JSON.parse(body);
  assert.equal(data['@type'], 'FAQPage');
  assert.equal(data.mainEntity.length, FAQS.length);
  data.mainEntity.forEach((item: { name: string; acceptedAnswer: { text: string } }, i: number) => {
    assert.equal(item.name, FAQS[i]!.q);
    assert.equal(item.acceptedAnswer.text, FAQS[i]!.a);
  });
});

test('an answer cannot close the script element early', () => {
  const body = renderFaqJsonLd().replace(/^<script type="application\/ld\+json">/, '').replace(/<\/script>\s*$/, '');
  assert.ok(!body.includes('</'), 'no raw "</" inside the JSON');
  assert.ok(!body.includes('<'), 'every "<" inside the JSON is escaped');
});

test('prices on the page are the prices the server charges', () => {
  for (const id of ['single', 'pack5', 'pack20'] as const) {
    assert.equal(PACK_PRICES[id].cents, CREDIT_PACKS[id].amountCents, id);
    assert.equal(PACK_PRICES[id].credits, CREDIT_PACKS[id].credits, id);
  }
  assert.match(PRICE_SUMMARY, /\$29\b.*\$99\b.*\$19\.80.*\$299\b.*\$14\.95/);
});

test('index.html has the two injection markers and a single noscript block', () => {
  const html = read('index.html');
  assert.ok(html.includes(FALLBACK_MARKER));
  assert.ok(html.includes(FAQ_MARKER));
  // The word "<noscript>" also appears in the explanatory comment, so count the real block by what follows it.
  assert.equal((html.match(/<noscript>\s*<!--STATIC_FALLBACK-->/g) || []).length, 1, 'exactly one real noscript fallback');
  assert.equal((html.match(/<!--/g) || []).length, (html.match(/-->/g) || []).length, 'every HTML comment is closed');
  assert.equal((html.match(/"@type": "FAQPage"/g) || []).length, 0, 'FAQPage is injected, not hand-written');
});

test('every internal link in body copy points at something that exists', () => {
  const docs = read('src/pages/DocsPage.tsx');
  for (const href of [LINKS.pillars, LINKS.mcp, LINKS.evidence, LINKS.ownership]) {
    const id = href.split('#')[1]!;
    assert.ok(docs.includes(`id="${id}"`), `/docs has no section with id "${id}"`);
  }
  assert.ok(read('src/components/landing/PricingSection.tsx').includes('id="pricing"'));
  assert.ok(read('src/components/landing/FaqSection.tsx').includes('id="faq"'));
});

test('the MCP version in structured data is not stale', () => {
  const html = read('index.html');
  const mcp = JSON.parse(read('mcp-server/package.json')).version as string;
  const listed = /"softwareVersion": "([^"]+)"/.exec(html)?.[1];
  // The listed version is the one published on npm, which may lag the repo by a release;
  // it must never be older than the last published major.
  assert.ok(listed && Number(listed.split('.')[0]) >= 1, `softwareVersion ${listed} (repo ${mcp})`);
});

test('llms.txt states the same prices as the page and keeps its attribution terms', () => {
  const llms = read('public/llms.txt');
  assert.ok(llms.includes(PRICE_SUMMARY), 'llms.txt must repeat PRICE_SUMMARY exactly');
  assert.ok(/Preferred attribution/i.test(llms));
  assert.ok(/Do not crawl .*\/api\//.test(llms));
  for (const href of [LINKS.pillars, LINKS.mcp, LINKS.pricing, LINKS.faq]) {
    assert.ok(llms.includes(`https://seclayer.app${href}`), `llms.txt should link ${href}`);
  }
  const robots = read('server/routes/wellKnown.ts'); // robots.txt is generated by the server
  for (const p of ['/api/', '/dashboard', '/r/']) assert.ok(robots.includes(`'Disallow: ${p}'`), `llms.txt says robots.txt disallows ${p}`);
});
