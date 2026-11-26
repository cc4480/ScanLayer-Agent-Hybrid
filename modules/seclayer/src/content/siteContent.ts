// The landing page's indexable content, in one place.
//
// Two things read this file and must say the same thing: the React sections a
// visitor sees, and the static HTML fallback that vite injects into index.html
// at build time (see staticHtml.ts). A crawler that does not run JavaScript gets
// only the second, so it has to carry the same text as the first. That is what
// keeps the <noscript> honest: nothing is shown to a crawler that a user does
// not also see.
//
// Keep every claim here anchored to what the product does (docs/prd.md and the
// /docs page). No invented capabilities, no ratings, no vanity numbers.

/** Credit pack prices in US cents. server/stripe.ts CREDIT_PACKS is the source of truth; a test pins them together. */
export const PACK_PRICES = {
  single: { credits: 1, cents: 2900 },
  pack5: { credits: 5, cents: 9900 },
  pack20: { credits: 20, cents: 29900 },
} as const;

const usd = (cents: number) => `$${(cents / 100).toFixed(cents % 100 === 0 ? 0 : 2)}`;
const perScan = (p: { credits: number; cents: number }) => usd(Math.round(p.cents / p.credits));

export const PRICE_SUMMARY = `A single scan is ${usd(PACK_PRICES.single.cents)}, a 5-scan pack is ${usd(PACK_PRICES.pack5.cents)} (${perScan(PACK_PRICES.pack5)} a scan) and a 20-scan pack is ${usd(PACK_PRICES.pack20.cents)} (${perScan(PACK_PRICES.pack20)} a scan). Credits never expire and there is no subscription.`;

// The free beta is on right now (FREE_MODE). When payments go live, this line
// and the matching copy in PricingSection and llms.txt must change together.
export const BETA_NOTE = 'During the free public beta, every scan is free and needs no card.';

export interface QuickAnswer { q: string; a: string }

export const QUICK_ANSWERS: QuickAnswer[] = [
  {
    q: 'What is Seclayer?',
    a: 'Seclayer is a black-box penetration testing service. You give it a public URL and it returns a plain-English report with each finding, a fix for it, and a ready-to-paste prompt for your AI coding agent.',
  },
  {
    q: 'How much does a scan cost?',
    a: `${PRICE_SUMMARY} ${BETA_NOTE}`,
  },
  {
    q: 'What does a scan test?',
    a: 'Seven categories: secrets in served code, vulnerable libraries, security headers and cookies, DNS and attack surface, web-app probes, API authorization, and real exploit attempts such as SQL injection and XSS. Active probes run only after you prove you own the domain.',
  },
  {
    q: 'How do I use it with my coding agent?',
    a: 'Run the MCP server with npx -y @seclayer/mcp in Claude Code, Cursor, Windsurf or any MCP-compatible client, set SECLAYER_API_KEY from your dashboard, then ask your agent to scan a URL.',
  },
];

export interface Step { name: string; text: string }

/** Mirrors the HowTo JSON-LD in index.html: same four steps, in the same order. */
export const HOW_IT_WORKS: Step[] = [
  {
    name: 'Enter your URL',
    text: 'Sign in and submit the public URL of the site or API you want tested. Passive checks start immediately on any public URL: security headers, TLS, exposed secrets, vulnerable libraries and DNS.',
  },
  {
    name: 'Prove you own the domain',
    text: 'Add a DNS TXT record or a well-known file. The next scan then runs live exploit probes: SQL injection, XSS, SSRF, BOLA/IDOR and API-schema fuzzing. This is what stops Seclayer being used as an anonymous attack proxy.',
  },
  {
    name: 'Read the report and hand the fix to your AI agent',
    text: 'Every finding has an impact statement, a fix for your stack and a ready-to-paste prompt. Proven findings include the exact request and response that demonstrated the problem.',
  },
  {
    name: 'Automate it from your agent or CI',
    text: 'Install the MCP server to scan from your editor, or call the HTTP API from CI. Put a target on a daily, weekly or monthly schedule to re-scan it automatically.',
  },
];

export interface Category { key: string; name: string; what: string; mode: 'Passive' | 'Active (needs verified domain)' | 'Passive, active when verified' }

/**
 * The seven categories as /docs describes them. Seclayer tests from the
 * outside, so two names mean something narrower than they do for source-code
 * tools; CATEGORY_NOTE says so, and must stay next to this list.
 */
export const WHAT_WE_TEST: Category[] = [
  { key: 'SAST', name: 'Secrets in served code', mode: 'Passive', what: 'Searches the HTML, JavaScript and CSS your site serves for exposed API keys, cloud credentials and private keys.' },
  { key: 'SCA', name: 'Libraries', mode: 'Passive', what: 'Identifies the JavaScript libraries your pages load and checks each version against known vulnerabilities.' },
  { key: 'IAST', name: 'Headers and cookies', mode: 'Passive', what: 'Checks security headers such as CSP, HSTS and X-Frame-Options, and the Secure, HttpOnly and SameSite flags on session cookies.' },
  { key: 'EASM', name: 'Attack surface', mode: 'Passive', what: 'Resolves DNS, enumerates common subdomains and reads what your server reveals about itself.' },
  { key: 'DAST', name: 'Web-app probing', mode: 'Passive, active when verified', what: 'Crawls the site, looks for exposed config files and backups, and once you verify ownership, fuzzes the parameters it found.' },
  { key: 'API_SEC', name: 'API security', mode: 'Active (needs verified domain)', what: 'Checks for exposed GraphQL introspection and tests whether one account can read another account’s records (BOLA/IDOR).' },
  { key: 'RED_TEAM', name: 'Exploit attempts', mode: 'Active (needs verified domain)', what: 'Attempts real exploitation, including SQL injection, reflected XSS, OS command injection and server-side request forgery.' },
];

export const CATEGORY_NOTE =
  'Seclayer tests from the outside, so two category names are narrower than in source-code tools: SAST here means secrets in code your site serves, and IAST means response headers and cookie flags.';

/** Paragraphs that have always been in the <noscript> fallback. Kept verbatim. */
export const NOSCRIPT_INTRO: string[] = [
  'Point Seclayer at a public URL and get a real black-box penetration test: signature-confirmed findings across seven AppSec categories (SAST, SCA, IAST, EASM, DAST, RED_TEAM, API_SEC), each with a plain-English impact statement, a stack-tailored fix, and a ready-to-paste remediation prompt for an AI coding agent.',
  'Passive recon runs on any public URL. Active exploitation — SQL injection, XSS, SSRF, BOLA/IDOR, JWT and business-logic probes — unlocks once you prove you own the target\'s domain, so it can\'t be used as an anonymous attack proxy. Every active finding ships a replayable receipt: the exact request and response, quoted verbatim.',
  'Pay per scan, no subscription, credits never expire. A free public beta is active now. Use it from the web dashboard, a plain HTTP API, or the official MCP server (@seclayer/mcp) in Claude Code, Cursor, Windsurf, or any MCP-compatible client.',
];

/** Internal links placed in body copy. Each target exists: /docs has these section ids, and the landing page has #pricing and #faq. */
export const LINKS = {
  pillars: '/docs#pillars',
  mcp: '/docs#mcp-api',
  evidence: '/docs#evidence',
  ownership: '/docs#ownership',
  pricing: '/#pricing',
  faq: '/#faq',
  docs: '/docs',
} as const;

export interface Faq { q: string; a: string }

// Answers are kept factually anchored to what the product actually does (see
// docs/prd.md + the /docs page) — no invented capabilities, no vanity numbers.
export const FAQS: Faq[] = [
  {
    q: 'What does Seclayer actually do?',
    a: 'Point it at a public URL and it runs a real black-box penetration test — HTTP probes, DNS and attack-surface recon, and (once you prove you own the target) live exploit attempts across seven AppSec categories. You get back a plain-English report with a posture score, an impact statement per finding, a stack-tailored fix, and a ready-to-paste prompt for your AI coding agent.',
  },
  {
    q: 'What kinds of vulnerabilities does it actually find?',
    a: 'Across seven AppSec pillars: exposed secrets and misconfiguration, injection (SQL — including time-based blind — XSS, SSTI, command injection, path traversal/LFI, CRLF), SSRF, broken access control (a BOLA/IDOR check that compares what two distinct identities can read), JWT authentication weaknesses, business-logic flaws like price and webhook-signature tampering, prototype pollution, vulnerable dependencies, and backend-as-a-service misconfiguration — open Supabase/Firebase rules and secrets shipped in your client bundle. Each finding is confirmed by a real signature match or a live exploit receipt, not a checklist guess.',
  },
  {
    q: 'Does it test my API, not just my web pages?',
    a: 'Yes. On a verified target it discovers your OpenAPI/Swagger schema — or you can point it at one — and fuzzes every declared operation: each path, method, query parameter and JSON/form body field, run through the exact same injection engine and proof-gating as the rest of the scan. It also probes GraphQL introspection exposure. Any active scan can submit real POST requests to forms and API endpoints it discovers, which can create or change records on the target; the aggressive opt-in adds a further set of more invasive checks (prototype pollution, price manipulation, webhook-signature probing). Test against staging where you can.',
  },
  {
    q: 'Is it safe or legal to scan a site I don’t own?',
    a: 'Passive checks (headers, DNS, tech fingerprinting, exposed-secret scanning) run against any public URL. Active exploitation — SQL injection, XSS, command injection, SSRF, BOLA probes, API-schema fuzzing, and the rest of the red-team suite — only unlocks once you prove ownership of the target’s domain via a DNS TXT record or a well-known file. That gate is what stops the platform being used as an anonymous attack proxy against a site you don’t control.',
  },
  {
    q: 'What’s the difference between a PROVEN and a DETECTED finding?',
    a: 'PROVEN means the exploit was demonstrated end-to-end and Seclayer captured a replayable receipt — the exact request and response, with the proof quoted verbatim from what came back. DETECTED means a real signal was observed that’s worth reporting, but wasn’t demonstrated end-to-end. Both are real and both count toward your score — PROVEN just wears a badge it can back up with evidence.',
  },
  {
    q: 'Do I need an AI API key?',
    a: 'No. AI-written reports are included — every scan comes back with an AI-generated executive narrative and live scan commentary, with no key to supply and no separate AI bill. If the AI service is ever unreachable, the report still ships with a deterministic summary generated locally from the same findings, so a scan never comes back empty.',
  },
  {
    q: 'What happens to my scan data — is it private?',
    a: 'Scan reports are private. When a scan finishes we email you a read-only link to that one report so you can open it without signing in — a link only ever exposes that single report, never your account or scan history — and you can revoke it at any time from the report page.',
  },
  {
    q: 'Why is Seclayer closed source?',
    a: 'The active-exploitation modules are real, working exploit probes. Publishing the exact detection signatures and payload logic would hand attackers a manual for evading detection, or a ready-made offensive toolkit outside the ownership-verification gate. See the Documentation page for a detailed, honest account of what each module checks and why — it stops short of the literal payloads and signatures.',
  },
  {
    q: 'Do scan credits expire?',
    a: 'No — purchased credits never expire, and each scan consumes exactly one. During the current free beta, every scan is free and doesn’t consume a credit at all.',
  },
  {
    q: 'Can I run Seclayer from my AI coding agent?',
    a: 'Yes. Seclayer ships as a standard stdio MCP server — works the same in Cursor, Claude Code, Windsurf, or any MCP-compatible client — alongside the web dashboard and a plain HTTP API. Generate an API key from the console and your agent can trigger a scan and read the report in natural language before you deploy.',
  },
  {
    q: 'Can Seclayer fix the issues, not just find them?',
    a: 'Every finding already ships a copy-paste fix prompt for your AI agent. Beyond that, the @seclayer/mcp CLI (and a matching GitHub Action) can open a pull request that fixes a proven finding for you: the agent runs entirely inside your own CI job — it reads and edits your files and runs your tests there, and the contents of any file it reads are relayed through Seclayer\'s backend to DeepSeek to generate the fix, but never stored. It always opens a PR for review and never merges, one branch per finding.',
  },
  {
    q: 'Can I keep a target monitored, not just scan it once?',
    a: 'Yes. Put a target on a re-scan cadence — daily, weekly, or monthly — and Seclayer re-runs the full scan on schedule, re-validating that the target is still safe to scan each time. A Slack-compatible webhook pings you only when a result is actually actionable — a live high or critical finding — so you hear about regressions, not routine “all clear” runs.',
  },
  {
    q: 'Can it scan my network and open ports too?',
    a: 'On self-hosted deployments, Network Reconnaissance runs a real, full-depth nmap sweep of a verified target — every port, service and version, plus nmap’s vulnerability NSE scripts — as an independent scan type separate from the seven web-app pillars. It’s self-hosted only, since nmap is a real system binary a serverless platform can’t run; where it isn’t available the feature cleanly hides itself rather than erroring.',
  },
  {
    q: 'How is this different from a generic vulnerability scanner?',
    a: 'Most scanners produce a wall of theoretical findings from a checklist and leave you to verify each one. Seclayer confirms every finding against a real signature match — and where possible, a live exploit receipt — so what you get is precision over noise: fewer findings, but ones you can trust and act on immediately.',
  },
  {
    q: 'What if I disagree with a finding?',
    a: 'Mark it as a false positive directly from the report, with a reason. It’s excluded from your score and severity immediately, and Seclayer won’t resurface it on future scans of the same target.',
  },
];
