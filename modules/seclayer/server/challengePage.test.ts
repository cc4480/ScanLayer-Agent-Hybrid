import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectChallengePage, explainChallenge } from './challengePage.js';
import { compileStaticFindings } from './findings.js';

const page = (title: string, body = '') =>
  `<!doctype html><html><head><title>${title}</title></head><body>${body}</body></html>`;

test('detects a Cloudflare interstitial by title', () => {
  const v = detectChallengePage(403, page('Just a moment...'));
  assert.equal(v.isChallenge, true);
  assert.equal(v.vendor, 'Cloudflare');
});

test('detects vendor fingerprints in the body', () => {
  for (const [body, vendor] of [
    ['<script src="/cdn-cgi/challenge-platform/h/b/orchestrate"></script>', 'Cloudflare'],
    ['window._cf_chl_opt={};', 'Cloudflare'],
    ['<iframe src="https://geo.captcha-delivery.com/captcha/"></iframe>', 'DataDome'],
    ['Incapsula incident ID: 123-456', 'Imperva/Incapsula'],
    ['<img src="https://errors.edgesuite.net/x.gif">', 'Akamai'],
    ['token from awswaf.com', 'AWS WAF'],
  ] as const) {
    const v = detectChallengePage(200, page('Site', body));
    assert.equal(v.isChallenge, true, `${vendor} body signal must match`);
    assert.equal(v.vendor, vendor);
  }
});

test('a vendor header decides on its VALUE, not its presence', () => {
  // A site can serve its real homepage under x-datadome: protected — that means
  // the request PASSED. Treating the header itself as a verdict would mark a
  // working site as blocked while its content sits in the body.
  assert.equal(detectChallengePage(200, page('Real Site'), { 'x-datadome': 'protected' }).isChallenge, false);
  assert.equal(detectChallengePage(200, page('x'), { 'x-datadome': 'blocked' }).isChallenge, true);
  assert.equal(detectChallengePage(200, page('x'), { 'cf-mitigated': 'challenge' }).isChallenge, true);
});

test('a bare 403/503/429 with almost no body is an interception', () => {
  assert.equal(detectChallengePage(403, '<html><body>Forbidden</body></html>').isChallenge, true);
  assert.equal(detectChallengePage(503, '').isChallenge, true);
  assert.equal(detectChallengePage(429, 'rate limited').isChallenge, true);
});

test('does NOT fire on real pages — the expensive false direction', () => {
  // Suppressing a real scan is the failure this guards against, so pin it hard.
  const realPages: [number, string, Record<string, string>][] = [
    [200, page('Acme Corp — Home', '<h1>Welcome</h1><p>Please wait while we load your dashboard.</p>'), {}],
    [200, page('Security check your account settings', '<p>access denied to this folder</p>'), {}],
    [200, page('Blog — one more step to launch'), {}],
    // A big real page that merely loads a vendor script stays a real page.
    [200, page('Shop', '<script src="/cdn-cgi/challenge-platform/x"></script>' + 'x'.repeat(60_000)), {}],
    [403, page('Members Only', '<p>' + 'Real content explaining why access is restricted. '.repeat(80) + '</p>'), {}],
    [200, page('News'), { 'x-datadome': 'protected' }],
  ];
  for (const [status, html, headers] of realPages) {
    const v = detectChallengePage(status, html, headers);
    assert.equal(v.isChallenge, false, `must NOT flag: ${html.slice(0, 60)}`);
  }
});

test('an intercepted scan withholds content-derived findings and says so', () => {
  const base: any = {
    url: 'https://example.com', responseStatus: 403, sslSecure: true,
    headers: { server: 'cloudflare' },
    missingHeaders: ['content-security-policy', 'strict-transport-security', 'x-content-type-options'],
    techLeaked: ['cloudflare'], probedPaths: [],
    cookieIssues: ['Cookie "sessionid" is missing the Secure attribute'],
    cookieEvidence: { 'Cookie "sessionid" is missing the Secure attribute': 'sessionid=x' },
    sastFindings: [], scaFindings: [], scaLibraries: [], exposedConfigs: [], openRedirects: [],
    paramEndpoints: [], crawledPages: [], subdomains: [], dnsRecords: [],
    headerEvidence: {}, redirectChain: [], tlsInfo: {}, apiFindings: [], redTeamFindings: [],
    challenge: { isChallenge: true, vendor: 'Cloudflare', signal: 'interstitial title: "Just a moment..."' },
  };
  const out = compileStaticFindings(base);
  const titles = out.findings.map((f) => f.title);

  assert.ok(titles.some((t) => /intercepted by a bot-protection/i.test(t)), 'must explain the interception');
  // None of these describe example.com — they describe Cloudflare's page.
  for (const leaked of ['Missing Content-Security-Policy (CSP)', 'Missing Strict-Transport-Security (HSTS) Policy',
    'Missing X-Content-Type-Options (MIME Sniffing)', 'Verbose Server Framework Signature Leaked']) {
    assert.ok(!titles.includes(leaked), `must withhold "${leaked}" — it describes the interstitial`);
  }
  assert.ok(!titles.some((t) => /sessionid/i.test(t)), 'must withhold the challenge page\'s own cookies');
});

test('an ordinary scan is completely unaffected', () => {
  const base: any = {
    url: 'https://example.com', responseStatus: 200, sslSecure: true, headers: {},
    missingHeaders: ['content-security-policy'], techLeaked: [], probedPaths: [],
    cookieIssues: [], cookieEvidence: {},
    sastFindings: [], scaFindings: [], scaLibraries: [], exposedConfigs: [], openRedirects: [],
    paramEndpoints: [], crawledPages: [], subdomains: [], dnsRecords: [],
    headerEvidence: {}, redirectChain: [], tlsInfo: {}, apiFindings: [], redTeamFindings: [],
    challenge: { isChallenge: false, vendor: null, signal: null },
  };
  const titles = compileStaticFindings(base).findings.map((f) => f.title);
  assert.ok(titles.includes('Missing Content-Security-Policy (CSP)'), 'normal findings still report');
  assert.ok(!titles.some((t) => /intercepted/i.test(t)), 'no interception note on a normal scan');
});

// Verified against lovable.dev on 2026-09-11: a Cloudflare MANAGED challenge
// serves headless Chromium the same interactive page it serves undici — HTTP
// 403, redirected to ?__cf_chl_rt_tk=..., titled "Just a moment...". The
// browser fallback in runPassiveScan re-judges the rendered response with this
// function, so if this stopped flagging, a challenge page would be adopted as
// the real site and every content-derived finding would describe Cloudflare.
test('a managed challenge served to the BROWSER is still a challenge', () => {
  const html = '<!DOCTYPE html><html><head><title>Just a moment...</title></head>'
    + '<body><div class="main-wrapper"><noscript>Enable JavaScript and cookies to continue</noscript></div></body></html>';
  const v = detectChallengePage(403, html, {
    'content-security-policy': "default-src 'self'",
    'x-frame-options': 'SAMEORIGIN',
  });
  assert.equal(v.isChallenge, true);
  assert.equal(v.vendor, 'Cloudflare');
});

// The other half: a browser that genuinely reached the origin must NOT be
// judged a challenge, or the fallback could never adopt a recovered page.
test('a real page recovered by the browser is not a challenge', () => {
  const html = '<!DOCTYPE html><html><head><title>AI App Builder | Build with AI</title></head>'
    + '<body><main><h1>Welcome</h1><p>' + 'x'.repeat(3000) + '</p></main></body></html>';
  const v = detectChallengePage(200, html, { 'content-security-policy': "default-src 'self'" });
  assert.equal(v.isChallenge, false);
});

const baseDiag = () => ({
  url: 'https://example.com', responseStatus: 403, sslSecure: true,
  headers: { server: 'cloudflare' }, missingHeaders: [], techLeaked: [], probedPaths: [],
  cookieIssues: [], cookieEvidence: {}, sastFindings: [], scaFindings: [], scaLibraries: [],
  exposedConfigs: [], openRedirects: [], paramEndpoints: [], crawledPages: [], subdomains: [],
  dnsRecords: [], headerEvidence: {}, redirectChain: [], tlsInfo: {}, apiFindings: [], redTeamFindings: [],
});

test('a header block is explained with the status, the header and its value', () => {
  const v = detectChallengePage(403, page('Just a moment'), { 'cf-mitigated': 'challenge' });
  assert.equal(v.rule, 'header');
  assert.equal(v.status, 403);
  const why = explainChallenge(v);
  assert.match(why, /HTTP 403 Forbidden/);
  assert.match(why, /cf-mitigated response header: challenge/);
  assert.match(why, /Cloudflare/);
});

test('the header explanation uses the right article', () => {
  const v = detectChallengePage(202, page('Home'), { 'x-amzn-waf-action': 'challenge' });
  assert.match(explainChallenge(v), /and an AWS WAF response header/);
});

test('a title block quotes the exact title it fired on', () => {
  const v = detectChallengePage(503, page('Just a moment...'));
  assert.equal(v.rule, 'title');
  const why = explainChallenge(v);
  assert.match(why, /HTTP 503 Service Unavailable/);
  assert.match(why, /"Just a moment\.\.\."/);
});

test('a body block names the fingerprint and the vendor', () => {
  const v = detectChallengePage(401, page('Reuters', '<script src="https://geo.captcha-delivery.com/x.js"></script>'));
  assert.equal(v.rule, 'body');
  const why = explainChallenge(v);
  assert.match(why, /HTTP 401 Unauthorized/);
  assert.match(why, /DataDome/);
  assert.match(why, /DataDome captcha delivery/);
});

test('an unattributed block says no vendor was identified and why it is still a block', () => {
  const v = detectChallengePage(403, page('Oops', '<p>denied</p>'));
  assert.equal(v.vendor, null);
  assert.equal(v.rule, 'bare-status');
  const why = explainChallenge(v);
  assert.match(why, /HTTP 403 Forbidden/);
  assert.match(why, /No bot-protection vendor was identified/);
  assert.match(why, /-character body/);
});

test('the report finding carries the exact reason, not just the vendor', () => {
  const diag: any = { ...baseDiag(), responseStatus: 403, challenge: detectChallengePage(403, page('Just a moment...')) };
  const { findings } = compileStaticFindings(diag);
  const f = findings.find((x) => /intercepted by a bot-protection/i.test(x.title))!;
  assert.match(f.description, /WHY IT WAS JUDGED A BLOCK: .*HTTP 403 Forbidden/);
  assert.match(f.description, /"Just a moment\.\.\."/);
});

test('a page that is not a challenge explains nothing', () => {
  assert.equal(explainChallenge(detectChallengePage(200, page('Home', '<p>hello</p>'))), '');
});
