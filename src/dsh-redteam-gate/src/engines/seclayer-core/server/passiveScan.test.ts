import { test } from "node:test";
import assert from "node:assert/strict";
import { cookieFlagIssues, redactCookieValue, MAX_COOKIE_ISSUES, isCookieDeletion, metaCspPolicy, transportOf } from "./passiveScan.js";
// cookieFlagIssues now returns { message, observed }; these assertions are
// about WHICH problems are reported, so they compare the messages.
const messages = (list: { message: string }[]) => list.map((i) => i.message);

test("cookieFlagIssues flags missing HttpOnly regardless of scheme, and missing Secure only over HTTPS", () => {
  const httpIssues = cookieFlagIssues(["sessionId=abc"], false, 0);
  assert.deepEqual(messages(httpIssues), ['Cookie "sessionId" is set without the HttpOnly attribute']);

  const httpsIssues = cookieFlagIssues(["sessionId=abc"], true, 0);
  assert.deepEqual(messages(httpsIssues), [
    'Cookie "sessionId" is set without the Secure attribute over HTTPS',
    'Cookie "sessionId" is set without the HttpOnly attribute',
  ]);
});

test("cookieFlagIssues reports nothing for a properly flagged cookie", () => {
  const issues = cookieFlagIssues(["sessionId=abc; Secure; HttpOnly; SameSite=Strict"], true, 0);
  assert.deepEqual(issues, []);
});

test("cookieFlagIssues never flags missing SameSite (browsers default it to Lax)", () => {
  const issues = cookieFlagIssues(["sessionId=abc; Secure; HttpOnly"], true, 0);
  assert.deepEqual(issues, []);
});

test("cookieFlagIssues respects the running count across repeated calls (global cap, not per-call)", () => {
  // Simulates the scanner calling this once per crawled page: pass the prior
  // total back in as `alreadyFound` so the cap holds across the whole scan.
  const manyCookies = Array.from({ length: 10 }, (_, i) => `c${i}=v`); // 2 issues each over HTTPS
  const first = cookieFlagIssues(manyCookies.slice(0, 2), true, 0);
  assert.equal(first.length, 4);
  const second = cookieFlagIssues(manyCookies.slice(2), true, first.length);
  assert.equal(first.length + second.length, MAX_COOKIE_ISSUES, "total across calls never exceeds the global cap");
});

// The cookie VALUE must never reach a stored report: a Set-Cookie value can be
// a live session token, and these strings are persisted and rendered in the UI.
test('redactCookieValue strips the value but keeps every security attribute', () => {
  const raw = 'NID=534=SECRET_TOKEN_VALUE; expires=Tue, 09-Mar-2027 08:52:06 GMT; path=/; domain=.google.com; HttpOnly';
  const out = redactCookieValue(raw);
  assert.ok(!out.includes('SECRET_TOKEN_VALUE'), 'the cookie value must be redacted');
  assert.match(out, /^NID=<redacted>;/);
  // The attributes are the entire point of quoting the line back.
  assert.match(out, /HttpOnly/);
  assert.match(out, /domain=\.google\.com/);
  assert.ok(!/;\s*Secure/i.test(out), 'Secure was genuinely absent and must stay absent');
});

test('cookieFlagIssues quotes the line each issue came from, value redacted', () => {
  // The real google.com response to a non-browser UA: HttpOnly but no Secure.
  const [issue] = cookieFlagIssues(['NID=534=abc; path=/; domain=.google.com; HttpOnly'], true, 0);
  assert.match(issue.message, /without the Secure attribute/);
  assert.equal(issue.observed, 'NID=<redacted>; path=/; domain=.google.com; HttpOnly');
});

test('a cookie being deleted is not flagged for the attributes its deletion line lacks', () => {
  // A logout response clearing the session. The browser drops the cookie on
  // arrival; it held no value. These produced two medium findings each.
  for (const deletion of [
    'session=; Max-Age=0; Path=/',
    'session=deleted; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/',
    'session=; max-age=-1',
  ]) {
    assert.equal(isCookieDeletion(deletion), true, deletion);
    assert.deepEqual(cookieFlagIssues([deletion], true, 0), [], deletion);
  }
});

test('a live cookie is still flagged, including one whose stale Expires is overridden by Max-Age', () => {
  // Max-Age wins over Expires (RFC 6265 §5.3), so this cookie lives an hour.
  const live = 'session=abc; Max-Age=3600; Expires=Thu, 01 Jan 1970 00:00:00 GMT';
  assert.equal(isCookieDeletion(live), false);
  assert.equal(cookieFlagIssues([live], true, 0).length, 2);
  assert.equal(isCookieDeletion('session=abc; Expires=Fri, 01 Jan 2100 00:00:00 GMT'), false);
  assert.equal(isCookieDeletion('session=abc; Path=/'), false);
});

test('metaCspPolicy finds a policy delivered in a <meta> tag in the head', () => {
  const html = `<!doctype html><html><head><meta charset="utf-8">
    <meta content="default-src 'self'; script-src 'self' 'nonce-abc'" http-equiv="Content-Security-Policy">
    </head><body>hi</body></html>`;
  assert.equal(metaCspPolicy(html), "default-src 'self'; script-src 'self' 'nonce-abc'");
  // Entity-encoded quotes, single-quoted attribute, any case.
  assert.equal(
    metaCspPolicy(`<head><META HTTP-EQUIV='content-security-policy' CONTENT="object-src &#39;none&#39;"></head>`),
    "object-src 'none'",
  );
});

test('metaCspPolicy ignores meta policies a browser would not enforce', () => {
  // Outside <head>: the HTML spec ignores it.
  assert.equal(metaCspPolicy(`<head></head><body><meta http-equiv="Content-Security-Policy" content="default-src 'self'"></body>`), null);
  // Commented out.
  assert.equal(metaCspPolicy(`<head><!-- <meta http-equiv="Content-Security-Policy" content="default-src 'self'"> --></head>`), null);
  // Only directives that restrict nothing (the common mixed-content upgrade tag).
  assert.equal(metaCspPolicy(`<head><meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests"></head>`), null);
  assert.equal(metaCspPolicy(`<head><meta http-equiv="Content-Security-Policy" content="frame-ancestors 'none'"></head>`), null);
  // Report-only cannot be delivered by meta at all.
  assert.equal(metaCspPolicy(`<head><meta http-equiv="Content-Security-Policy-Report-Only" content="default-src 'self'"></head>`), null);
  assert.equal(metaCspPolicy(''), null);
});

test('transport is judged by where the root request ended, not by the URL as typed', () => {
  // http:// typed, the site redirected to HTTPS: served over TLS. This was a
  // HIGH "Insecure Connection Protocol (HTTP)" false positive.
  assert.deepEqual(transportOf({ url: 'https://example.com/' }, 'http://example.com'), { finalUrl: 'https://example.com/', sslSecure: true });
  // https:// typed, the site redirected down to plain HTTP: really plaintext.
  assert.equal(transportOf({ url: 'http://example.com/' }, 'https://example.com').sslSecure, false);
  // No redirect information (a Response built in a test): what was requested.
  assert.deepEqual(transportOf({ url: '' }, 'http://example.com'), { finalUrl: 'http://example.com', sslSecure: false });
});
