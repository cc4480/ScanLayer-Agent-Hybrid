// Detection for WAF challenge and block pages.
//
// When a target's edge decides the scanner is a bot it does not fail the
// request — it returns 200, 403 or 503 with a complete HTML document of its
// own. Everything downstream then analyses that document: the missing CSP is
// Cloudflare's, the cookies are the challenge's, the "exposed" nothing and the
// absent security headers all belong to an interstitial the customer never
// published. The report describes the WAF and is attributed to the site.
//
// Detection is deliberately strict, because the failure modes are asymmetric.
// Calling a real page a challenge page suppresses genuine findings; failing to
// call a challenge page one attributes another company's error page to your
// customer. The second is the more expensive error, but only because the first
// is guarded against here: a match needs an unambiguous vendor fingerprint — a
// challenge-platform script path, a vendor header whose VALUE says blocked, a
// verbatim interstitial title — never a phrase that could appear in prose.

export interface ChallengeVerdict {
  /** True only when a vendor fingerprint matched. */
  isChallenge: boolean;
  vendor: string | null;
  /** What matched, for the evidence line in the report. */
  signal: string | null;
  /** Which kind of evidence decided it. Absent when nothing matched. */
  rule?: "header" | "title" | "body" | "bare-status";
  /** HTTP status the response carried. */
  status?: number;
  /** Length of the response body, in characters. */
  bodyLength?: number;
  /** The document's <title>, when it has one. */
  title?: string | null;
}

const NOT_A_CHALLENGE: ChallengeVerdict = { isChallenge: false, vendor: null, signal: null };

// Vendor-specific asset paths, script tokens and verbatim interstitial strings.
// Never a phrase a normal page might contain.
const BODY_SIGNALS: { vendor: string; re: RegExp; label: string }[] = [
  { vendor: "Cloudflare", re: /\/cdn-cgi\/challenge-platform\//i, label: "/cdn-cgi/challenge-platform/ script" },
  // Deliberately no word boundary before cf_chl_opt. The markup Cloudflare
  // actually emits is `window._cf_chl_opt={...}`, and "_" is a word character,
  // so a leading word boundary never matches the real-world form. This file's
  // own test caught that.
  { vendor: "Cloudflare", re: /cf_chl_opt|__cf_chl_/i, label: "cf_chl_opt challenge payload" },
  { vendor: "Cloudflare", re: /cf-browser-verification|cf-im-under-attack/i, label: "cf-browser-verification marker" },
  { vendor: "Imperva/Incapsula", re: /_Incapsula_Resource|Incapsula incident ID/i, label: "Incapsula resource marker" },
  { vendor: "Akamai", re: /errors\.edgesuite\.net|AkamaiGHost/i, label: "Akamai error host" },
  { vendor: "Sucuri", re: /Sucuri WebSite Firewall|sucuri_cloudproxy/i, label: "Sucuri firewall page" },
  { vendor: "PerimeterX", re: /_pxhd|px-captcha|perimeterx/i, label: "PerimeterX challenge" },
  { vendor: "DataDome", re: /geo\.captcha-delivery\.com/i, label: "DataDome captcha delivery" },
  { vendor: "AWS WAF", re: /awswaf\.com|aws-waf-token/i, label: "AWS WAF token" },
];

// Matched against the <title> only, and anchored: "just a moment" in body copy
// is ordinary English, while a document whose entire title is "Just a moment..."
// is not a page anyone published.
const TITLE_SIGNALS: { vendor: string; re: RegExp }[] = [
  { vendor: "Cloudflare", re: /^just a moment\.{0,3}$/i },
  { vendor: "Cloudflare", re: /^attention required!/i },
  { vendor: "Cloudflare", re: /^access denied \| .*cloudflare/i },
  { vendor: "generic WAF", re: /^(checking your browser|please wait\.{0,3}|one more step|security check)$/i },
  { vendor: "generic WAF", re: /^(403 forbidden|access denied|request blocked|blocked)$/i },
];

// The VALUE decides, never the presence. These headers are set on ALLOWED
// traffic too — a site can serve its real homepage under `x-datadome:
// protected`, meaning the request passed. Treating the header itself as a
// verdict would mark a working site as blocked while its content sits in the
// response body.
const HEADER_SIGNALS: { vendor: string; header: string; re: RegExp; label: string }[] = [
  { vendor: "Cloudflare", header: "cf-mitigated", re: /challenge|block/i, label: "cf-mitigated response header" },
  { vendor: "DataDome", header: "x-datadome", re: /block|challenge|captcha/i, label: "x-datadome response header" },
  { vendor: "AWS WAF", header: "x-amzn-waf-action", re: /block|challenge|captcha/i, label: "x-amzn-waf-action response header" },
];

function titleOf(html: string): string | null {
  const m = /<title\b[^>]*>([\s\S]{0,200}?)<\/title\s*>/i.exec(html);
  return m ? (m[1] ?? "").replace(/\s+/g, " ").trim() : null;
}

/**
 * Decide whether a response is an edge challenge rather than the target's page.
 * `headers` keys must be lowercased — passiveScan already normalises them.
 */
export function detectChallengePage(
  status: number,
  html: string,
  headers: Record<string, string> = {},
): ChallengeVerdict {
  const hit = (rule: NonNullable<ChallengeVerdict["rule"]>, vendor: string | null, signal: string): ChallengeVerdict => ({
    isChallenge: true,
    vendor,
    signal,
    rule,
    status,
    bodyLength: (html || "").length,
    title: titleOf(html || ""),
  });

  for (const h of HEADER_SIGNALS) {
    const value = headers[h.header];
    if (value !== undefined && h.re.test(value)) {
      return hit("header", h.vendor, `${h.label}: ${value.slice(0, 60)}`);
    }
  }

  // A large document is a real page that merely loads a vendor's script, so the
  // interstitial size ceiling applies to body and title signals alike.
  const looksInterstitial = (html || "").length < 60_000;

  const title = titleOf(html || "");
  if (title && looksInterstitial) {
    for (const t of TITLE_SIGNALS) {
      if (t.re.test(title)) {
        return hit("title", t.vendor, `interstitial title: "${title.slice(0, 80)}"`);
      }
    }
  }

  if (looksInterstitial) {
    for (const b of BODY_SIGNALS) {
      if (b.re.test(html || "")) {
        return hit("body", b.vendor, b.label);
      }
    }
  }

  // A bare 403/503/429 with almost no body is an interception even when no
  // vendor signed it. Anything with real content is left alone — an empty-ish
  // error page is not something a site publishes as its homepage.
  const dense = (html || "").replace(/\s+/g, "").length;
  if ((status === 403 || status === 503 || status === 429) && dense < 2_000) {
    return hit("bare-status", null, `HTTP ${status} with a ${(html || "").length}-byte body`);
  }

  return NOT_A_CHALLENGE;
}

const STATUS_WORDS: Record<number, string> = { 401: "Unauthorized", 403: "Forbidden", 429: "Too Many Requests", 503: "Service Unavailable" };

/**
 * A plain-language statement of exactly why a response was judged a block, for
 * the report. Only states what was observed: the status, the rule that fired
 * and the value it fired on — so the reader can replay it with one request.
 */
export function explainChallenge(v: ChallengeVerdict): string {
  if (!v.isChallenge) return "";
  const status = v.status ? `HTTP ${v.status}${STATUS_WORDS[v.status] ? ` ${STATUS_WORDS[v.status]}` : ""}` : "the response";
  const size = v.bodyLength !== undefined ? `a ${v.bodyLength.toLocaleString("en-US")}-character body` : "a short body";
  const who = v.vendor ?? "no vendor";
  switch (v.rule) {
    case "header":
      return `The server answered with ${status} and ${/^[aeiou]/i.test(who) ? "an" : "a"} ${who} response header that says the request was challenged or blocked (${v.signal}). ${who} sets that header on the requests it stops.`;
    case "title":
      return `The server answered with ${status} and a page whose entire title is ${JSON.stringify(v.title ?? "")}, which is ${who}'s standard interstitial. A site's own page does not carry that title (${v.signal}).`;
    case "body":
      return `The server answered with ${status} and ${size} containing ${who}'s challenge fingerprint (${v.signal}). That marker appears only on ${who}'s challenge or captcha pages.`;
    case "bare-status":
      return `The server answered with ${status} and only ${size}${v.title ? ` titled ${JSON.stringify(v.title)}` : ""}. No bot-protection vendor was identified. It was judged a block, not the site's page, because a refusal status with a body this small is not something a site serves as its homepage.`;
    default:
      return v.signal ?? "";
  }
}
