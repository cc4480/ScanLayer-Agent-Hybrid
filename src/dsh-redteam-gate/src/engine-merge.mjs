// Merge the two engines into one report with no overlap.
//
// SecScan (vibescan-core) is the BASE. Its 158-check catalog is the reference
// coverage, so a SecScan finding always wins and is never repeated. SecLayer
// (seclayer-core) is then folded in for the checks SecScan does NOT have — the
// active exploit proofs and the out-of-band work — and anything it reports that
// SecScan has already covered is dropped, with the drop recorded so it is never
// silent.
//
// The join key is a canonical ISSUE KEY (`headers:csp`, `injection:sqli`, …), not
// a finding title: the two engines name the same issue differently ("Missing
// Content-Security-Policy (CSP)" vs "Missing CSP Header"), which is exactly why a
// title-based dedup would leave duplicates behind. A finding whose name matches no
// key is treated as SECLAYER-ONLY and always kept — the safe direction, because a
// mis-keyed finding is reported twice rather than lost.
//
// Nothing here decides whether a finding is true; it decides who reports it.

/** Canonical issue keys. First match wins; order matters only for readability. */
const ISSUE_KEYS = [
  // transport / headers
  [/no https|plaintext http|insecure connection/i, 'transport:https'],
  [/content-security-policy|\bcsp\b/i, 'headers:csp'],
  [/x-frame-options|clickjacking/i, 'headers:xfo'],
  [/x-content-type-options|nosniff/i, 'headers:xcto'],
  [/referrer-policy/i, 'headers:referrer'],
  [/permissions-policy/i, 'headers:permissions'],
  [/cross-origin-opener-policy|\bcoop\b/i, 'headers:coop'],
  [/cross-origin-embedder-policy|\bcoep\b/i, 'headers:coep'],
  [/cross-origin-resource-policy|\bcorp\b/i, 'headers:corp'],
  [/strict-transport-security|\bhsts\b/i, 'headers:hsts'],
  [/x-powered-by/i, 'headers:poweredby'],
  [/server (banner|header|version)|verbose server framework/i, 'headers:serverbanner'],
  [/cors/i, 'headers:cors'],
  [/(structured data|open graph|\bog:|social metadata)/i, 'seo:structured'],

  // cookies
  [/cookie.*secure flag|without the secure|missing secure/i, 'cookies:secure'],
  [/cookie.*httponly|without the httponly|missing httponly/i, 'cookies:httponly'],
  [/cookie.*samesite|missing samesite/i, 'cookies:samesite'],
  [/cookie/i, 'cookies:other'],

  // exposure
  [/environment file|\.env\b/i, 'exposure:env'],
  [/git config|\.git\b/i, 'exposure:git'],
  [/php ?info/i, 'exposure:phpinfo'],
  [/backup archive|backup\.zip/i, 'exposure:backup'],
  [/package manifest|package\.json/i, 'exposure:manifest'],
  [/directory listing|index of \//i, 'exposure:listing'],
  [/source map|\.js\.map\b|\.map\b/i, 'exposure:sourcemap'],
  // Secrets are keyed by KIND. "Stripe key exposed" and "AWS key id exposed" are
  // different findings; keying them both as `secrets:exposed` silently dropped the
  // AWS one because a Stripe finding was already reported.
  [/stripe/i, 'secrets:stripe'],
  [/\baws\b|amazon/i, 'secrets:aws'],
  [/(secret key|credential signature|exposed credential|api key exposed)/i, 'secrets:other'],
  [/sensitive file/i, 'exposure:sensitivefile'],
  [/security\.txt/i, 'exposure:securitytxt'],

  // errors
  [/verbose error|error pages expose|stack trace/i, 'errors:verbose'],

  // api
  [/graphql/i, 'api:graphql'],
  [/openapi|swagger|api documentation/i, 'api:docs'],

  // injection / active
  [/sql injection|sqli/i, 'injection:sqli'],
  [/xss/i, 'injection:xss'],
  [/command injection|os command/i, 'injection:cmdi'],
  [/template injection|ssti/i, 'injection:ssti'],
  [/nosql/i, 'injection:nosql'],
  [/path traversal|lfi|local file inclusion/i, 'injection:lfi'],
  [/host.header|host header/i, 'injection:hostheader'],
  [/crlf|response header injection|header injection/i, 'injection:crlf'],
  [/open redirect/i, 'injection:redirect'],
  [/prototype pollution/i, 'injection:protopollution'],
  [/ssrf|server.side request forgery/i, 'injection:ssrf'],
  [/xml external entity|\bxxe\b/i, 'injection:xxe'],

  // auth / business logic
  [/idor|bola|cross-tenant|object level|object-level/i, 'authz:idor'],
  [/rate limit/i, 'auth:ratelimit'],
  [/webhook/i, 'logic:webhook'],
  [/price tamper|business-logic|price manipulation/i, 'logic:price'],
  [/session token|predictable token/i, 'auth:sessiontoken'],
  [/weak\/predictable|weak token|entropy/i, 'auth:weaktoken'],

  // supply chain
  [/known-cve|end-of-life|dependency cve|outdated library|vulnerable librar/i, 'deps:cve'],
]

/**
 * @param {string} name a finding title/testName from either engine
 * @returns {string|null} canonical issue key, or null when no overlap is known
 */
export function issueKey(name) {
  const s = String(name ?? '')
  for (const [re, key] of ISSUE_KEYS) if (re.test(s)) return key
  return null
}

/**
 * @param {Array<{engine:'secscan'|'seclayer', name:string, severity?:string, confidence?:any, key?:string|null}>} findings
 * @returns {{merged: object[], dropped: object[]}}
 */
export function mergeEngines(findings) {
  const base = findings.filter((f) => f.engine === 'secscan')
  const extra = findings.filter((f) => f.engine !== 'secscan')

  const covered = new Set()
  for (const f of base) {
    const k = f.key ?? issueKey(f.name)
    if (k) covered.add(k)
  }

  const merged = []
  const dropped = []
  for (const f of base) merged.push({ ...f, key: f.key ?? issueKey(f.name), decidedBy: 'secscan' })

  for (const f of extra) {
    const k = f.key ?? issueKey(f.name)
    // No key = SecScan has no equivalent check → SecLayer-only, always kept.
    if (k && covered.has(k)) {
      dropped.push({ ...f, key: k, reason: `already reported by SecScan (${k})` })
      continue
    }
    merged.push({ ...f, key: k, decidedBy: 'seclayer' })
    // Deliberately NOT added to `covered`: coverage is SecScan's decision. Folding
    // SecLayer's own repeats into it would also collapse two legitimate findings
    // of the same kind on different targets, which is a different question (and
    // one SecLayer already answers with its own per-endpoint dedup).
  }
  return { merged, dropped }
}
