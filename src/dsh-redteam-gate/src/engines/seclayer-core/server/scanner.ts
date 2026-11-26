import { crawlSite, targetsFromHtml, dedupeTargets, paramsOf, InjectableTarget } from "./crawler.js";
import { SCANNER_USER_AGENT } from "./config.js";
import { discoverAndParseApi } from "./openapi.js";
import { runTemplates, selectTemplates } from "./templateEngine.js";
import { TEMPLATES } from "./templates.js";
import { detectTechTags } from "./techprofile.js";
import { renderPage, isRenderingEnabled } from "./render.js";
import { safeFetch, assertTargetIsScannable } from "./ssrf.js";
import { parseAuthHeader } from "./evidence.js";
import { fuzzDiscoveredTargets, type FuzzCapture } from "./paramFuzzer.js";
import { weakTokenFindings } from "./weakTokenScan.js";
import { buildGuessedTargets } from "./paramMiner.js";
import { probeStoredXss } from "./storedXss.js";
import { findLoginTarget, probeWeakSessionToken } from "./redTeam/weakSessionToken.js";
import { runRedTeamProbes } from "./redTeamProbes.js";
import { runAggressiveProbes } from "./aggressiveProbes.js";
import { runApiSecProbes, exposedUserListInCapture, exposedCredentialListInCapture } from "./apiProbes.js";
import { probeJwtAuth, extractJwtSecretCandidates } from "./jwtProbe.js";
import { probeI18nAuthBypass } from "./i18nProbe.js";
import { extractUrlKeyPairs, probeCredentialUrlPairs } from "./credentialChainProbe.js";
import { extractTableNames, extractStorageBucketNames } from "./supabaseKeys.js";
import { probeSupabaseStorage } from "./supabaseStorageProbe.js";
import { fetchFirstPartyScripts } from "./scriptCapture.js";
import { extractFirebaseDbUrls, probeFirebaseOpenDb } from "./firebaseProbe.js";
import { extractBucketUrls, probeOpenBuckets } from "./bucketProbe.js";
import { assessCsrf, redactCookieValue } from "./csrfProbe.js";
import { probeExposedSourceMaps } from "./sourceMapProbe.js";
import { probeLlmPromptInjection, probeLlmMemoryPoisoning, probeLlmInsecureToolUse } from "./llmProbe.js";
import { probeEdgeFunctionAuth } from "./edgeFunctionProbe.js";
import { probePrototypePollution } from "./prototypePollutionProbe.js";
import { probePriceManipulation } from "./priceManipulationProbe.js";
import { probeWebhookSignatureBypass } from "./webhookSignatureProbe.js";
import { probeAuthRateLimit } from "./authRateLimitProbe.js";
import { probeDomXss } from "./domXss.js";
import { runPassiveScan, cookieFlagIssues } from "./passiveScan.js";
import { scanCookiesForSerialized } from "./deserializationScan.js";
import { probeTls } from "./tlsProbe.js";
import { analyzeSecrets, analyzeDataDumpExposure } from "./staticAnalysis.js";
import { buildScanCoverage, type ScanStage } from "./coverage.js";
import type { DiagnosticResult, ScanOptions } from "./scanTypes.js";
import { resultTier, resultMarker } from "./scoring.js";

// Re-export the SSRF, evidence, and findings-compilation entry points so
// existing importers of scanner.js keep working after these moved to dedicated
// modules (./ssrf.js, ./evidence.js, ./findings.js).
export { isBlockedIp, firstBlockedAddress, safeDispatcher, guardedFetch, assertScanTargetSafe, safeFetch } from "./ssrf.js";
export { looksLikeHtml, parseAuthHeader, renderRawRequest, windowAround } from "./evidence.js";
export { compileStaticFindings, compileScanEvidence } from "./findings.js";
export type { DiagnosticResult, ScanOptions } from "./scanTypes.js";
/**
 * Dedup key for a capture-sourced finding: the ENDPOINT, not the fuzzed URL.
 *
 * The fuzzer hits one endpoint once per payload, and each of those responses is
 * a separate capture whose `url` carries a different query string. Keying on the
 * full URL made every payload look like a new finding â€” the same weak reset token
 * was reported six times in one scan. Stripping the query collapses them to one.
 */
function captureKey(issue: string, file: string): string {
  try {
    const u = new URL(file);
    return `${issue}|${u.origin}${u.pathname}`;
  } catch {
    return `${issue}|${file}`;
  }
}

export async function runDiagnostics(
  targetUrl: string,
  authHeader?: string,
  opts: ScanOptions = {},
): Promise<DiagnosticResult> {
  const allowActiveProbes = !!opts.allowActiveProbes;
  // The aggressive tier is more invasive, so it requires BOTH the active-probe
  // gate (verified ownership) AND an explicit per-scan opt-in.
  const allowAggressiveProbes = allowActiveProbes && !!opts.allowAggressiveProbes;
  // Live progress sink for the real-time ticker (no-op when nobody's watching).
  const emit = opts.emit;
  // How many tech-gated templates were actually selected to run (for coverage).
  let templatesRun = 0;
  // Stages below that threw and were caught so the scan could go on. They did
  // not finish, and the coverage record says so instead of listing them as
  // ran-and-clean.
  const failedStages: ScanStage[] = [];
  let url = targetUrl.trim();
  if (!/^https?:\/\//i.test(url)) {
    url = "https://" + url;
  }

  const parsedUrl = new URL(url);
  const host = parsedUrl.origin;
  const hostname = parsedUrl.hostname;

  // SSRF guard: refuse internal/reserved targets before issuing any request.
  await assertTargetIsScannable(parsedUrl);

  const result: DiagnosticResult = {
    url,
    scannedAt: new Date().toISOString(),
    responseStatus: 0,
    sslSecure: url.startsWith("https://"),
    headers: {},
    missingHeaders: [],
    techLeaked: [],
    probedPaths: [],
    cookieIssues: [],
    cookieEvidence: {},
    sastFindings: [],
    scaLibraries: [],
    easmPerimeter: {
      subdomains: [],
      ip: "", // resolved from real DNS below
      nameserver: "", // resolved from real DNS below
      protocol: url.startsWith("https://") ? "HTTPS" : "HTTP",
    },
    redTeamFindings: [],
    activeProbesSkipped: !allowActiveProbes,
  };

  const headers: Record<string, string> = {
    "User-Agent": SCANNER_USER_AGENT,
    Accept:
      "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
  };
  // Authenticated scanning: the user-supplied credential is applied to EVERY
  // request path (root fetch, probes, crawl, and templates) so auth-gated
  // surface is actually reached.
  const authHeaders = parseAuthHeader(authHeader);
  Object.assign(headers, authHeaders);

  // The session the crawl establishes, appended to authedFetch requests AFTER
  // the crawl. Empty until then. Every authedFetch consumer is SAME-ORIGIN (the
  // crawl itself, OpenAPI discovery, and templates all hit the scanned host), so
  // carrying the target's own session here never leaks it cross-origin â€” unlike
  // the firebase/bucket probes, which fetch third-party origins with plain
  // `headers` on purpose. A real user-supplied auth Cookie is placed first and
  // wins; the crawl session is appended after it.
  let crawlSessionCookie = "";

  // Wrapper that injects the auth + scanner identity into crawler/template
  // requests, which otherwise only carry their own minimal headers.
  const authedFetch = (u: string, init: RequestInit) => {
    const initHeaders = (init.headers as Record<string, string>) || {};
    const cookieParts = [authHeaders["Cookie"], initHeaders["Cookie"], crawlSessionCookie].filter(Boolean);
    const merged: Record<string, string> = {
      "User-Agent": headers["User-Agent"],
      ...authHeaders,
      ...initHeaders,
    };
    if (cookieParts.length) merged["Cookie"] = cookieParts.join("; ");
    return safeFetch(u, { ...init, headers: merged });
  };

  // Passive recon of the root document: headers, cookies, SAST secrets, SCA
  // libraries, EASM perimeter, and sensitive paths. Returns the root HTML to
  // seed the crawler. Throws on an unreachable target. See server/passiveScan.ts.
  emit?.("system", "Target validated. Passive recon: headers, TLS, secrets, libraries, perimeter & sensitive pathsâ€¦");
  const { rootHtml, rootCookies } = await runPassiveScan(url, host, hostname, headers, result, emit);

  // TLS/certificate posture (HTTPS only, read-only, SSRF-gated). A plain fetch
  // can't see an expired cert or a deprecated protocol â€” one handshake can.
  // Best-effort: never throws, and a failed handshake leaves no finding (the
  // coverage record marks the certificate checks as not completed instead).
  // Checked where the root request ended, so a typed http:// URL that redirects
  // to HTTPS still gets its certificate inspected.
  try {
    result.tls = await probeTls(result.finalUrl || url);
  } catch {
    /* posture is a bonus signal â€” a probe failure must never fail the scan */
  }

  // RED TEAM active fuzzing (SQLi/XSS/cmd-injection/SSRF, incl. blind OOB).
  // Gated behind verified domain ownership. See server/redTeamProbes.ts.
  if (allowActiveProbes) emit?.("system", "Active red-team probes â€” firing real exploit payloads at the targetâ€¦");
  result.redTeamFindings = allowActiveProbes
    ? await runRedTeamProbes(url, headers, { oob: opts.oob, scanId: opts.scanId, emit })
    : [];

  // API SECURITY active probes (GraphQL introspection, exposed user object,
  // two-identity BOLA). Gated behind ownership. See server/apiProbes.ts.
  if (allowActiveProbes) emit?.("system", "API security probes â€” GraphQL introspection, exposed objects, BOLA/IDORâ€¦");
  result.apiSecFindings = allowActiveProbes
    ? await runApiSecProbes(url, host, headers, { bolaIdentities: opts.bolaIdentities })
    : [];

  // Insecure deserialization (PASSIVE, unconditional): a native serialized
  // object stored in a cookie the server issued is deserialized on every
  // request â€” CWE-502 exposure. Inspects only the root Set-Cookie lines already
  // captured; makes no new request. Placed AFTER the apiSecFindings assignment
  // above so it isn't overwritten; per-page cookies are scanned in the crawl
  // loop below. See server/deserializationScan.ts.
  for (const df of scanCookiesForSerialized(rootCookies, url)) {
    const key = `${df.testName}|${df.endpoint}`;
    if (!(result.apiSecFindings || []).some((f) => `${f.testName}|${f.endpoint}` === key)) {
      result.apiSecFindings = [...(result.apiSecFindings || []), df];
    }
  }
  if (allowActiveProbes && emit) {
    for (const f of result.apiSecFindings || []) {
      // Label by the finding's actual tier, not a blanket "CONFIRMED". An
      // inconclusive cross-tenant result is NEEDS VERIFICATION; the "Enforced"
      // pass is PASS; only a real, high-confidence finding is CONFIRMED/PROVEN.
      emit("result", `${resultMarker(resultTier(f))}: ${f.testName} [${f.severity.toUpperCase()}] â€” ${f.endpoint}`);
    }
  }

  // JWT auth-weakness probe runs AFTER the crawl below (it can use a signing
  // secret the crawl discovers in a leaked file, e.g. a served .env) â€” see
  // the crawl.captures loop.
  if (allowActiveProbes) {
    // DOM-based XSS (headless-browser execution proof). No-ops unless
    // ENABLE_BROWSER_RENDERING is set; non-mutating, so gated on ownership only.
    try {
      const domFinding = await probeDomXss(url, headers);
      if (domFinding) result.redTeamFindings = [...(result.redTeamFindings || []), domFinding];
    } catch (e) {
      console.warn("DOM-XSS probe encountered an error", e);
      failedStages.push("domXss");
    }
  }

  // AGGRESSIVE tier (opt-in, more invasive): SSTI, LFI/path-traversal, open
  // redirect, CRLF, CORS, out-of-band XXE, NoSQL injection. Non-destructive and
  // signature/OOB-proven. Appended to the red-team findings so they share the
  // RED_TEAM category, PROVEN-receipt scoring, and the report/fix-prompt pipeline.
  if (allowAggressiveProbes) {
    emit?.("system", "Aggressive tier â€” SSTI, LFI, XXE, CORS, CRLF, open-redirect, NoSQL, host-headerâ€¦");
    const aggressive = await runAggressiveProbes(url, headers, { oob: opts.oob, scanId: opts.scanId, emit });
    result.redTeamFindings = [...(result.redTeamFindings || []), ...aggressive];
  }

  // --- CRAWL + DISCOVERED-PARAMETER FUZZING ---
  // Map the real attack surface (links, forms, JS-referenced endpoints) and aim
  // the injection probes at the parameters the application actually uses, rather
  // than only a few hardcoded names. Strictly bounded by page/request/time caps.
  try {
    if (rootHtml && result.responseStatus > 0) {
      emit?.("system", "Crawling to map the attack surface (links, forms, JS-referenced endpoints)â€¦");
      const crawl = await crawlSite(url, authedFetch, {
        maxPages: 10,
        maxDepth: 2,
        budgetMs: 15000,
        seedHtml: rootHtml,
        // Seed the crawl's session jar with the root response's cookies (the
        // session cookie most apps set on first contact) so pages that only
        // render in-session are mapped. Read-only GET crawl â€” never a
        // state-changing request. See CookieJar in server/crawler.ts.
        initialCookies: rootCookies,
      });

      // Extend secret-signature + cookie-flag analysis beyond the root
      // document to every page the crawler actually visited, HTML or not â€”
      // e.g. a JSON API endpoint (like /api/settings) that hardcodes secrets
      // in its response, or a cookie set by a page other than the root.
      // Deduped so the same secret/cookie found via multiple pages isn't
      // repeated in the report.
      const seenSecretKeys = new Set(result.sastFindings.map((f) => captureKey(f.issue, f.file)));
      const isHttpsTarget = result.sslSecure;
      // The page's own scripts (the crawler follows links, not <script src>): a built single-page app keeps its
      // project URL, keys and table and bucket names there.
      const scripts = await fetchFirstPartyScripts(rootHtml, url, headers).catch(() => []);
      const scriptCaptures = scripts.map((sc) => ({ url: sc.url, status: 200, contentType: "application/javascript", text: sc.text, setCookie: [] as string[] }));
      for (const capture of [...crawl.captures, ...scriptCaptures]) {
        for (const sf of analyzeSecrets(capture.text, capture.url)) {
          const key = captureKey(sf.issue, sf.file);
          if (seenSecretKeys.has(key)) continue;
          seenSecretKeys.add(key);
          result.sastFindings.push(sf);
        }
        for (const df of analyzeDataDumpExposure(capture.text, capture.url)) {
          const key = captureKey(df.issue, df.file);
          if (seenSecretKeys.has(key)) continue;
          seenSecretKeys.add(key);
          result.sastFindings.push(df);
        }
        for (const ci of cookieFlagIssues(capture.setCookie, isHttpsTarget, result.cookieIssues.length)) {
          const issue = ci.message;
          if (!result.cookieIssues.includes(issue)) {
            result.cookieIssues.push(issue);
            result.cookieEvidence[issue] = ci.observed;
          }
        }
        // Passive â€” no new request, just inspecting what the crawler already
        // fetched â€” so this runs unconditionally like the checks above, not
        // gated behind allowActiveProbes (unlike the fixed-path exposed-
        // user-object probe in apiProbes.ts, which makes its own requests).
        for (const capFinding of [
          exposedUserListInCapture(capture.text, capture.url),
          exposedCredentialListInCapture(capture.text, capture.url),
          // Serialized object in a cookie this page set â€” insecure-deser exposure.
          ...scanCookiesForSerialized(capture.setCookie, capture.url),
        ]) {
          if (!capFinding) continue;
          const key = `${capFinding.testName}|${capFinding.endpoint}`;
          if (!(result.apiSecFindings || []).some((f) => `${f.testName}|${f.endpoint}` === key)) {
            result.apiSecFindings = [...(result.apiSecFindings || []), capFinding];
          }
        }
      }

      // Every response body this scan has actually seen the text of, for the
      // two content-correlation checks below â€” NOT just crawl.captures,
      // which only covers pages the crawler itself fetched while following
      // links. The root document is SEEDED into the crawler (never
      // "fetched" by it, so it's absent from captures) and a sensitive-path
      // hit like /.env is fetched by server/perimeter.ts entirely separately
      // from the crawl. Missing either source means missing exactly the
      // cases these checks exist for (a key declared on the homepage itself;
      // a secret leaked via sensitive-path probing rather than a crawled
      // link) â€” confirmed by a real miss against the Tier 3 fixture before
      // this was added.
      const allScannedText = [
        rootHtml,
        ...crawl.captures.map((c) => c.text),
        ...scriptCaptures.map((c) => c.text),
        ...result.probedPaths.map((p) => p.body).filter((b): b is string => !!b),
      ];

      // Header set for every probe below this point: the crawl's own
      // established session (see CookieJar in server/crawler.ts) merged in
      // behind whatever Cookie the caller already supplied. A probe that
      // re-requests a page can then reach content that only renders once that
      // GET-only session is present â€” the crawl already proved it reads, so
      // reusing it here costs no extra request. Never overrides a real
      // user-supplied auth Cookie: appended after it when both exist, used
      // alone only when the caller supplied none.
      const existingCookie = headers["Cookie"] || headers["cookie"];
      const mergedCookie = crawl.sessionCookie
        ? existingCookie
          ? `${existingCookie}; ${crawl.sessionCookie}`
          : crawl.sessionCookie
        : existingCookie;
      const postCrawlHeaders: Record<string, string> = mergedCookie
        ? { ...headers, Cookie: mergedCookie }
        : headers;
      // Also make the SAME-ORIGIN authedFetch consumers (OpenAPI discovery,
      // templates) session-aware â€” they run after this point and would otherwise
      // re-request with only the caller's headers. Cross-origin probes never use
      // authedFetch, so this stays inside the same-origin boundary.
      crawlSessionCookie = crawl.sessionCookie || "";

      // Weak-session-token probe, run FIRST after the crawl. It spends exactly one
      // real login, and every later POST probe (prototype pollution, price
      // tampering, webhook signature, then fuzzing) also hits the login form â€”
      // on a target with a login rate limiter (Tier 1: 5 per 15 min) those
      // used the allowance up and this login got a 429, so a real weak token
      // went unreported. Found by re-running the Tier 1 fixture 2026-09-25.
      let weakTokenProbed = false;
      const runWeakTokenProbe = async (targets: typeof crawl.targets) => {
        if (!allowAggressiveProbes || !opts.loginCredentials) return;
        const loginTarget = findLoginTarget(targets);
        if (!loginTarget) return;
        weakTokenProbed = true;
        emit?.("system", `Testing session token strength via ${loginTarget.url}â€¦`);
        try {
          const weakToken = await probeWeakSessionToken(loginTarget, opts.loginCredentials, { ...postCrawlHeaders, "Cache-Control": "no-cache" });
          if (weakToken) result.redTeamFindings = [...(result.redTeamFindings || []), weakToken];
        } catch (e) {
          console.warn("Weak session-token probe encountered an error", e);
          failedStages.push("weakSessionToken");
        }
      };
      await runWeakTokenProbe(crawl.targets);

      // Exposed JavaScript source maps (passive, same-origin): a shipped .js.map
      // reconstructs the original un-minified source. Runs unconditionally like
      // the sensitive-path probing above â€” it only GETs the target's OWN .map
      // assets, confirmed by the Source-Map-v3 JSON signature (never a 200 alone).
      // Reported LOW via the probedPaths `meta` mechanism.
      try {
        const smCaptures = [{ url, text: rootHtml }, ...crawl.captures.map((c) => ({ url: c.url, text: c.text }))];
        const exposedMaps = await probeExposedSourceMaps(smCaptures, url, postCrawlHeaders);
        if (exposedMaps.length) result.probedPaths.push(...exposedMaps);
      } catch (e) {
        console.warn("Source-map exposure probe encountered an error", e);
        failedStages.push("sourceMaps");
      }

      // Cross-origin credential chaining: a client-side key paired with the
      // URL it's for (both disclosed in the SAME served content) is tested
      // against that OTHER origin â€” the only probe in this codebase that
      // ever calls back to somewhere other than the scanned target. The
      // target origin is one the scanned app's own content named, not a
      // guess, and reuses safeFetch's existing SSRF gate unchanged. Gated
      // behind ownership like the other active probes.
      if (allowActiveProbes) {
        const urlKeyPairs = allScannedText.flatMap((t) => extractUrlKeyPairs(t));
        if (urlKeyPairs.length) {
          try {
            const allText = allScannedText.join("\n");
            const chainFinding = await probeCredentialUrlPairs(urlKeyPairs, extractTableNames(allText));
            if (chainFinding) result.apiSecFindings = [...(result.apiSecFindings || []), chainFinding];
          } catch (e) {
            console.warn("Credential-chain probe encountered an error", e);
            failedStages.push("credentialChain");
          }
          // Supabase Storage with the same key: can anyone list the files in a bucket the app's code opens?
          try {
            const storageFinding = await probeSupabaseStorage(urlKeyPairs, extractStorageBucketNames(allScannedText.join("\n")));
            if (storageFinding) result.apiSecFindings = [...(result.apiSecFindings || []), storageFinding];
          } catch (e) {
            console.warn("Supabase Storage probe encountered an error", e);
            failedStages.push("supabaseStorage");
          }
        }
      }

      // Firebase Realtime Database open-rules: extract any RTDB URL the scanned
      // app's own bundle references (Firebase web config is public by design) and
      // prove the database's security RULES permit an unauthenticated read â€” a
      // 200 at `<db>/.json` where a locked-down DB returns 401. Read-only, and
      // the DB origin is one the app named, not a guess. Same cross-origin BaaS
      // discipline + ownership gate as the credential-chain probe above.
      if (allowActiveProbes) {
        const fbDbUrls = [...new Set(allScannedText.flatMap((t) => extractFirebaseDbUrls(t)))];
        if (fbDbUrls.length) {
          try {
            // Deliberately plain `headers`, NOT postCrawlHeaders: this is a
            // cross-origin request to firebaseio.com, a different origin from
            // the scanned app. probeFirebaseOpenDb only reads User-Agent out of
            // this, but the crawl's session Cookie must never even be offered
            // to a third-party origin.
            const fbFinding = await probeFirebaseOpenDb(fbDbUrls, headers);
            if (fbFinding) result.apiSecFindings = [...(result.apiSecFindings || []), fbFinding];
          } catch (e) {
            console.warn("Firebase open-DB probe encountered an error", e);
            failedStages.push("firebase");
          }
        }
      }

      // Open cloud-storage buckets: extract any S3/GCS/Azure bucket the scanned
      // app's own content references and prove it permits an anonymous object
      // LIST (a 200 listing document where a locked-down bucket returns 403).
      // Read-only GETs, buckets named by the app not guessed â€” same cross-origin
      // discipline + ownership gate as the Firebase/credential-chain probes above.
      if (allowActiveProbes) {
        const bucketRefs = extractBucketUrls(allScannedText.join("\n"));
        if (bucketRefs.length) {
          try {
            // Deliberately plain `headers`, NOT postCrawlHeaders: this hits a
            // third-party bucket origin (S3/GCS/Azure), not the scanned app.
            // Same reasoning as the Firebase probe above â€” never offer the
            // crawl's session Cookie to a different origin.
            const bucketFinding = await probeOpenBuckets(bucketRefs, headers, hostname);
            if (bucketFinding) result.apiSecFindings = [...(result.apiSecFindings || []), bucketFinding];
          } catch (e) {
            console.warn("Open-bucket probe encountered an error", e);
            failedStages.push("buckets");
          }
        }
      }

      // CSRF posture: a SameSite=None session cookie (cross-site-sendable) plus a
      // state-changing form with no anti-CSRF token. Read-only inference over
      // data already gathered â€” the Set-Cookie attributes and the crawled forms â€”
      // so it needs no extra request and no ownership gate (passive posture, not
      // an exploit). Reported medium-confidence / needs-verification.
      try {
        const cookieLines = [
          ...(result.setCookies || []),
          ...crawl.captures.flatMap((c) => (c.setCookie || []).map(redactCookieValue)),
        ];
        const forms = crawl.targets
          .filter((t) => t.source === "form" && t.method === "POST")
          .map((t) => ({ url: t.url, method: t.method, params: t.params, discoveredOnPage: t.discoveredOnPage }));
        const csrfFinding = assessCsrf(cookieLines, forms);
        if (csrfFinding) result.apiSecFindings = [...(result.apiSecFindings || []), csrfFinding];
      } catch (e) {
        console.warn("CSRF posture check encountered an error", e);
        failedStages.push("csrf");
      }

      // Edge Function auth-bypass: extract any Edge/serverless function URL the
      // scanned app's own content references (a .../functions/v1/<name> ref or a
      // functions.invoke('<name>') call + a discovered base URL) and prove it
      // accepts a forged token where no token is denied. Read-only (GET), like
      // the JWT probe; the function origin is one the app named, not a guess.
      if (allowActiveProbes) {
        try {
          const edgeFinding = await probeEdgeFunctionAuth(allScannedText, postCrawlHeaders);
          if (edgeFinding) result.redTeamFindings = [...(result.redTeamFindings || []), edgeFinding];
        } catch (e) {
          console.warn("Edge Function auth probe encountered an error", e);
          failedStages.push("edgeFunction");
        }
      }

      // JWT auth-weakness probe. Delayed until after the crawl above so it
      // can also try re-signing with any JWT signing secret the crawl found
      // leaked in a served file (e.g. .env) â€” a validly-signed forged token
      // is a materially stronger proof than the alg:none/tampered-signature
      // forgeries alone (see extractJwtSecretCandidates in jwtProbe.ts).
      if (allowActiveProbes) {
        const secretCandidates = [
          ...new Set(allScannedText.flatMap((t) => extractJwtSecretCandidates(t))),
        ];
        try {
          const jwtFinding = await probeJwtAuth(
            url,
            postCrawlHeaders,
            secretCandidates,
            crawl.captures.map((c) => c.url),
          );
          if (jwtFinding) result.redTeamFindings = [...(result.redTeamFindings || []), jwtFinding];
        } catch (e) {
          console.warn("JWT auth probe encountered an error", e);
          failedStages.push("jwt");
        }
      }

      // Locale-route auth bypass: unlike the checks above this makes NEW
      // requests (a locale-swapped sibling of each discovered /en//es/ path),
      // so it's gated behind verified ownership like the other active probes,
      // even though it's read-only. Every URL the crawl fetched at all (not
      // just ones that became "pages") is a candidate, since a 401/403 JSON
      // response never becomes a page but is exactly the gated half of the
      // differential this needs.
      if (allowActiveProbes) {
        try {
          const i18nFinding = await probeI18nAuthBypass(
            url,
            crawl.captures.map((c) => c.url),
            { ...postCrawlHeaders, "Cache-Control": "no-cache" },
          );
          if (i18nFinding) result.redTeamFindings = [...(result.redTeamFindings || []), i18nFinding];
        } catch (e) {
          console.warn("i18n auth-bypass probe encountered an error", e);
          failedStages.push("i18n");
        }
      }

      // Server-side prototype pollution (AGGRESSIVE tier). Needs discovered POST
      // endpoints, so it runs here (after the crawl) rather than in the root-only
      // aggressive orchestrator above. It POSTs a benign body then the "json
      // spaces" gadget and proves pollution via a response-formatting flip â€” the
      // one probe that leaves a transient (cosmetic, self-healing) trace, so it's
      // gated behind the aggressive+ownership tier and reverts the gadget on a hit.
      if (allowAggressiveProbes) {
        const postUrls = [
          ...new Set(crawl.targets.filter((t) => t.method === "POST").map((t) => t.url)),
        ];
        try {
          const ppFinding = await probePrototypePollution(url, postUrls, { ...postCrawlHeaders, "Cache-Control": "no-cache" });
          if (ppFinding) result.redTeamFindings = [...(result.redTeamFindings || []), ppFinding];
        } catch (e) {
          console.warn("prototype-pollution probe encountered an error", e);
          failedStages.push("prototypePollution");
        }

        // Business-logic price tampering (client-controlled price honored). Sends
        // only line items â€” no payment instrument, no confirmation â€” so it can
        // elicit at most a quote/total, never a real charge. Same aggressive+owned
        // gate + discovered-POST-target set as the prototype-pollution probe.
        try {
          const priceFinding = await probePriceManipulation(url, postUrls, { ...postCrawlHeaders, "Cache-Control": "no-cache" });
          if (priceFinding) result.redTeamFindings = [...(result.redTeamFindings || []), priceFinding];
        } catch (e) {
          console.warn("price-manipulation probe encountered an error", e);
          failedStages.push("priceManipulation");
        }

        // Webhook signature-verification bypass. Sends only a zero-amount
        // FAILURE event for a nonexistent entity, so acceptance processes nothing
        // of value â€” proving the (conditional) signature skip without a real
        // payment side effect. Same aggressive+owned gate + discovered-POST set.
        try {
          const webhookFinding = await probeWebhookSignatureBypass(url, postUrls, { ...postCrawlHeaders, "Cache-Control": "no-cache" });
          if (webhookFinding) result.redTeamFindings = [...(result.redTeamFindings || []), webhookFinding];
        } catch (e) {
          console.warn("webhook-signature probe encountered an error", e);
          failedStages.push("webhookSignature");
        }

        // Missing rate-limit on OTP/2FA verification. Observational (absence of a
        // control) â†’ reported at LOW confidence and LOW severity, never PROVEN. A
        // bounded burst of wrong codes sized to outlast the common 3-30 limiter
        // thresholds; bails the instant any throttle signal appears.
        try {
          const rlFinding = await probeAuthRateLimit(url, postUrls, { ...postCrawlHeaders, "Cache-Control": "no-cache" });
          if (rlFinding) result.redTeamFindings = [...(result.redTeamFindings || []), rlFinding];
        } catch (e) {
          console.warn("auth-rate-limit probe encountered an error", e);
          failedStages.push("authRateLimit");
        }
      }

      // Optional headless rendering: merge JS-rendered links and XHR/fetch
      // endpoints the static crawl cannot see (no-op unless explicitly enabled).
      let allTargets = crawl.targets;
      if (isRenderingEnabled()) {
        const rendered = await renderPage(url, {
          "User-Agent": headers["User-Agent"],
          ...authHeaders,
          ...(mergedCookie ? { Cookie: mergedCookie } : {}),
        });
        if (rendered) {
          const renderedTargets = [
            ...targetsFromHtml(rendered.html, url),
            ...rendered.requestedUrls
              .map((u) => ({ url: u, method: "GET" as const, params: paramsOf(u), source: "script" as const }))
              .filter((t) => t.params.length > 0),
          ];
          allTargets = dedupeTargets([...crawl.targets, ...renderedTargets]);
        }
      }

      // Weak-session-token probe: only runs when the caller explicitly supplied
      // real login credentials for a target they own (never guessed) â€” logs in
      // ONCE against a discovered login-shaped form and tries to reproduce the
      // resulting token from common weak (seed, algorithm) recipes. Aggressive
      // tier, same trust bar as the other credentialed/mutating probes below.
      // Deliberately runs BEFORE discovered-parameter fuzzing: fuzzing hits
      // every discovered form (including this same login form) with many
      // payloads, which can exhaust a target's own login rate limiter before
      // this probe's one legitimate login gets a turn â€” so it goes first.
      //
      // Normally it already ran right after the crawl (see runWeakTokenProbe
      // above); this later call only covers a login form that browser rendering
      // surfaced after that point.
      if (!weakTokenProbed) await runWeakTokenProbe(allTargets);

      // Mapping (crawl) is always allowed â€” it's passive same-origin GETs.
      // Fuzzing the discovered parameters is an active exploit attempt, so it
      // is gated behind verified domain ownership like the other red-team probes.
      let fuzz = { findings: [] as any[], paramsTested: 0, captures: [] as FuzzCapture[] };
      if (allowActiveProbes) {
        // Fuzz both GET query parameters and POST form fields the crawler mapped.
        // The fuzzer sends each payload with the target's own method (query string
        // for GET, form-encoded body for POST), so discovered forms are no longer
        // mapped-but-skipped.
        const discovered = allTargets.filter((t) => t.params.length > 0);

        // Parameter MINING: on the root and any crawled pages that linked no
        // parameters, guess common injectable names and keep the ones the app
        // reflects (plus a small always-test set), so injection probing reaches a
        // surface even on SPAs / JSON APIs that link or form nothing â€” the case
        // where the crawl otherwise yields zero fuzzable parameters. See
        // server/paramMiner.ts.
        const pathOf = (u: string) => { try { const p = new URL(u); return p.origin + p.pathname; } catch { return u; } };
        const paramPaths = new Set(discovered.map((t) => pathOf(t.url)));
        const mineBases = [url, ...crawl.pages].filter((p) => !paramPaths.has(pathOf(p)));
        emit?.("system", "Parameter mining: guessing common injectable parameter names on paths that linked noneâ€¦");
        const guessed = await buildGuessedTargets(mineBases, { ...postCrawlHeaders, "Cache-Control": "no-cache" });
        if (guessed.length) {
          const total = guessed.reduce((n, g) => n + g.params.length, 0);
          emit?.("recon", `Parameter mining: ${guessed.length} path(s), ${total} candidate parameter(s) to fuzz.`);
        }

        // API-first testing: discover an OpenAPI/Swagger spec and fuzz every
        // DECLARED operation's parameters â€” the full API surface, not just what
        // the crawl referenced. GET operations (reads) run here under active
        // probing; POST operations (which can create state) are held to the
        // aggressive opt-in, the same non-destructive line the rest of the fuzzer
        // draws. Same-origin only, via the SSRF-guarded authedFetch.
        let apiTargets: InjectableTarget[] = [];
        try {
          const api = await discoverAndParseApi(url, authedFetch, {
            explicitUrl: opts.apiSchemaUrl,
            includePost: allowAggressiveProbes,
          });
          if (api) {
            apiTargets = api.targets;
            let specPath = api.specUrl;
            try { specPath = new URL(api.specUrl).pathname; } catch { /* keep full */ }
            emit?.("recon", `API schema: ${api.format} at ${specPath} â€” ${api.operationCount} declared operation(s) queued for fuzzing.`);
          }
        } catch (e) {
          console.warn("API-schema discovery encountered an error", e);
          failedStages.push("apiSchema");
        }

        // Fuzz discovered + mined + schema-declared parameters. Add a JSON-body
        // twin for API-looking endpoints so injection is exercised over
        // application/json, not only form-encoded bodies (many APIs accept only JSON).
        let fuzzTargets = dedupeTargets([...discovered, ...guessed, ...apiTargets]);
        const apiRe = /\/(api|graphql|rest|v\d)(\/|$)/i;
        const jsonTwins = fuzzTargets
          .filter((t) => apiRe.test(pathOf(t.url)))
          .map((t) => ({ url: t.url, method: "POST" as const, params: t.params, source: "script" as const, contentType: "json" as const }));
        fuzzTargets = [...fuzzTargets, ...jsonTwins];

        if (fuzzTargets.length) emit?.("system", `Fuzzing ${fuzzTargets.length} parameterized endpoint(s) (discovered + mined) with injection payloadsâ€¦`);
        fuzz = await fuzzDiscoveredTargets(fuzzTargets, { ...postCrawlHeaders, "Cache-Control": "no-cache" }, { aggressive: allowAggressiveProbes, emit });
        result.redTeamFindings = [...(result.redTeamFindings || []), ...fuzz.findings];

        // Fuzzing is the only pass that ever POSTs to these endpoints, so it's
        // the only place a JSON response like a password-reset token is ever
        // seen â€” scan every response it captured for weak/low-entropy security
        // tokens the app put in its own body (see weakTokenScan.ts).
        for (const capture of fuzz.captures) {
          for (const wf of weakTokenFindings(capture.text, capture.url)) {
            const key = captureKey(wf.issue, wf.file);
            if (seenSecretKeys.has(key)) continue;
            seenSecretKeys.add(key);
            result.sastFindings.push(wf);
          }
        }
      }

      // Stored/persistent XSS over discovered POST forms. Aggressive tier: it
      // submits a persisting marker (mutates state), so it requires the same
      // explicit opt-in as the other invasive probes. Proves the two-step flow â€”
      // POST the marker, then see it on a separate GET.
      if (allowAggressiveProbes) {
        const formTargets = allTargets.filter((t) => t.method === "POST" && t.params.length > 0);
        const stored = await probeStoredXss(formTargets, { ...postCrawlHeaders, "Cache-Control": "no-cache" });
        result.redTeamFindings = [...(result.redTeamFindings || []), ...stored];
      }

      // LLM prompt-injection (aggressive tier): POSTs a prompt to any LLM-backed
      // endpoint the crawl found (or a small curated guess-list) and proves the
      // model obeys an injected instruction-override via a DOUBLE computed-canary
      // oracle (two independent products it must compute â€” reflection/templating
      // can't). Aggressive+owned because it POSTs prompts that cost the owner LLM
      // tokens. See server/llmProbe.ts.
      if (allowAggressiveProbes) {
        try {
          const llmTargets = allTargets.map((t) => ({ url: t.url, method: t.method, params: t.params }));
          const llmHeaders = { ...postCrawlHeaders, "Cache-Control": "no-cache" };
          const llmFinding = await probeLlmPromptInjection(llmTargets, host, llmHeaders);
          if (llmFinding) result.redTeamFindings = [...(result.redTeamFindings || []), llmFinding];

          // AI-scope probes (proof-gated): memory poisoning (a planted canary
          // that leaks into an independent request) and insecure tool use (the
          // model fetching an injected OOB URL â€” callback is the proof, needs a
          // collaborator). Both fire only on hard evidence. See server/llmProbe.ts.
          const memFinding = await probeLlmMemoryPoisoning(llmTargets, host, llmHeaders);
          if (memFinding) result.redTeamFindings = [...(result.redTeamFindings || []), memFinding];

          const toolFinding = await probeLlmInsecureToolUse(llmTargets, host, llmHeaders, opts.oob, opts.scanId);
          if (toolFinding) result.redTeamFindings = [...(result.redTeamFindings || []), toolFinding];
        } catch (e) {
          console.warn("LLM prompt-injection probe encountered an error", e);
          failedStages.push("llm");
        }
      }

      result.crawl = {
        pagesVisited: crawl.pagesVisited,
        endpointsDiscovered: allTargets.length,
        paramsTested: fuzz.paramsTested,
        sampleEndpoints: allTargets.slice(0, 8).map((t) => {
          try {
            return new URL(t.url).pathname + (t.params.length ? `?${t.params.join("&")}` : "");
          } catch {
            return t.url;
          }
        }),
      };
      emit?.("recon", `Surface mapped: ${crawl.pagesVisited} page(s), ${allTargets.length} endpoint(s), ${fuzz.paramsTested} parameter(s) fuzzed.`);
    }
  } catch (crawlErr) {
    console.warn("Crawl/fuzz stage encountered an error", crawlErr);
    failedStages.push("crawl");
  }

  // --- TEMPLATE-BASED DETECTIONS ---
  // Data-driven checks (exposed panels, config/backup files, actuators, etc.).
  // Each template confirms via a body signature, so SPA fallbacks aren't flagged.
  try {
    if (result.responseStatus > 0) {
      // Gate framework-specific templates by the detected tech profile so the
      // pack scales without running every stack's checks against every target.
      const techTags = detectTechTags(result.headers, rootHtml);
      const selected = selectTemplates(TEMPLATES, techTags);
      templatesRun = selected.length;
      result.templateFindings = await runTemplates(host, authedFetch, selected, 6);
    }
  } catch (tplErr) {
    console.warn("Template detection stage encountered an error", tplErr);
    failedStages.push("templates");
  }

  // Full-transparency coverage record: exactly which check groups ran against
  // this target and how many discrete checks each fired.
  result.coverage = buildScanCoverage({
    activeProbesRun: allowActiveProbes,
    aggressiveProbesRun: allowAggressiveProbes,
    subdomainsChecked: result.easmPerimeter.subdomains.length,
    pathsProbed: result.probedPaths.length,
    templatesRun,
    crawlPages: result.crawl?.pagesVisited ?? 0,
    paramsFuzzed: result.crawl?.paramsTested ?? 0,
    domXssRun: allowActiveProbes && isRenderingEnabled(),
    tlsHandshake: !result.sslSecure ? "not-https" : result.tls?.reachable ? "ok" : "failed",
    failedStages,
  });

  return result;
}
