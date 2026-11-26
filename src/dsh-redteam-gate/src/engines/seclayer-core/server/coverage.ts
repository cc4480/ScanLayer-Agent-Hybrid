// Full-transparency scan-coverage accounting. Builds the per-scan record of
// exactly which check groups ran against a target and how many discrete checks
// each fired — from the real run, using the same probe arrays the scanner
// executes (so the numbers can't drift from what actually happened). Gated groups
// (ownership-required exploit probes, the aggressive opt-in) are listed with
// their would-run count and ran:false + a reason, so a report can show both what
// ran and what's available once the domain is verified.
import type { ScanCoverage, ScanCoverageItem } from "../src/types.js";
import { SECURITY_HEADERS } from "./passiveScan.js";
import { SECRET_SIGNATURE_COUNT, LIBRARY_SIGNATURE_COUNT } from "./staticAnalysis.js";
import { RED_TEAM_PROBE_COUNT } from "./redTeamProbes.js";
import { AGGRESSIVE_PROBE_COUNT } from "./aggressiveProbes.js";
import { API_PROBE_COUNT } from "./apiProbes.js";

const OWNERSHIP_NOTE = "requires verified domain ownership";
const AGGRESSIVE_NOTE = "requires the aggressive opt-in + verified ownership";
const FAILED_NOTE = "stopped with an error, so its results are missing, not clean";

const TLS_POSTURE = "TLS certificate & protocol posture";
const CRAWL = "Crawl / surface mapping (pages)";
const TEMPLATES = "Template detection pack (tech-gated)";
const PARAM_FUZZING = "Discovered + mined parameter injection fuzzing";
const JWT = "JWT auth-weakness probe";
const DOM_XSS = "DOM-based XSS (headless execution proof)";
const STORED_XSS = "Stored/persistent XSS (discovered forms)";

// Stages scanner.ts runs inside their own try/catch, so that one failing probe
// cannot sink the whole scan. A stage that threw did not finish, and listing
// its group as run would tell the reader it ran and found nothing. Stages that
// feed a group above share its label; the rest get a row of their own when
// they fail.
export const SCAN_STAGES = {
  crawl: { label: CRAWL, category: "DAST" },
  templates: { label: TEMPLATES, category: "DAST" },
  domXss: { label: DOM_XSS, category: "RED_TEAM" },
  jwt: { label: JWT, category: "RED_TEAM" },
  sourceMaps: { label: "Exposed JavaScript source maps", category: "DAST" },
  csrf: { label: "CSRF posture (SameSite=None session cookie + tokenless form)", category: "IAST" },
  credentialChain: { label: "Credential chaining (disclosed key + the URL it is for)", category: "API_SEC" },
  firebase: { label: "Firebase open-database rules", category: "API_SEC" },
  buckets: { label: "Open cloud-storage bucket listing", category: "API_SEC" },
  supabaseStorage: { label: "Supabase Storage bucket listing (public key)", category: "API_SEC" },
  edgeFunction: { label: "Edge Function auth bypass", category: "RED_TEAM" },
  i18n: { label: "Locale-route auth bypass", category: "RED_TEAM" },
  weakSessionToken: { label: "Weak session-token probe", category: "RED_TEAM" },
  apiSchema: { label: "API schema discovery (OpenAPI/Swagger)", category: "DAST" },
  prototypePollution: { label: "Server-side prototype pollution", category: "RED_TEAM" },
  priceManipulation: { label: "Client-controlled price tampering", category: "RED_TEAM" },
  webhookSignature: { label: "Webhook signature-verification bypass", category: "RED_TEAM" },
  authRateLimit: { label: "OTP/2FA verification rate limiting", category: "RED_TEAM" },
  llm: { label: "LLM prompt-injection probes", category: "RED_TEAM" },
} as const;
export type ScanStage = keyof typeof SCAN_STAGES;

export interface CoverageInputs {
  activeProbesRun: boolean;
  aggressiveProbesRun: boolean;
  subdomainsChecked: number;
  pathsProbed: number;
  templatesRun: number;
  crawlPages: number;
  paramsFuzzed: number;
  domXssRun: boolean;
  // How the TLS handshake went. "failed" covers a handshake that never
  // completed (timeout, IPv6-only host): certificate expiry and protocol
  // were not checked, which is not the same as checked and fine.
  tlsHandshake: "ok" | "failed" | "not-https";
  failedStages?: ScanStage[];
}

export function buildScanCoverage(p: CoverageInputs): ScanCoverage {
  const active = p.activeProbesRun;
  const aggressive = p.aggressiveProbesRun;

  const items: ScanCoverageItem[] = [
    // --- Passive tier: always runs ---
    { label: "Security response headers", category: "IAST", checks: SECURITY_HEADERS.length, ran: true },
    { label: "Cookie security flags (Secure, HttpOnly)", category: "IAST", checks: 2, ran: true },
    // Passive CWE-502: a native serialized object (Java/PHP/Ruby/pickle) in a
    // cookie the server issues — deserialized on every request. See deserializationScan.ts.
    { label: "Insecure deserialization (serialized object in cookies)", category: "IAST", checks: 1, ran: true },
    { label: "HTTP-vs-HTTPS transport", category: "EASM", checks: 1, ran: true },
    // Certificate expiry + negotiated protocol version, read off one TLS
    // handshake by server/tlsProbe.ts.
    {
      label: TLS_POSTURE, category: "EASM", checks: 2, ran: p.tlsHandshake === "ok",
      failed: p.tlsHandshake === "failed" || undefined,
      note:
        p.tlsHandshake === "failed" ? "the TLS handshake did not complete, so certificate expiry and protocol were not checked"
        : p.tlsHandshake === "not-https" ? "the site is served over plain HTTP, so there is no certificate to inspect"
        : undefined,
    },
    { label: "DNS resolution (A record + nameserver)", category: "EASM", checks: 2, ran: true },
    { label: "Subdomain enumeration", category: "EASM", checks: p.subdomainsChecked, ran: p.subdomainsChecked > 0 },
    { label: "Exposed-secret signatures (SAST)", category: "SAST", checks: SECRET_SIGNATURE_COUNT, ran: true },
    { label: "Vulnerable-library signatures (SCA)", category: "SCA", checks: LIBRARY_SIGNATURE_COUNT, ran: true },
    { label: "Sensitive-path probing", category: "DAST", checks: p.pathsProbed, ran: p.pathsProbed > 0 },
    { label: TEMPLATES, category: "DAST", checks: p.templatesRun, ran: p.templatesRun > 0 },
    { label: CRAWL, category: "DAST", checks: p.crawlPages, ran: p.crawlPages > 0 },

    // --- Active exploit tier: gated behind verified ownership ---
    {
      label: "Red-team exploit probes (root URL): SQLi, XSS, cmd-injection, SSRF, blind SSRF",
      category: "RED_TEAM", checks: RED_TEAM_PROBE_COUNT, ran: active, note: active ? undefined : OWNERSHIP_NOTE,
    },
    {
      label: PARAM_FUZZING,
      category: "RED_TEAM", checks: p.paramsFuzzed, ran: active && p.paramsFuzzed > 0,
      note: active ? undefined : OWNERSHIP_NOTE,
    },
    {
      label: "API security probes: GraphQL introspection, GraphQL query-cost controls, exposed-object, BOLA/IDOR",
      category: "API_SEC", checks: API_PROBE_COUNT, ran: active, note: active ? undefined : OWNERSHIP_NOTE,
    },
    {
      label: JWT,
      category: "RED_TEAM", checks: 1, ran: active,
      note: active ? "fires only when a Bearer JWT is supplied" : OWNERSHIP_NOTE,
    },
    {
      label: DOM_XSS,
      category: "RED_TEAM", checks: 1, ran: p.domXssRun,
      note: p.domXssRun ? undefined : "requires ownership + ENABLE_BROWSER_RENDERING",
    },

    // --- Aggressive tier: explicit opt-in + ownership ---
    {
      label: "Aggressive injection tier: SSTI, LFI, XXE, CORS, CRLF, open-redirect, NoSQL, host-header",
      category: "RED_TEAM", checks: AGGRESSIVE_PROBE_COUNT, ran: aggressive, note: aggressive ? undefined : AGGRESSIVE_NOTE,
    },
    {
      label: STORED_XSS,
      category: "RED_TEAM", checks: 1, ran: aggressive, note: aggressive ? undefined : AGGRESSIVE_NOTE,
    },
  ];

  const markFailed = (label: string, category: string) => {
    const item = items.find((i) => i.label === label);
    if (item) Object.assign(item, { ran: false, failed: true, note: FAILED_NOTE });
    else items.push({ label, category, checks: 1, ran: false, failed: true, note: FAILED_NOTE });
  };
  for (const stage of new Set(p.failedStages ?? [])) {
    markFailed(SCAN_STAGES[stage].label, SCAN_STAGES[stage].category);
    // Fuzzing, the JWT probe and stored XSS all run inside the crawl stage.
    // When it stopped early there is no telling which of them got to run.
    if (stage === "crawl") {
      if (active) {
        markFailed(PARAM_FUZZING, "RED_TEAM");
        markFailed(JWT, "RED_TEAM");
      }
      if (aggressive) markFailed(STORED_XSS, "RED_TEAM");
    }
  }

  const totalChecks = items.reduce((sum, it) => sum + (it.ran ? it.checks : 0), 0);
  return { totalChecks, activeProbesRun: active, aggressiveProbesRun: aggressive, items };
}
