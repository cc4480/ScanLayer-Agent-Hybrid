// EASM perimeter mapping and sensitive-path probing. Resolves the target's real
// host IP and authoritative nameserver, enumerates common subdomains (wildcard-
// DNS aware so wildcards don't bloat the results with false positives), and
// probes a small set of high-value sensitive paths — treating one as "exposed"
// only when the response BODY matches the file's signature, not merely on a 200.
// Mutates the passed DiagnosticResult in place (easmPerimeter + probedPaths).
import type { DiagnosticResult } from "./scanner.js";
import { SCANNER_USER_AGENT } from "./config.js";
import type { Severity } from "../src/types.js";
import { safeFetch, resolveIpv4 } from "./ssrf.js";
import { looksLikeHtml } from "./evidence.js";
import { isLikelyPlaceholderSecret } from "./fpFilters.js";
import crypto from "crypto";
import * as dns from "dns/promises";

// One sensitive-path check. A path is "exposed" only when the response BODY
// matches `matches` (never a status code alone), which eliminates the dominant
// false positive: SPAs that serve index.html (HTTP 200) for every unknown path.
// `meta`, when present, carries this file's own finding wording + severity;
// absent → findings.ts applies its generic critical/high exposed-file mapping.
export interface SensitiveProbe {
  path: string;
  matches: (body: string) => boolean;
  meta?: { title: string; severity: Severity; description: string; fix: string };
}

const CONFIG_SECRET_KEY = /^(password|secret|api[_-]?key|private[_-]?key)$/i;
// Keys meant to be shipped to browsers: Stripe and Mapbox publishable keys
// exist to be public. Finding one in a front end's config.json discloses
// nothing.
const PUBLISHABLE_KEY = /^(pk_(live|test)_[0-9A-Za-z]{8,}|pk\.[0-9A-Za-z._-]{20,})$/;
// A Google API key (AIza…) is public by design inside a Firebase web config,
// where it only identifies the project and access is enforced by security
// rules. The same format is also used for billable keys (Gemini, unrestricted
// Maps), so it is only exempt when its object carries Firebase's own fields.
const GOOGLE_API_KEY = /^AIza[0-9A-Za-z_-]{35}$/;
const FIREBASE_CONFIG_FIELD = /^(authDomain|projectId|messagingSenderId|appId|storageBucket)$/;
// Values that stand in for a credential rather than being one: filler, empty
// markers and references to where the real value comes from.
const NOT_A_VALUE = /^(\*+|x+|-+|null|none|n\/a|undefined|true|false)$|^\$\{.*\}$|^%[^%]+%$|^<[^>]*>$|^\{\{.*\}\}$|process\.env|^env:/i;

// Whether a served config.json actually holds a credential. Only the key
// names used to be checked, so a public Firebase web config ("apiKey") or a
// password-POLICY object ("password": { "minLength": 12 }) was reported as a
// HIGH exposed secret. Now a credential-named key must carry a string that
// looks like a real value.
export function configJsonLeaksSecret(body: string): boolean {
  if (!body || looksLikeHtml(body)) return false;
  // Each credential-named string value, with whether the object holding it
  // looks like a Firebase web config.
  const found: Array<{ value: string; inFirebaseConfig: boolean }> = [];
  try {
    const walk = (node: unknown): void => {
      if (Array.isArray(node)) node.forEach(walk);
      else if (node && typeof node === "object") {
        const entries = Object.entries(node);
        const inFirebaseConfig = entries.some(([k]) => FIREBASE_CONFIG_FIELD.test(k));
        for (const [key, value] of entries) {
          if (typeof value === "string" && CONFIG_SECRET_KEY.test(key)) found.push({ value, inFirebaseConfig });
          else walk(value);
        }
      }
    };
    walk(JSON.parse(body));
  } catch {
    // Not strict JSON (comments, a trailing comma, a truncated body): read the
    // string-valued keys straight off the text.
    const inFirebaseConfig = /"(authDomain|projectId|messagingSenderId|appId)"\s*:/.test(body);
    for (const m of body.matchAll(/"([\w-]+)"\s*:\s*"((?:[^"\\]|\\.)*)"/g)) {
      if (CONFIG_SECRET_KEY.test(m[1])) found.push({ value: m[2], inFirebaseConfig });
    }
  }
  return found.some(({ value, inFirebaseConfig }) => {
    const v = value.trim();
    if (v.length < 4 || NOT_A_VALUE.test(v) || PUBLISHABLE_KEY.test(v) || isLikelyPlaceholderSecret(v)) return false;
    return !(inFirebaseConfig && GOOGLE_API_KEY.test(v));
  });
}

// Exported so the signature matchers are unit-testable without a live target.
export const SENSITIVE_PROBES: SensitiveProbe[] = [
  // --- Secret / VCS / config files (critical–high, via the default mapping) ---
  { path: "/.env", matches: (b) => !looksLikeHtml(b) && /^[A-Z][A-Z0-9_]*\s*=/m.test(b) },
  { path: "/.git/config", matches: (b) => /\[core\]/i.test(b) || /repositoryformatversion/i.test(b) },
  { path: "/.git/HEAD", matches: (b) => /^ref:\s+refs\//m.test(b.trim()) },
  { path: "/phpinfo.php", matches: (b) => /<title>phpinfo\(\)/i.test(b) || /PHP Version\s*</i.test(b) },
  { path: "/.aws/credentials", matches: (b) => !looksLikeHtml(b) && /aws_access_key_id/i.test(b) },
  { path: "/config.json", matches: configJsonLeaksSecret },

  // --- Supply-chain: dependency lockfiles ---
  // A lockfile discloses the EXACT resolved version of every direct and
  // transitive dependency, letting an attacker map the app to known CVEs offline
  // with no guesswork. Real exposure, but not a breach on its own → LOW.
  {
    path: "/package-lock.json",
    matches: (b) => !looksLikeHtml(b) && /"lockfileVersion"\s*:/.test(b),
    meta: {
      title: "Exposed npm lockfile (package-lock.json)",
      severity: "low",
      description: "The npm lockfile package-lock.json is publicly served. It discloses the exact resolved version of every direct and transitive dependency, which an attacker uses to map the application to known-vulnerable package versions (CVEs) with no guesswork.",
      fix: "Don't serve lockfiles from the web root — they belong in source control and the build environment, not the deployed public directory. Exclude package-lock.json (and yarn.lock / pnpm-lock.yaml) from the served build output.",
    },
  },
  {
    path: "/yarn.lock",
    matches: (b) => !looksLikeHtml(b) && (/^# yarn lockfile v1/m.test(b) || /^__metadata:/m.test(b)),
    meta: {
      title: "Exposed Yarn lockfile (yarn.lock)",
      severity: "low",
      description: "The Yarn lockfile yarn.lock is publicly served, disclosing the exact resolved version of every dependency — enough to map the app to known-vulnerable versions (CVEs) offline.",
      fix: "Exclude yarn.lock from the deployed public directory; keep it in source control only.",
    },
  },
  {
    path: "/pnpm-lock.yaml",
    matches: (b) => !looksLikeHtml(b) && /^lockfileVersion:/m.test(b),
    meta: {
      title: "Exposed pnpm lockfile (pnpm-lock.yaml)",
      severity: "low",
      description: "The pnpm lockfile pnpm-lock.yaml is publicly served, disclosing the exact resolved version of every dependency — enough to map the app to known-vulnerable versions (CVEs) offline.",
      fix: "Exclude pnpm-lock.yaml from the deployed public directory; keep it in source control only.",
    },
  },
  {
    path: "/composer.lock",
    matches: (b) => !looksLikeHtml(b) && /"content-hash"\s*:/.test(b),
    meta: {
      title: "Exposed Composer lockfile (composer.lock)",
      severity: "low",
      description: "The PHP Composer lockfile composer.lock is publicly served, disclosing the exact resolved version of every PHP dependency — enough to map the app to known-vulnerable versions (CVEs) offline.",
      fix: "Serve only the application's public/ directory; keep composer.lock out of the web root.",
    },
  },
  {
    path: "/Gemfile.lock",
    matches: (b) => !looksLikeHtml(b) && /^GEM$/m.test(b) && /^DEPENDENCIES$/m.test(b),
    meta: {
      title: "Exposed Ruby lockfile (Gemfile.lock)",
      severity: "low",
      description: "The Ruby Bundler lockfile Gemfile.lock is publicly served, disclosing the exact resolved version of every gem — enough to map the app to known-vulnerable versions (CVEs) offline.",
      fix: "Exclude Gemfile.lock from the public web root; keep it in source control only.",
    },
  },
  // A published .npmrc carrying an auth token is a CREDENTIAL leak, not mere
  // dependency disclosure — an npm registry token grants supply-chain WRITE
  // access. HIGH, and only fired when a token is actually present.
  {
    path: "/.npmrc",
    matches: (b) => !looksLikeHtml(b) && /_authToken\s*=/.test(b),
    meta: {
      title: "Exposed npm credentials (.npmrc auth token)",
      severity: "high",
      description: "A publicly served .npmrc contains an _authToken — a live npm registry credential. Anyone can read it and use it to publish or unpublish packages under the associated account, a direct supply-chain compromise vector.",
      fix: "Rotate the leaked token immediately (npm token revoke), remove .npmrc from anything served publicly, and supply registry auth via a CI secret / environment variable instead of a committed file.",
    },
  },
];

const COMMON_SUBDOMAINS = [
  "www", "api", "dev", "staging", "admin", "vpn", "dashboard", "status", "mail",
  "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure", "shop",
  "portal", "test", "cdn", "app", "m", "cloud", "qa", "support", "docs", "help",
  "login", "auth", "ftp", "pop", "imap",
];

export async function scanPerimeter(host: string, hostname: string, result: DiagnosticResult): Promise<void> {
  // EASM: DNS + subdomain enumeration.
  try {
    const ipRecords = await resolveIpv4(hostname);
    if (ipRecords.length > 0) {
      result.easmPerimeter.ip = ipRecords[0];
    }

    // Resolve the authoritative nameserver(s) for real, when available.
    const nsRecords = await dns.resolveNs(hostname).catch(() => [] as string[]);
    if (nsRecords && nsRecords.length > 0) {
      result.easmPerimeter.nameserver = nsRecords[0];
    }

    // Check for Wildcard DNS to prevent false positive subdomain bloating
    let wildcardIp: string | null = null;
    const randomSub = crypto.randomBytes(6).toString("hex");
    const wildcardRecords = await resolveIpv4(`${randomSub}.${hostname}`);
    if (wildcardRecords.length > 0) {
      wildcardIp = wildcardRecords[0];
    }

    const subdomainChecks = COMMON_SUBDOMAINS.map(async (sub) => {
      const subUrl = `${sub}.${hostname}`;
      const records = await resolveIpv4(subUrl);

      // A subdomain that doesn't resolve (or a resolver that can't answer) is
      // simply not live — no A record, nothing to report.
      if (records.length === 0) {
        return { domain: subUrl, status: "inactive" as const, port: "0" };
      }

      // Filter out false positives caused by Wildcard DNS records
      if (wildcardIp && records.includes(wildcardIp)) {
        return { domain: subUrl, status: "inactive" as const, port: "0" };
      }

      return {
        domain: subUrl,
        status: "live" as const,
        port: sub.includes("vpn")
          ? "1194"
          : sub.includes("mail") || sub.includes("smtp")
            ? "25"
            : "443",
        ip: records[0],
      };
    });

    const subResults = await Promise.all(subdomainChecks);
    result.easmPerimeter.subdomains = subResults;
  } catch (e) {
    console.warn("DNS resolution failed or not supported in this environment.", e);
    // Fallback
    COMMON_SUBDOMAINS.slice(0, 10).forEach((sub) => {
      result.easmPerimeter.subdomains.push({
        domain: `${sub}.${hostname}`,
        status: "inactive",
        port: "0",
      });
    });
  }

  // Sensitive Paths Probing. A path is only treated as "exposed" when the
  // response BODY actually matches the file's signature, not merely on a 200.
  // This eliminates the dominant false positive: single-page apps that serve
  // index.html (HTTP 200) for every unknown path including /.env. See
  // SENSITIVE_PROBES above (secret/VCS/config files + supply-chain lockfiles).
  for (const probe of SENSITIVE_PROBES) {
    try {
      const probeController = new AbortController();
      const probeId = setTimeout(() => probeController.abort(), 2500);
      const probeRes = await safeFetch(`${host}${probe.path}`, {
        method: "GET",
        headers: { "User-Agent": SCANNER_USER_AGENT },
        signal: probeController.signal,
      });
      const body = await probeRes.text().catch(() => "");
      clearTimeout(probeId);

      const exposed = probeRes.status === 200 && probe.matches(body);
      // Retain the body only when actually exposed (capped — these are
      // small config-shaped files, not arbitrary large responses) so
      // downstream checks (e.g. leaked-secret/credential extraction in
      // server/jwtProbe.ts, server/credentialChainProbe.ts) can inspect what
      // this probe already fetched, instead of every such check needing its
      // own separate request to the same sensitive path.
      result.probedPaths.push({
        path: probe.path,
        status: probeRes.status,
        exposed,
        ...(exposed ? { body: body.slice(0, 50_000) } : {}),
        // Attach this file's own finding wording/severity when it defines one
        // (e.g. lockfiles → LOW), so findings.ts doesn't apply the generic
        // critical/high exposed-file mapping meant for secret/VCS files.
        ...(exposed && probe.meta ? { meta: probe.meta } : {}),
      });
    } catch (err) {
      result.probedPaths.push({ path: probe.path, status: 0, exposed: false });
    }
  }
}
