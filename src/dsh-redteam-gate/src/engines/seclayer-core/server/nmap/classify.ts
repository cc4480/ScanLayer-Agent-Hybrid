// Classifies a single NSE `--script vuln` result's raw output text. nmap
// includes a <script> element for every script that ran against a port/host
// regardless of what it found — a script that explicitly reports "not
// vulnerable", or one that failed to execute or timed out, produces output
// exactly like a real hit structurally. Treating every element as a finding
// (the previous behavior) mislabeled negative results and tooling failures as
// DETECTED security findings — the exact class of false positive this
// product exists not to produce. This reads the script's own conventional
// output text (nmap's XML has no separate structured verdict field to rely
// on instead — see parseXml.ts) to sort each result into what actually
// happened.
import type { NmapScriptOutcome } from "../../src/types.js";

// nmap's own wrapper when an NSE script raises a Lua error, verbatim and
// script-independent — and the two explicit no-response/timeout phrasings
// used by scripts like ssl-ccs-injection when they can't get a probe answer.
const ERROR_PATTERNS = [/^ERROR: Script execution failed/i, /^No reply from server/i, /\(TIMEOUT\)/i];

// vulns.lua's own "couldn't determine" state, used by scripts that share that
// library — a script ran to completion but couldn't establish either verdict.
const INCONCLUSIVE_PATTERNS = [/State:\s*UNKNOWN/i];

// Explicit negative determinations. Checked before the generic "VULNERABLE"
// substring test below so a "State: NOT VULNERABLE" line (vulns.lua) is never
// mistaken for a hit just because it contains the word "VULNERABLE".
const NEGATIVE_PATTERNS = [
  /couldn'?t find any/i,
  /\bnot vulnerable\b/i,
  /no vulnerabilities found/i,
  /appears to be (not vulnerable|patched)/i,
  /^likely not vulnerable/i,
];

export function classifyNmapScriptOutput(output: string): NmapScriptOutcome {
  const text = (output || "").trim();
  if (!text) return "negative";
  if (ERROR_PATTERNS.some((re) => re.test(text))) return "error";
  if (INCONCLUSIVE_PATTERNS.some((re) => re.test(text))) return "inconclusive";
  if (NEGATIVE_PATTERNS.some((re) => re.test(text))) return "negative";
  return "finding";
}

// Scripts -sV runs alongside --script vuln that only REPORT a fact. Their
// output is never a vulnerability claim, so the generic "anything that isn't
// explicitly negative is a finding" rule would mislabel e.g. the server banner
// "nginx/1.25.5" as a DETECTED hit.
const INFORMATIONAL_SCRIPTS = new Set([
  "http-server-header", "http-title", "http-headers", "http-generator",
  "banner", "fingerprint-strings", "ssl-cert", "ssl-date", "ssh-hostkey",
  "tls-alpn", "tls-nextprotoneg", "http-robots.txt", "http-favicon",
  "http-methods", "http-date", "rdp-ntlm-info", "smb-os-discovery",
]);

// CVE scripts that are specific to ONE product, keyed to what nmap's own
// service detection must report for the verdict to apply. Several of these
// test a behaviour, not the product: http-vuln-cve2011-3192 only checks that
// overlapping byte ranges get a 206, which nginx answers safely — so it
// reports the Apache DoS as VULNERABLE against a patched nginx. When -sV
// identified a DIFFERENT product, the hit is downgraded to inconclusive.
const PRODUCT_SPECIFIC_SCRIPTS: Record<string, RegExp> = {
  "http-vuln-cve2011-3192": /apache/i,
  "http-vuln-cve2011-3368": /apache/i,
  "http-vuln-cve2017-5638": /apache|tomcat|struts|jetty/i,
  "http-vuln-cve2015-1635": /iis|microsoft/i,
  "http-iis-webdav-vuln": /iis|microsoft/i,
  "http-iis-short-name-brute": /iis|microsoft/i,
  "http-vuln-cve2010-2861": /coldfusion|jrun/i,
  "http-vuln-cve2013-0156": /rails|ruby|passenger|puma|webrick|thin/i,
  "http-vuln-cve2012-1823": /php|apache/i,
};

export interface ScriptContext {
  scriptId: string;
  // The -sV product string for the port the script ran on, when known.
  product?: string;
}

// Full classification: the output text, then what the script IS and what
// service it ran against.
export function classifyNmapScript(output: string, ctx: ScriptContext): NmapScriptOutcome {
  const base = classifyNmapScriptOutput(output);
  if (base !== "finding") return base;
  if (INFORMATIONAL_SCRIPTS.has(ctx.scriptId)) return "informational";
  const needs = PRODUCT_SPECIFIC_SCRIPTS[ctx.scriptId];
  if (needs && ctx.product && !needs.test(ctx.product)) return "inconclusive";
  return "finding";
}
