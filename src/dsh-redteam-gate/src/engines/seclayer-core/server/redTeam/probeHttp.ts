// Shared fetch helper for the red-team probes. Wraps safeFetch (the SSRF-guarded
// fetch) in the AbortController + setTimeout + clearTimeout pattern every probe
// otherwise repeated verbatim. The timer guards the request only — the body read
// happens after the timer is cleared, matching the original per-probe behavior.
import { safeFetch } from "../ssrf.js";

// Each active probe caps a single request at 4s so one slow endpoint can't stall
// the whole scan pipeline.
export const PROBE_TIMEOUT_MS = 4000;

export async function probeFetch(
  url: string,
  headers: Record<string, string>,
  timeoutMs = PROBE_TIMEOUT_MS,
): Promise<Response> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    return await safeFetch(url, { headers, signal: ctl.signal });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Attach a query string to the target's base URL without duplicating the slash.
 *
 * Every root probe used to build `${ctx.url}/?param=`, and the scan normalises a
 * bare host to a URL WITH a trailing slash — so the request went to "//?param="
 * instead of "/?param=". That is not a cosmetic difference: the path becomes
 * "//", which many servers and proxies normalise, redirect, or route differently,
 * and several URL parsers read "//?x" as a protocol-relative authority and drop
 * the query entirely. A probe pointed at the wrong path reports "no signal" about
 * a target it never actually tested.
 *
 * `base` may carry its own query or path; the query is appended with "&" when
 * one is already present.
 */
export function probeUrl(base: string, query: string): string {
  const q = query.replace(/^[?&]+/, "");
  const u = new URL(base);
  // A bare origin has pathname "/" already, but a stripped trailing slash leaves
  // "" — force the root path back so the scope gate never sees "host?query" as a
  // hostname.
  if (!u.pathname) u.pathname = "/";
  const sep = u.search ? "&" : "?";
  return `${u.origin}${u.pathname}${u.search}${sep}${q}${u.hash}`;
}

/** The target's own root URL, with exactly one trailing slash. */
export function probeRoot(base: string): string {
  return `${base.replace(/\/+$/, "")}/`;
}
