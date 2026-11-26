// Exposed JavaScript source-map probe. A shipped `.js.map` reconstructs the
// ORIGINAL, un-minified source of a bundle — comments, internal structure,
// route/file names, feature flags, and any logic the minified build obscured —
// handing a reverse engineer the real code for free. Vibe-coder builds ship them
// by accident constantly (a Vite/webpack default left on).
//
// False-positive-proof: a source map is a very specific JSON shape
// (`{"version":3,"sources":[...],"mappings":"..."}`), so an SPA that serves
// index.html (HTTP 200) for an unknown `.map` path never matches. Passive and
// same-origin only — it just GETs the target's own asset paths, like the
// sensitive-path probing in server/perimeter.ts.
import { safeFetch } from "./ssrf.js";
import { SCANNER_USER_AGENT } from "./config.js";
import type { Severity } from "../src/types.js";

// True only for a real Source Map v3 document. Cheap regex pre-check guards the
// bounded JSON.parse so a large non-JSON body isn't parsed needlessly.
export function isSourceMap(text: string): boolean {
  if (!text || text.length < 20) return false;
  if (!/"version"\s*:/.test(text) || !/"mappings"\s*:/.test(text) || !/"sources"\s*:/.test(text)) return false;
  try {
    const j = JSON.parse(text) as any;
    return !!j && typeof j === "object" && typeof j.mappings === "string" && Array.isArray(j.sources);
  } catch {
    return false;
  }
}

// Same-origin <script src> bundle URLs referenced by an HTML document.
export function extractScriptSrcs(html: string, baseUrl: string): string[] {
  let base: URL;
  try { base = new URL(baseUrl); } catch { return []; }
  const out = new Set<string>();
  const re = /<script[^>]+src\s*=\s*["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    try {
      const abs = new URL(m[1], base);
      if (abs.origin === base.origin && /\.m?js(\?|$)/i.test(abs.pathname)) out.add(abs.origin + abs.pathname);
    } catch { /* skip malformed src */ }
  }
  return [...out];
}

// Same-origin sourceMappingURL(s) declared inside a JS file, resolved against the
// JS file's URL. Inline `data:` maps are skipped — they're already in the bundle,
// not separately exposed.
export function extractSourceMappingUrls(jsText: string, jsUrl: string): string[] {
  const out = new Set<string>();
  let base: URL;
  try { base = new URL(jsUrl); } catch { return []; }
  const re = /[#@]\s*sourceMappingURL\s*=\s*(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(jsText)) !== null) {
    const ref = m[1].trim();
    if (ref.startsWith("data:")) continue;
    try {
      const abs = new URL(ref, base);
      if (abs.origin === base.origin) out.add(abs.origin + abs.pathname);
    } catch { /* skip malformed ref */ }
  }
  return [...out];
}

async function timedGet(url: string, headers: Record<string, string>): Promise<{ status: number; text: string } | null> {
  const ctl = new AbortController();
  const id = setTimeout(() => ctl.abort(), 4000);
  try {
    const res = await safeFetch(url, { headers, signal: ctl.signal });
    return { status: res.status, text: await res.text().catch(() => "") };
  } catch {
    return null;
  } finally {
    clearTimeout(id);
  }
}

export interface SourceCapture { url: string; text: string }
export interface ExposedPathEntry {
  path: string;
  status: number;
  exposed: boolean;
  meta: { title: string; severity: Severity; description: string; fix: string };
  // Whether the map embeds the original source text (sourcesContent).
  embedsSource?: boolean;
}

// True when the map embeds the original source text. Without sourcesContent a
// map holds the file names and the identifier mapping but none of the code, so
// saying it "hands a reverse engineer your real code" overstated it. Same
// distinction secscan draws (sourceMaps.ts).
export function embedsSourceText(text: string): boolean {
  try {
    const content = (JSON.parse(text) as { sourcesContent?: unknown }).sourcesContent;
    return Array.isArray(content) && content.some((c) => typeof c === "string" && c.trim().length > 0);
  } catch {
    return false;
  }
}

const RECONSTRUCTS =
  "reconstruct the ORIGINAL, un-minified source — including comments, internal structure, file/route names, and logic the minified bundle obscured — which hands a reverse engineer your real code with no effort";
const NAMES_ONLY =
  "list the original source file names and the project's layout but do not embed their contents (no sourcesContent), so they disclose structure rather than the code itself";

function sourceMapDescription(paths: string[], embedding: number): string {
  if (paths.length === 1) {
    return embedding
      ? `A JavaScript source map (${paths[0]}) is publicly served. It embeds the original source text, so its contents ${RECONSTRUCTS}.`
      : `A JavaScript source map (${paths[0]}) is publicly served. Its entries ${NAMES_ONLY}.`;
  }
  const shown = paths.slice(0, 10);
  const more = paths.length > shown.length ? `, and ${paths.length - shown.length} more` : "";
  const served = `${paths.length} JavaScript source maps are publicly served (${shown.join(", ")}${more}).`;
  if (embedding === paths.length) return `${served} They embed the original source text, so together they ${RECONSTRUCTS}.`;
  if (embedding === 0) return `${served} They ${NAMES_ONLY}.`;
  return `${served} ${embedding} of them embed the original source text and so ${RECONSTRUCTS}; the others only list file names.`;
}

// Given the HTML/JS the scan already fetched, derive candidate `.map` URLs (from
// <script src>.map and from sourceMappingURL comments), probe each, and return a
// probedPaths-shaped entry (with LOW `meta`) for every one that is a real source
// map. Bounded to `max` fetches. Empty when nothing is exposed.
export async function probeExposedSourceMaps(
  captures: SourceCapture[],
  baseUrl: string,
  headers: Record<string, string>,
  max = 6,
): Promise<ExposedPathEntry[]> {
  const candidates = new Set<string>();
  for (const c of captures) {
    let pathname = c.url;
    try { pathname = new URL(c.url).pathname; } catch { /* keep as-is */ }
    if (/\.m?js(\?|$)/i.test(pathname)) {
      // A captured JS bundle: trust its own sourceMappingURL, and also try the
      // conventional <bundle>.js.map sibling.
      for (const u of extractSourceMappingUrls(c.text, c.url)) candidates.add(u);
      try { const p = new URL(c.url); candidates.add(p.origin + p.pathname + ".map"); } catch { /* skip */ }
    } else {
      // An HTML document: derive its script bundles, then their .map siblings.
      for (const src of extractScriptSrcs(c.text, c.url)) candidates.add(src + ".map");
    }
  }

  // Every candidate is same-origin with the scanned app (extractScriptSrcs /
  // extractSourceMappingUrls both filter to it), so forwarding the full header
  // set — including any session Cookie the crawl carries — is safe here, unlike
  // the cross-origin Firebase/bucket probes. A .map is usually a public static
  // asset, but this reaches the rare case where it isn't served without a session.
  const out: ExposedPathEntry[] = [];
  for (const mapUrl of [...candidates].slice(0, max)) {
    const r = await timedGet(mapUrl, { "User-Agent": SCANNER_USER_AGENT, ...headers });
    if (!r || r.status !== 200 || !isSourceMap(r.text)) continue;
    let path = mapUrl;
    try { path = new URL(mapUrl).pathname; } catch { /* keep full */ }
    const embedsSource = embedsSourceText(r.text);
    out.push({
      path,
      status: 200,
      exposed: true,
      embedsSource,
      meta: {
        title: `Exposed JavaScript source map (${path})`,
        severity: "low",
        description: sourceMapDescription([path], embedsSource ? 1 : 0),
        fix: `Stop shipping .map files to production, or restrict access to them. In Vite set build.sourcemap to false (or 'hidden'); in webpack pick a production devtool that doesn't emit public maps; or block *.map at the CDN / web server.`,
      },
    });
  }
  return consolidateSourceMaps(out);
}

// Several exposed maps are ONE decision (the build ships source maps), not N
// separate weaknesses. Reported one-per-file, a site shipping maps for five
// chunks lost 25 points for it (developer.mozilla.org in the 2026-09-25 live
// run). Collapse them into a single finding that still lists every file.
export function consolidateSourceMaps(entries: ExposedPathEntry[]): ExposedPathEntry[] {
  if (entries.length <= 1) return entries;
  const paths = entries.map((e) => e.path);
  // An entry built without the flag keeps the original wording.
  const embedding = entries.filter((e) => e.embedsSource !== false).length;
  return [{
    path: paths[0],
    status: 200,
    exposed: true,
    embedsSource: embedding > 0,
    meta: {
      title: `Exposed JavaScript source maps (${paths.length} files)`,
      severity: "low",
      description: sourceMapDescription(paths, embedding),
      fix: entries[0].meta.fix,
    },
  }];
}
