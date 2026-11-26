// The page's own JavaScript, as text, for the checks that read served content.
//
// The crawler follows <a href> links, never <script src>, so on a single-page app (an empty shell and one bundle) the
// code that holds the project URL, the keys and the bucket and table names was never read. This fetches the scripts the
// root document loads from its OWN origin (same scheme, host and port), bounded in number and size. Read-only GETs through safeFetch, so the SSRF gate applies to every request.
import { safeFetch } from "./ssrf.js";
import { SCANNER_USER_AGENT } from "./config.js";

export const MAX_SCRIPTS = 12;
/** A built bundle is 0.5 to 3 MB and its own code comes last, so a short cap would cut off exactly that part. */
export const MAX_SCRIPT_CHARS = 5 * 1024 * 1024;

export interface ScriptCapture { url: string; text: string }

/** Same-origin <script src> URLs of a document, in order, without duplicates. */
export function scriptUrls(html: string, baseUrl: string): string[] {
  const out: string[] = [];
  for (const m of html.matchAll(/<script\b[^>]*?\bsrc\s*=\s*["']([^"']+)["']/gi)) {
    try {
      const u = new URL(m[1]!.trim(), baseUrl);
      if (!/^https?:$/.test(u.protocol) || u.origin !== new URL(baseUrl).origin) continue;
      u.hash = "";
      if (!out.includes(u.href)) out.push(u.href);
    } catch { /* not a URL */ }
    if (out.length >= MAX_SCRIPTS) break;
  }
  // Chunks the page only preloads: code-splitting builds such as TanStack Start list them as <link rel="modulepreload">.
  for (const tag of html.match(/<link\b[^>]*>/gi) ?? []) {
    if (out.length >= MAX_SCRIPTS) break;
    if (!/\brel\s*=\s*["']?modulepreload\b/i.test(tag)) continue;
    const href = /\bhref\s*=\s*["']([^"']+)["']/i.exec(tag)?.[1];
    if (!href) continue;
    try {
      const u = new URL(href, baseUrl);
      if (!/^https?:$/.test(u.protocol) || u.origin !== new URL(baseUrl).origin) continue;
      u.hash = "";
      if (!out.includes(u.href)) out.push(u.href);
    } catch { /* not a URL */ }
  }
  return out;
}

/** Most extra chunks read per scan, on top of the scripts the page itself lists. */
export const MAX_LAZY_CHUNKS = 12;

/**
 * Module chunks the given scripts load on demand: `import("./Admin-3fa9.js")` and the file list a Vite build writes into
 * its preload helper (`__vite__mapDeps`). A code-split route (React.lazy) lives in a chunk the HTML never names, and what
 * a lazy admin screen holds (a service_role key, an AI key) is what the entry script does not. Same-origin .js/.mjs only,
 * none already read. webpack's chunk maps are not read.
 */
export function lazyChunkUrls(scripts: ScriptCapture[], pageUrl: string): string[] {
  const seen = new Set(scripts.map((s) => s.url));
  const out: string[] = [];
  const root = new URL("/", pageUrl);
  const add = (spec: string, from: string) => {
    if (out.length >= MAX_LAZY_CHUNKS || !/\.m?js(?:\?[^"'`\s]*)?$/i.test(spec)) return;
    try {
      const u = new URL(spec, from);
      u.hash = "";
      if (!/^https?:$/.test(u.protocol) || u.origin !== root.origin || seen.has(u.href)) return;
      seen.add(u.href);
      out.push(u.href);
    } catch { /* not a URL */ }
  };
  for (const { url, text } of scripts) {
    for (const m of text.matchAll(/\bimport\(\s*["'`]([^"'`\s]+)["'`]\s*\)/g)) add(m[1]!, url);
    // Vite writes the chunks a dynamic import needs as site-relative paths: m.f||(m.f=["assets/Admin-3fa9.js","assets/x.css"])
    const list = /\.f\s*\|\|\s*\(\s*[\w$.]+\.f\s*=\s*(\[[^\]]*\])/.exec(text)?.[1];
    if (list) {
      try { for (const p of JSON.parse(list) as unknown[]) if (typeof p === "string") add(p, root.href); } catch { /* not JSON */ }
    }
  }
  return out;
}

export async function fetchFirstPartyScripts(html: string, baseUrl: string, headers: Record<string, string> = {}): Promise<ScriptCapture[]> {
  const download = async (url: string): Promise<ScriptCapture | null> => {
    const ctl = new AbortController();
    const id = setTimeout(() => ctl.abort(), 10_000);
    try {
      const res = await safeFetch(url, { headers: { ...headers, "User-Agent": headers["User-Agent"] ?? SCANNER_USER_AGENT }, signal: ctl.signal });
      if (res.status < 200 || res.status >= 300) return null;
      const text = (await res.text().catch(() => "")).slice(0, MAX_SCRIPT_CHARS);
      return text ? { url, text } : null;
    } catch {
      return null;
    } finally {
      clearTimeout(id);
    }
  };
  const first = (await Promise.all(scriptUrls(html, baseUrl).map(download))).filter((g): g is ScriptCapture => g !== null);
  // Then the chunks those scripts load on demand (code-split routes).
  const lazy = (await Promise.all(lazyChunkUrls(first, baseUrl).map(download))).filter((g): g is ScriptCapture => g !== null);
  return [...first, ...lazy];
}
