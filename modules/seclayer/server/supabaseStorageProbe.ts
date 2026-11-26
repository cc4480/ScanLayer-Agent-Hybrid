// Supabase Storage: can the project's public (anon) key list the files in a bucket?
//
// The bucket list endpoint (`GET /storage/v1/bucket`) answers the anon key with an empty list unless a policy allows it,
// so a public bucket whose FILES can be listed (`POST /storage/v1/object/list/<bucket>`, allowed by a SELECT policy on
// storage.objects, the common "Public Access" policy) is found only by naming the bucket, and the app's own code is
// where its name is written: `supabase.storage.from("avatars")`. Like every cross-origin probe here the project is one
// the scanned app's OWN content named (the URL and key pair that credentialChainProbe extracts), never a guess, and the
// bucket names come from that same code. Read-only: one GET for the bucket list and one POST per bucket that asks for
// five file names (a list request, no write); reuses safeFetch's SSRF gate unchanged.
import { safeFetch } from "./ssrf.js";
import { SCANNER_USER_AGENT } from "./config.js";
import { renderRawRequest, windowAround } from "./evidence.js";
import type { UrlKeyPair } from "./credentialChainProbe.js";
import type { ExploitEvidence } from "../src/types.js";

const MAX_BUCKETS = 5;

async function timed(url: string, init: { method?: string; headers: Record<string, string>; body?: string }): Promise<{ status: number; statusText: string; text: string } | null> {
  const ctl = new AbortController();
  const id = setTimeout(() => ctl.abort(), 5000);
  try {
    const res = await safeFetch(url, { ...init, signal: ctl.signal });
    return { status: res.status, statusText: res.statusText, text: await res.text().catch(() => "") };
  } catch {
    return null;
  } finally {
    clearTimeout(id);
  }
}

function jsonArray(text: string): unknown[] | null {
  try {
    const v: unknown = JSON.parse(text);
    return Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

/**
 * Probes the Supabase projects among `pairs` for a bucket whose files the anon key can list. `bucketHints` are the bucket
 * names the app's code opens. Returns an apiSec-shaped finding for the first listable bucket, else null.
 */
export async function probeSupabaseStorage(pairs: UrlKeyPair[], bucketHints: string[] = []): Promise<any | null> {
  for (const pair of pairs.filter((p) => p.prefix === "SUPABASE").slice(0, 2)) {
    const headers = { apikey: pair.key, Authorization: `Bearer ${pair.key}`, "User-Agent": SCANNER_USER_AGENT };

    const listed = await timed(`${pair.url}/storage/v1/bucket`, { headers });
    const fromList = listed && listed.status === 200
      ? (jsonArray(listed.text) ?? []).map((b) => (b && typeof b === "object" ? (b as { name?: unknown }).name : undefined)).filter((n): n is string => typeof n === "string")
      : [];
    const buckets = [...new Set([...bucketHints, ...fromList])].slice(0, MAX_BUCKETS);

    for (const bucket of buckets) {
      const url = `${pair.url}/storage/v1/object/list/${encodeURIComponent(bucket)}`;
      const body = JSON.stringify({ prefix: "", limit: 5, offset: 0 });
      const r = await timed(url, { method: "POST", headers: { ...headers, "Content-Type": "application/json" }, body });
      if (!r || r.status !== 200) continue;
      const objects = jsonArray(r.text);
      const names = (objects ?? []).map((o) => (o && typeof o === "object" ? (o as { name?: unknown }).name : undefined)).filter((n): n is string => typeof n === "string");
      if (names.length === 0) continue; // 200 + empty is what a locked bucket answers too

      const sample = names[0]!;
      const proof = r.text.includes(sample) ? sample : r.text.slice(0, 200);
      const response = `HTTP/1.1 ${r.status} ${r.statusText}\n\n` + windowAround(r.text, Math.max(0, r.text.indexOf(proof)), proof.length, 1200);
      const evidence: ExploitEvidence = {
        method: "oracle",
        attack: { request: renderRawRequest("POST", url, { apikey: `${pair.key.slice(0, 12)}…`, "Content-Type": "application/json" }, body), response },
        signal: {
          quote: proof,
          offsetInResponse: Math.max(0, response.indexOf(proof)),
          why: `A list request for the "${bucket}" bucket made with only the project's public key returned file names (HTTP 200); a bucket without a public SELECT policy answers with an empty list or an error.`,
        },
        demonstration: `We called ${pair.url}'s Storage API with the public key from this page's own JavaScript and the bucket "${bucket}" listed ${names.length} file(s), e.g. "${sample}".`,
        reproduction: `curl -s -X POST "${url}" -H "apikey: ${pair.key}" -H "Content-Type: application/json" -d '${body}'`,
        capturedAt: new Date().toISOString(),
      };
      return {
        testName: `Supabase Storage Files Listable Without Authentication (${bucket})`,
        payload: `POST ${url} with the client-exposed ${pair.prefix} key`,
        severity: "medium",
        description: `The public key in this application's own JavaScript is enough to list the files in the Supabase Storage bucket "${bucket}" at ${pair.url}: anyone can see what was uploaded (e.g. "${sample}") and fetch it by name. A bucket meant to serve public images can still be listed like this, so check that nothing private (invoices, ID documents, exports) is in it.`,
        fix: "In the Supabase dashboard: Storage → Policies. Remove any policy that lets the anon role SELECT on storage.objects for this bucket, and give authenticated users access to only their own folder. A public bucket serves files by URL without needing a list policy.",
        evidence,
      };
    }
  }
  return null;
}
