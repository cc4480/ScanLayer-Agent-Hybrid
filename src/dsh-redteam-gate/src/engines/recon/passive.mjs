// Passive recon: public DNS records and certificate-transparency (CT) names for a domain.
// Nothing here connects to the target's own hosts. Queries go to public resolvers and to crt.sh.
// Network access is injected (resolver, fetchFn) so tests run without a network.

import * as dnsPromises from 'node:dns/promises';
import { normalizeDomain } from './domain.mjs';

export const CT_ENDPOINT = 'https://crt.sh/';
const DEFAULT_TIMEOUT_MS = 10000;
const RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'];
const METHOD_FOR = {
  A: 'resolve4',
  AAAA: 'resolve6',
  MX: 'resolveMx',
  TXT: 'resolveTxt',
  NS: 'resolveNs',
  CNAME: 'resolveCname',
};
// "No records" answers are normal for passive lookups, not errors.
const EMPTY_CODES = new Set(['ENODATA', 'ENOTFOUND']);

function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function errorText(err) {
  return err?.code ? `${err.code}: ${err.message}` : String(err?.message ?? err);
}

/** Normalize one resolver answer into a JSON-safe value for its record type. */
function shapeAnswer(type, answer) {
  const host = (v) => String(v).toLowerCase().replace(/\.$/, '');
  if (type === 'MX') return answer.map((m) => ({ exchange: host(m.exchange), priority: Number(m.priority) }));
  if (type === 'TXT') return answer.map((chunks) => (Array.isArray(chunks) ? chunks.join('') : String(chunks)));
  if (type === 'NS' || type === 'CNAME') return [].concat(answer).map(host);
  return [].concat(answer).map(String);
}

/**
 * Public DNS records for a domain, via an injected resolver (default: node:dns/promises).
 * Each record type is queried independently; a failure in one does not hide the others.
 * @param {string} domain
 * @param {{[method: string]: Function}} [resolver] object exposing resolve4, resolve6, resolveMx, resolveTxt, resolveNs, resolveCname
 * @param {{timeoutMs?: number}} [opts]
 * @returns {Promise<{domain: string, records: Record<string, unknown[]>, errors: Record<string, string>}>}
 */
export async function dnsRecords(domain, resolver = dnsPromises, opts = {}) {
  const d = normalizeDomain(domain);
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const records = {};
  const errors = {};

  await Promise.all(RECORD_TYPES.map(async (type) => {
    records[type] = [];
    const method = METHOD_FOR[type];
    if (typeof resolver?.[method] !== 'function') {
      errors[type] = `resolver has no ${method}`;
      return;
    }
    try {
      const answer = await withTimeout(Promise.resolve(resolver[method](d)), timeoutMs, `${type} lookup`);
      records[type] = shapeAnswer(type, answer ?? []);
    } catch (err) {
      if (!EMPTY_CODES.has(err?.code)) errors[type] = errorText(err);
    }
  }));

  // Keep a stable key order in the output.
  const orderedRecords = Object.fromEntries(RECORD_TYPES.map((t) => [t, records[t]]));
  const orderedErrors = Object.fromEntries(Object.entries(errors).sort(([a], [b]) => a.localeCompare(b)));
  return { domain: d, records: orderedRecords, errors: orderedErrors };
}

/** Hostnames inside a CT name_value field (may hold several lines, may include wildcards). */
function ctNamesFrom(entries, domain) {
  const names = new Set();
  for (const entry of entries) {
    const raw = `${entry?.name_value ?? ''}\n${entry?.common_name ?? ''}`;
    for (const piece of raw.split(/[\n\r]+/)) {
      let name = piece.trim().toLowerCase();
      if (name.startsWith('*.')) name = name.slice(2);
      if (!name || (name !== domain && !name.endsWith(`.${domain}`))) continue;
      try {
        names.add(normalizeDomain(name));
      } catch {
        // Not a clean hostname (for example, an email-style SAN); skip it.
      }
    }
  }
  return [...names].sort();
}

/**
 * Certificate-transparency names for a domain, from crt.sh JSON output.
 * Returns an error string instead of throwing so a merge can still use DNS results.
 * @param {string} domain
 * @param {(url: string, init?: object) => Promise<{ok: boolean, status?: number, json: () => Promise<unknown>}>} [fetchFn]
 * @param {{timeoutMs?: number}} [opts]
 * @returns {Promise<{domain: string, source: 'crt.sh', names: string[], error?: string}>}
 */
export async function certTransparency(domain, fetchFn = globalThis.fetch, opts = {}) {
  const d = normalizeDomain(domain);
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const url = `${CT_ENDPOINT}?q=${encodeURIComponent(`%.${d}`)}&output=json`;
  try {
    if (typeof fetchFn !== 'function') throw new Error('no fetch function available');
    const signal = typeof AbortSignal?.timeout === 'function' ? AbortSignal.timeout(timeoutMs) : undefined;
    const res = await withTimeout(
      Promise.resolve(fetchFn(url, { headers: { accept: 'application/json', 'user-agent': 'dsh-redteam-recon/0.1' }, signal })),
      timeoutMs,
      'crt.sh query',
    );
    if (!res?.ok) throw new Error(`crt.sh responded with status ${res?.status ?? 'unknown'}`);
    const body = await res.json();
    if (!Array.isArray(body)) throw new Error('crt.sh returned a non-array body');
    return { domain: d, source: 'crt.sh', names: ctNamesFrom(body, d) };
  } catch (err) {
    return { domain: d, source: 'crt.sh', names: [], error: errorText(err) };
  }
}

/** In-zone hostnames referenced by MX, NS and CNAME answers (these are real names in the zone). */
function zoneNamesFromDns(dns, domain) {
  const values = [
    ...dns.records.NS,
    ...dns.records.CNAME,
    ...dns.records.MX.map((m) => m.exchange),
  ];
  return values.filter((v) => v === domain || v.endsWith(`.${domain}`));
}

/**
 * Merge passive subdomain sources: CT names plus in-zone names that DNS records point at.
 * The apex itself is excluded. Each name lists which sources saw it.
 * @param {string} domain
 * @param {{resolver?: object, fetchFn?: Function, timeoutMs?: number}} [sources]
 * @returns {Promise<{domain: string, subdomains: {name: string, sources: string[]}[], dns: object, ct: object}>}
 */
export async function subdomainsFromPublicRecords(domain, sources = {}) {
  const d = normalizeDomain(domain);
  const timeoutMs = sources.timeoutMs;
  const [dns, ct] = await Promise.all([
    dnsRecords(d, sources.resolver ?? dnsPromises, { timeoutMs }),
    certTransparency(d, sources.fetchFn ?? globalThis.fetch, { timeoutMs }),
  ]);

  const seen = new Map();
  const add = (name, source) => {
    if (name === d || !name.endsWith(`.${d}`)) return;
    if (!seen.has(name)) seen.set(name, new Set());
    seen.get(name).add(source);
  };
  for (const name of ct.names) add(name, 'crt.sh');
  for (const name of zoneNamesFromDns(dns, d)) add(name, 'dns');

  const subdomains = [...seen.keys()].sort().map((name) => ({ name, sources: [...seen.get(name)].sort() }));
  return { domain: d, subdomains, dns, ct };
}
