// Strict domain validation for passive recon. Refuses anything that is not a bare DNS name:
// IP addresses, URLs, paths, ports, userinfo, wildcards, whitespace, trailing dots, single labels.
// Input is lowercased; the normalized form is what gets returned and sent to resolvers / CT.

const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const TLD_RE = /^(?:[a-z]{2,24}|xn--[a-z0-9-]{1,59})$/;
const FORBIDDEN_CHARS_RE = /[\s/\\:@?#*%[\]<>"'`;|&$()]/;
const IPV4_LIKE_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

/**
 * Return the normalized domain, or throw a TypeError describing why it was refused.
 * @param {unknown} input
 * @returns {string} lowercase domain with no trailing dot
 */
export function normalizeDomain(input) {
  if (typeof input !== 'string') throw new TypeError('domain must be a string');
  if (input.length === 0) throw new TypeError('domain is empty');
  if (input.length > 253) throw new TypeError('domain exceeds 253 characters');

  const d = input.toLowerCase();
  if (IPV4_LIKE_RE.test(d)) throw new TypeError(`"${input}" is an IP address, not a domain`);
  if (d.includes(':') || d.startsWith('[')) throw new TypeError('ports, IPv6 literals and URLs are not domains');
  if (FORBIDDEN_CHARS_RE.test(d)) {
    throw new TypeError('domain contains a path, port, userinfo, wildcard, whitespace or other forbidden character');
  }
  if (d.endsWith('.')) throw new TypeError('trailing dot is not accepted');

  const labels = d.split('.');
  if (labels.length < 2) throw new TypeError('domain needs at least two labels (single-label names are refused)');
  for (const label of labels) {
    if (!LABEL_RE.test(label)) throw new TypeError(`invalid label "${label}"`);
  }
  if (!TLD_RE.test(labels[labels.length - 1])) throw new TypeError('invalid top-level domain');
  return d;
}

/** Non-throwing form: { ok: true, domain } or { ok: false, reason }. */
export function checkDomain(input) {
  try {
    return { ok: true, domain: normalizeDomain(input) };
  } catch (err) {
    return { ok: false, reason: err.message };
  }
}
