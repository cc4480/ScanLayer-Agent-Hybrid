// Ownership gate for the verbatim scan cores. Fails closed: a target that is neither a lab host nor
// verified returns ok:false, and the caller must send zero packets. The pre-execute hook in plugin.mjs
// runs the same rule first; this check is the second layer, so the engine is never reached without it.
import { isLoopbackHostname, normalizeDomain, ownershipGateDisabled } from './scan-gate-helpers.mjs'

/**
 * @param {string} rawUrl
 * @param {{isVerified: (domain: string) => Promise<boolean>}} verifier
 * @returns {Promise<{ok: true, url: string, host: string, lab: boolean} | {ok: false, reason: string}>}
 */
export async function gateScanTarget(rawUrl, verifier) {
  let url
  try {
    url = new URL(/^https?:\/\//i.test(String(rawUrl ?? '')) ? String(rawUrl) : `https://${String(rawUrl ?? '')}`)
  } catch {
    return { ok: false, reason: 'not a valid URL' }
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return { ok: false, reason: 'only http and https targets' }
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  if (isLoopbackHostname(host)) return { ok: true, url: url.href, host, lab: true }
  // Operator bypass: with the ownership gate switched off, any http/https host is allowed without DNS
  // verification. Still the operator's own authorized-use responsibility; the result is marked unverified.
  if (ownershipGateDisabled()) {
    return { ok: true, url: url.href, host: normalizeDomain(host) ?? host, lab: false, unverified: true }
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':')) {
    return { ok: false, reason: `${host} is an IP target; IP targets cannot be ownership-verified. Zero packets sent.` }
  }
  const domain = normalizeDomain(host)
  if (!domain) return { ok: false, reason: 'unusable hostname' }
  let verified = false
  try {
    verified = (await verifier.isVerified(domain)) === true
  } catch {
    verified = false
  }
  if (!verified) {
    return { ok: false, reason: `${domain} is not ownership-verified (DNS TXT challenge). Zero packets sent.` }
  }
  return { ok: true, url: url.href, host: domain, lab: false }
}
