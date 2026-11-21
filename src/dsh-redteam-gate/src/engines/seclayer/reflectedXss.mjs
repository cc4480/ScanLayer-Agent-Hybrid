// Reflected XSS probe (ported from server/redTeam/reflectedXss.ts). Sends a unique <script>
// marker in the "q" parameter and reports only when the marker comes back as live HTML. Reflection
// inside JSON, an HTML comment, or a textarea/title element does not execute, so it is not reported.

import { randomBytes } from 'node:crypto'
import { buildEvidence } from './evidence.mjs'
import { createScopedFetch, normalizeTarget } from './gate.mjs'

export const name = 'reflected-xss'
export const owaspCategory = 'A03:2021-Injection'

/** True when the marker at `idx` would be parsed as an element by a browser. */
export function reflectionExecutes(contentType, body, idx) {
  if (!/text\/html/i.test(contentType ?? '')) return false
  const before = body.slice(0, idx)
  if (before.lastIndexOf('<!--') > before.lastIndexOf('-->')) return false
  const lower = before.toLowerCase()
  for (const tag of ['textarea', 'title']) {
    if (lower.lastIndexOf(`<${tag}`) > lower.lastIndexOf(`</${tag}`)) return false
  }
  return true
}

/**
 * @param {string} target http(s) root URL of a lab target
 * @param {{headers?: Record<string,string>, timeoutMs?: number, gate?: object}} [opts]
 * @param {typeof fetch} [fetchFn]
 * @returns {Promise<object|null>} finding when proven, otherwise null
 */
export async function run(target, opts = {}, fetchFn = globalThis.fetch) {
  const base = normalizeTarget(target)
  const get = createScopedFetch({ fetchFn, gate: opts.gate, headers: opts.headers, timeoutMs: opts.timeoutMs })

  const trigger = `xss_probe_${randomBytes(4).toString('hex')}`
  const attackUrl = `${base}/?q=%3Cscript%3E${trigger}%3C%2Fscript%3E`
  const res = await get(attackUrl)
  const marker = `<script>${trigger}</script>`
  const idx = res.body.indexOf(marker)
  if (idx === -1 || !reflectionExecutes(res.contentType, res.body, idx)) return null

  return {
    module: name,
    owaspCategory,
    testName: 'Active Reflected XSS Probe',
    payload: marker,
    severity: 'high',
    description: 'The unique script marker was reflected unescaped into an HTML response where a browser would execute it.',
    fix: 'Apply context-aware output encoding and a restrictive Content-Security-Policy.',
    evidence: buildEvidence({
      method: 'reflection',
      attackUrl,
      status: res.status,
      contentType: res.contentType,
      body: res.body,
      matchIndex: idx,
      quote: marker,
      why: 'The unique marker was echoed verbatim and unescaped inside the HTML body, so the browser parses it as a live script element.',
      demonstration: `Submitted ${marker} in the "q" parameter; the response contained it unescaped as HTML.`,
    }),
  }
}
