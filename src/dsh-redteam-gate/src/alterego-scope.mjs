// Scope rules for the AlterEgo tools registered in the app.
//
// scope.mjs (decideScope) only knows the scanner binary names and the shell tool names. The AlterEgo
// tools have their own names (shell_exec, web_fetch, cdp_navigate, ...), so decideScope would let
// every one of them through. This module checks them before they run, with the same verifier and the
// same lab-host exemption as the scanners.
//
// Registered names carry the prefix AE_PREFIX ("ae_"). Rules are keyed by the catalog name.
import { decideScope, ACTIVE_TOOLS, LAB_HOSTS, extractHosts } from './scope.mjs'

export const AE_PREFIX = 'ae_'

/** Shell-like tools: the command text is checked as a shell line, plus every URL and IP literal in it. */
export const SHELL_LIKE = new Set(['shell_exec', 'shell_pwsh', 'exec_background', 'exec'])

/** Tools that reach a host: browser and CDP navigation, fetches, DNS and TCP checks, and the browser dispatchers. */
export const NETWORK = new Set([
  'web_fetch', 'web_search', 'http_headers', 'dns_query', 'tls_info', 'tcp_check',
  'browser', 'browser_navigate', 'browser_snapshot', 'browser_click', 'browser_fill', 'browser_eval',
  'cdp', 'cdp_launch', 'cdp_connect', 'cdp_targets', 'cdp_navigate', 'cdp_snapshot',
  'cdp_click', 'cdp_type', 'cdp_evaluate', 'cdp_readback', 'cdp_close',
])

/** Batch runs several tool calls at once, so its nested calls are checked as a whole. */
export const BATCH = new Set(['batch'])

// Argument keys that name a target. The value is searched at any depth, so nested calls are covered.
const TARGET_KEYS = new Set(['url', 'urls', 'host', 'hosts', 'domain', 'domains', 'target', 'targets',
  'start_url', 'site', 'address', 'ip', 'ips'])

const URL_HOST_RE = /\bhttps?:\/\/(\[[^\]]+\]|[^\s/'"`;|&)<>?#]+)/gi
const IPV4_RE = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g

/** Strip AE_PREFIX from a registered tool name. Other names are returned unchanged. */
export function catalogName(toolName) {
  return typeof toolName === 'string' && toolName.startsWith(AE_PREFIX) ? toolName.slice(AE_PREFIX.length) : toolName
}

function collectStrings(value, out = []) {
  if (typeof value === 'string') out.push(value)
  else if (Array.isArray(value)) value.forEach((v) => collectStrings(v, out))
  else if (value && typeof value === 'object') Object.values(value).forEach((v) => collectStrings(v, out))
  return out
}

/** Strings found under a target-named key, at any depth. */
function targetStrings(value, out = []) {
  if (Array.isArray(value)) value.forEach((v) => targetStrings(v, out))
  else if (value && typeof value === 'object') {
    for (const [key, v] of Object.entries(value)) {
      if (TARGET_KEYS.has(key.toLowerCase())) collectStrings(v, out)
      targetStrings(v, out)
    }
  }
  return out
}

function normalizeUrlHost(raw) {
  let host = String(raw)
  host = host.replace(/^.*@/, '') // userinfo
  if (host.startsWith('[')) return host.slice(1, host.indexOf(']')).toLowerCase()
  return host.replace(/:\d+$/, '').replace(/\.+$/, '').toLowerCase()
}

/** Hosts of every http(s) URL in any string. Bare domain names are not guessed from free text. */
export function urlHosts(strings) {
  const found = new Set()
  for (const s of strings) for (const m of s.matchAll(URL_HOST_RE)) found.add(normalizeUrlHost(m[1]))
  return [...found].filter(Boolean)
}

function looksLikeIp(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':')
}

const deny = (reason) => ({ kind: 'deny', reason })
const ALLOW = { kind: 'allow' }

/**
 * Check every host a call names against the verified scope.
 * `activeWordsNeedTarget`: a scanner name with no target anywhere in the call is refused (batch).
 */
async function hostsDecision(args, verifier, { activeWordsNeedTarget }) {
  const everything = collectStrings(args)
  const hosts = new Set([
    ...targetStrings(args).flatMap((s) => extractHosts(s)),
    ...urlHosts(everything),
  ])
  if (activeWordsNeedTarget && hosts.size === 0) {
    const words = everything.join(' ').toLowerCase().split(/[^a-z0-9_-]+/)
    if (words.some((w) => ACTIVE_TOOLS.has(w))) return deny('scanner named with no target; scope cannot be verified')
  }
  for (const host of hosts) {
    if (LAB_HOSTS.has(host)) continue
    if (looksLikeIp(host)) return deny(`${host} is not a lab host and IP targets cannot be ownership-verified`)
    let verified = false
    try {
      verified = (await verifier.isVerified(host)) === true
    } catch {
      verified = false
    }
    if (!verified) return deny(`${host} is not a lab host and is not verified in SecScan; zero packets sent`)
  }
  return ALLOW
}

/** IP literals and URL hosts inside a shell line, checked in addition to the scanner-name rule. */
async function shellLineDecision(args, verifier) {
  const text = collectStrings(args).join(' ')
  const hosts = new Set([...urlHosts([text])])
  for (const ip of text.match(IPV4_RE) ?? []) hosts.add(ip)
  for (const host of hosts) {
    if (LAB_HOSTS.has(host)) continue
    if (looksLikeIp(host)) return deny(`${host} is not a lab host and IP targets cannot be ownership-verified`)
    let verified = false
    try {
      verified = (await verifier.isVerified(host)) === true
    } catch {
      verified = false
    }
    if (!verified) return deny(`${host} is not a lab host and is not verified in SecScan; zero packets sent`)
  }
  return ALLOW
}

/**
 * Decide whether one AlterEgo tool call may run. Non-AlterEgo tools are allowed here; the scanner
 * rules in scope.mjs still apply to them through decideScope.
 * @param {{name: string, arguments?: Record<string, unknown>}} exec
 * @param {{isVerified: (domain: string) => Promise<boolean>}} verifier - must fail closed
 */
export async function alterEgoScopeDecision(exec, verifier) {
  if (typeof exec?.name !== 'string' || !exec.name.startsWith(AE_PREFIX)) return ALLOW
  const name = catalogName(exec.name)
  const args = exec.arguments ?? {}
  if (SHELL_LIKE.has(name)) {
    const scanner = await decideScope({ toolName: 'bash', arguments: args }, verifier)
    if (scanner.kind === 'deny') return scanner
    return shellLineDecision(args, verifier)
  }
  if (BATCH.has(name)) return hostsDecision(args, verifier, { activeWordsNeedTarget: true })
  if (NETWORK.has(name)) return hostsDecision(args, verifier, { activeWordsNeedTarget: false })
  return ALLOW
}
