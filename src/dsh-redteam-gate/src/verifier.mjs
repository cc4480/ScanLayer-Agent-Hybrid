// Local domain-ownership verification: DNS TXT challenge, in-process. No server, no MCP token.
// Port of packages/redteam/auth-gate/src/local.ts + local-store.ts (same behavior).
//
// Flow: start(domain) mints a token and stores it as pending. The operator publishes that token at
// _secscan-challenge.<domain>. check(domain) reads TXT and, on a match, records the domain as verified.
// Every read fails closed: unreadable store or DNS failure means NOT verified.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { promises as dnsPromises } from 'node:dns'
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

export const CHALLENGE_RECORD_PREFIX = '_secscan-challenge'
export const CHALLENGE_TOKEN_PREFIX = 'secscan-verify-'
const STORE_VERSION = 1

/** Lowercase hostname from a URL or bare domain; null when unusable. */
export function normalizeDomain(raw) {
  let s = String(raw ?? '').trim()
  if (!s) return null
  if (!/^https?:\/\//i.test(s)) s = `https://${s}`
  try {
    const host = new URL(s).hostname.toLowerCase().replace(/\.$/, '')
    return host || null
  } catch {
    return null
  }
}

export function defaultStoreFile(env = process.env) {
  const named = (env.REDTEAM_VERIFIED_DOMAINS_FILE ?? '').trim()
  if (named) return named
  return join(homedir(), '.secscan-redteam', 'verified-domains.json')
}

function tokenMatches(candidate, expected) {
  const a = createHash('sha256').update(candidate, 'utf8').digest()
  const b = createHash('sha256').update(expected, 'utf8').digest()
  return timingSafeEqual(a, b)
}

function emptyStore() {
  return { version: STORE_VERSION, pending: {}, verified: {} }
}

function asRecord(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v) ? v : {}
}

/** Keep only well-formed entries; the file is a durable authorization record, so it is validated. */
export function coerceStore(parsed) {
  const root = asRecord(parsed)
  const doc = emptyStore()
  for (const [domain, raw] of Object.entries(asRecord(root.pending))) {
    const e = asRecord(raw)
    const key = normalizeDomain(domain)
    if (key && typeof e.token === 'string' && e.token && typeof e.createdAt === 'string' && e.createdAt) {
      doc.pending[key] = { token: e.token, createdAt: e.createdAt }
    }
  }
  for (const [domain, raw] of Object.entries(asRecord(root.verified))) {
    const e = asRecord(raw)
    const key = normalizeDomain(domain)
    if (key && typeof e.token === 'string' && e.token && typeof e.verifiedAt === 'string' && e.verifiedAt) {
      doc.verified[key] = { token: e.token, verifiedAt: e.verifiedAt, method: 'dns-txt' }
    }
  }
  return doc
}

export class VerificationStore {
  constructor(file) {
    this.file = file
  }

  async load() {
    let text
    try {
      text = await readFile(this.file, 'utf8')
    } catch (err) {
      if (err && err.code === 'ENOENT') return emptyStore()
      throw err
    }
    if (text.trim() === '') return emptyStore()
    return coerceStore(JSON.parse(text))
  }

  /** Atomic write (temp file + rename, mode 0600): a torn write must never read as a partial authorization. */
  async save(doc) {
    await mkdir(dirname(this.file), { recursive: true, mode: 0o700 })
    const tmp = `${this.file}.${randomBytes(6).toString('hex')}.tmp`
    await writeFile(tmp, `${JSON.stringify(doc, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 })
    await rename(tmp, this.file)
  }
}

export class LocalDomainVerifier {
  /**
   * @param {{storeFile?: string, resolveTxt?: (name: string) => Promise<string[][]>, now?: () => Date}} cfg
   */
  constructor(cfg = {}) {
    this.store = new VerificationStore(cfg.storeFile ?? defaultStoreFile())
    this.resolveTxt = cfg.resolveTxt ?? ((name) => dnsPromises.resolveTxt(name))
    this.now = cfg.now ?? (() => new Date())
  }

  get path() {
    return this.store.file
  }

  /** Mint a token for the domain and store it as pending. Re-issuing replaces the pending token. */
  async start(domain) {
    const d = normalizeDomain(domain)
    if (!d) throw new Error(`not a usable domain: ${JSON.stringify(domain)}`)
    const token = CHALLENGE_TOKEN_PREFIX + randomBytes(24).toString('hex')
    const createdAt = this.now().toISOString()
    const doc = await this.store.load()
    doc.pending[d] = { token, createdAt }
    await this.store.save(doc)
    return { domain: d, recordName: `${CHALLENGE_RECORD_PREFIX}.${d}`, token, createdAt }
  }

  /** Read the TXT record and decide. Anything other than a matching record is a denial. */
  async check(domain) {
    const d = normalizeDomain(domain)
    if (!d) throw new Error(`not a usable domain: ${JSON.stringify(domain)}`)
    const recordName = `${CHALLENGE_RECORD_PREFIX}.${d}`
    const doc = await this.store.load()
    const expected = doc.pending[d]?.token ?? doc.verified[d]?.token
    if (expected === undefined) {
      return { verified: false, domain: d, recordName, reason: `no challenge issued for ${d}; run start first` }
    }
    let records
    try {
      records = await this.resolveTxt(recordName)
    } catch (err) {
      return { verified: false, domain: d, recordName, reason: `TXT lookup for ${recordName} failed: ${err?.message ?? err}` }
    }
    const published = records.map((chunks) => chunks.join('').trim())
    if (!published.some((v) => tokenMatches(v, expected))) {
      return {
        verified: false,
        domain: d,
        recordName,
        reason: published.length === 0
          ? `no TXT record at ${recordName}`
          : `${published.length} TXT record(s) at ${recordName}, none carries the challenge token`,
      }
    }
    delete doc.pending[d]
    doc.verified[d] = { token: expected, verifiedAt: this.now().toISOString(), method: 'dns-txt' }
    await this.store.save(doc)
    return { verified: true, domain: d, recordName, reason: `${d} is ownership-verified` }
  }

  /** Fail closed: an unreadable store means not verified. */
  async isVerified(domain) {
    const d = normalizeDomain(domain)
    if (!d) return false
    try {
      return (await this.store.load()).verified[d] !== undefined
    } catch {
      return false
    }
  }
}
