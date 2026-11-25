/** Same-origin fetch helpers for the QNX pages. */
import { useCallback, useEffect, useRef, useState } from 'react'

/** A failure the page shows instead of data. */
export class QnxError extends Error {
  constructor(message: string, readonly status: number) {
    super(message)
  }
}

/** Call one panel API route. */
export async function call<T>(method: 'GET' | 'POST', path: string, body?: unknown): Promise<T> {
  let response: Response
  try {
    response = await fetch(`/qnx/api/${path}`, {
      method,
      headers: { accept: 'application/json', ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    })
  } catch (error) {
    throw new QnxError(error instanceof Error ? error.message : String(error), 0)
  }
  const text = await response.text()
  let value: unknown
  try { value = text === '' ? {} : JSON.parse(text) as unknown } catch { throw new QnxError(`The QNX bundle answered ${String(response.status)} without JSON.`, response.status) }
  if (!response.ok) {
    const error = typeof value === 'object' && value !== null && typeof (value as { error?: unknown }).error === 'string' ? (value as { error: string }).error : `Status ${String(response.status)}.`
    throw new QnxError(error, response.status)
  }
  return value as T
}

/** One audit line as the engine writes it. */
export interface AuditEntry {
  readonly seq: number
  readonly ts: string
  readonly kind: string
  readonly seat?: string | null
  readonly tool?: string | null
  readonly decision?: string
  readonly reason?: string
  readonly argv?: string[]
  readonly exit?: number
  readonly stdout_bytes?: number
  readonly duration_ms?: number
  readonly spawned?: boolean | null
  readonly targets?: Array<{ target: string; in_scope: boolean; reason: string }>
  readonly prev: string
  readonly hash: string
  readonly [key: string]: unknown
}

/** The engine state the pages render. */
export interface State {
  readonly target: { hostname: string; os: string; release: string; machine: string; qnx_version?: string }
  readonly catalog: { tools: number; visible: number; free?: number; listeners: Array<{ proto: string; addr: string; port: number }> }
  readonly policy: { allow_destructive: boolean; destructive_mode?: 'off' | 'ask' | 'on'; sandbox: { process: string; network: string }; self_scope: string[] }
  readonly engagements: { verified: Array<{ id: string; targets: string[]; expires_at: string | null }>; rejected: Array<{ id: string; reason: string }>; error: string | null }
  readonly audit: { ok: boolean; count: number; head: string; bad_line?: number; reason?: string }
  readonly signing_key: { key_id: string }
  readonly bundle: { target: 'standin' | 'qnx'; mcp?: string }
}

/** Read the engine state while mounted; poll so the chain count and engagements stay current. */
export function useQnxState() {
  const [state, setState] = useState<{ data?: State; error?: QnxError }>({})
  const load = useCallback(async () => {
    try { setState({ data: await call<State>('GET', 'state') }) } catch (error) { setState({ error: error as QnxError }) }
  }, [])
  useEffect(() => {
    void load()
    const timer = setInterval(() => { void load() }, 4000)
    return () => { clearInterval(timer) }
  }, [load])
  return { ...state, reload: load }
}

/** Follow the audit chain live: the newest `keep` entries, newest first. */
export function useAuditTape(keep = 300) {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const last = useRef(0)
  useEffect(() => {
    const controller = new AbortController()
    let retry: ReturnType<typeof setTimeout> | undefined
    const follow = async (): Promise<void> => {
      try {
        const response = await fetch(`/qnx/api/audit/stream?after=${String(last.current)}`, { signal: controller.signal })
        if (!response.ok || response.body === null) throw new Error(String(response.status))
        const reader = response.body.getReader()
        const decoder = new TextDecoder()
        let buffer = ''
        for (;;) {
          const { value, done } = await reader.read()
          if (done) break
          buffer += decoder.decode(value, { stream: true })
          const fresh: AuditEntry[] = []
          let index: number
          while ((index = buffer.indexOf('\n')) >= 0) {
            const line = buffer.slice(0, index)
            buffer = buffer.slice(index + 1)
            try {
              const entry = JSON.parse(line) as AuditEntry
              if (typeof entry.seq === 'number' && entry.seq > last.current) { last.current = entry.seq; fresh.push(entry) }
            } catch { /* keepalive or partial line */ }
          }
          if (fresh.length > 0) setEntries(previous => [...fresh.reverse(), ...previous].slice(0, keep))
        }
      } catch (error) {
        if (controller.signal.aborted) return
        void error
      }
      if (!controller.signal.aborted) retry = setTimeout(() => { void follow() }, 2000)
    }
    void follow()
    return () => { controller.abort(); if (retry !== undefined) clearTimeout(retry) }
  }, [keep])
  return entries
}
