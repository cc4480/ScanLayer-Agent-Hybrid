/** Same-origin fetch helpers for the two panels. */
import { useCallback, useEffect, useRef, useState } from 'react'
import type { PanelData, PageId } from '../types.ts'

/** A panel read failure the page shows instead of data. */
export class PanelError extends Error {
  constructor(message: string, readonly unreachable: boolean) {
    super(message)
  }
}

/** GET one panel endpoint. */
async function get<T>(path: string, signal: AbortSignal): Promise<T> {
  let response: Response
  try {
    response = await fetch(`/machine-control/api/${path}`, { signal, headers: { accept: 'application/json' } })
  } catch (error) {
    signal.throwIfAborted()
    throw new PanelError(error instanceof Error ? error.message : String(error), true)
  }
  const text = await response.text()
  let value: unknown
  try {
    value = text === '' ? {} : JSON.parse(text) as unknown
  } catch {
    throw new PanelError(`The machine control plugin answered ${String(response.status)} without JSON.`, response.status === 404)
  }
  if (!response.ok) {
    const message = typeof value === 'object' && value !== null && typeof (value as { error?: unknown }).error === 'string'
      ? (value as { error: string }).error
      : `The request failed with status ${String(response.status)}.`
    throw new PanelError(message, response.status === 404 && text === '')
  }
  return value as T
}

/** Whether the machine control plugin answers. */
export interface Status {
  readonly sandbox: string
  readonly cwd: string
  readonly pages: ReadonlyArray<string>
  /** Absolute path of the quit plan file, chosen by the Host. */
  readonly quitPlanPath: string
}

/**
 * Read one panel page while mounted, reloading on demand.
 * @param page - the page to read.
 * @returns the data, the failure, whether a read is running, and a reload callback.
 */
export function usePanel(page: PageId) {
  const [state, setState] = useState<{ data?: PanelData; error?: PanelError; loading: boolean }>({ loading: true })
  const current = useRef<AbortController>(undefined)
  const load = useCallback(async () => {
    current.current?.abort()
    const request = new AbortController()
    current.current = request
    setState(previous => ({ ...previous, loading: true }))
    try {
      const data = await get<PanelData>(`page/${page}`, request.signal)
      if (!request.signal.aborted) setState({ data, loading: false })
    } catch (error) {
      if (request.signal.aborted) return
      setState(previous => ({ error: error instanceof PanelError ? error : new PanelError(String(error), false), loading: false, ...previous.data === undefined ? {} : { data: previous.data } }))
    }
  }, [page])
  useEffect(() => {
    void load()
    return () => { current.current?.abort() }
  }, [load])
  return { ...state, reload: load }
}

/**
 * Read the plugin's status once while mounted.
 * @returns the status, or the failure that stopped it.
 */
export function useStatus() {
  const [state, setState] = useState<{ status?: Status; error?: PanelError }>({})
  useEffect(() => {
    const request = new AbortController()
    get<Status>('status', request.signal).then(
      status => { if (!request.signal.aborted) setState({ status }) },
      (error: unknown) => { if (!request.signal.aborted) setState({ error: error instanceof PanelError ? error : new PanelError(String(error), false) }) },
    )
    return () => { request.abort() }
  }, [])
  return state
}

/**
 * Save a quit plan the reader chose. The Host owns the file's location and validates the action.
 * @param plan - the action and optional plan name.
 * @returns the saved path.
 */
export async function saveQuitPlan(plan: { action: string; name?: string }): Promise<{ saved: boolean; path: string }> {
  const response = await fetch('/machine-control/api/quit-plan', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(plan),
  })
  const text = await response.text()
  let value: unknown
  try {
    value = text === '' ? {} : JSON.parse(text) as unknown
  } catch {
    throw new PanelError('The plan could not be saved; the answer was not JSON.', false)
  }
  if (!response.ok) {
    const message = typeof (value as { error?: unknown }).error === 'string' ? String((value as { error: string }).error) : 'The plan could not be saved.'
    throw new PanelError(message, false)
  }
  return value as { saved: boolean; path: string }
}

/** The answer to one panel action. */
export interface ActionReport {
  readonly op: string
  readonly title: string
  readonly exitCode: number | null
  readonly stdout: string
  readonly stderr: string
  readonly truncated: boolean
}

/**
 * Run one operation the Host's table allows. It builds the same PowerShell command the matching agent tool builds.
 * @param op - the operation id.
 * @param params - its arguments.
 * @returns the exit status and the captured output.
 */
export async function runAction(op: string, params: Record<string, unknown> = {}): Promise<ActionReport> {
  const response = await fetch('/machine-control/api/action', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ op, params }),
  })
  const text = await response.text()
  let value: unknown
  try {
    value = text === '' ? {} : JSON.parse(text) as unknown
  } catch {
    throw new PanelError('The action did not answer with JSON.', false)
  }
  if (!response.ok) {
    const message = typeof (value as { error?: unknown }).error === 'string'
      ? String((value as { error: string }).error)
      : 'The action failed.'
    throw new PanelError(message, false)
  }
  return value as ActionReport
}
