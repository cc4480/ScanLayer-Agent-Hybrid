/** The local Source: work a person starts from the panel, which has no external conversation to answer in. */
import { randomUUID } from 'node:crypto'
import { z } from 'zod'
import type { Trigger } from '../core/index.ts'
import type { SourceKind } from './kind.ts'

export const MANUAL_SOURCE = 'manual'
/** The one sender of the local Source: the person at this machine's panel. */
export const MANUAL_ACTOR = 'operator'
export const ManualConfigSchema = z.object({}).strict()
export type ManualConfig = z.infer<typeof ManualConfigSchema>
/**
 * A Source with nothing to configure, no listening rule, no Channel and no Thread reader: every Trigger it produces is work
 * a person typed in the panel. The Policy always allows its one sender (see `allowedSender`), and the ticket it starts has no
 * conversation to reply to, so its result is the ticket and its worker Session.
 */
export const manualKind: SourceKind<ManualConfig> = {
  kind: MANUAL_SOURCE,
  title: { zh: '本地任务', en: 'Local work' },
  description: { zh: '从面板发起的任务，没有会话可以回复；结果记在工单和它的 worker Session 上。',
    en: 'Work started from the panel. It has no conversation to answer in: its result is the ticket and its worker Session.' },
  schema: ManualConfigSchema,
  fields: [],
  health: [],
}
/**
 * One Trigger per piece of local work, on its own Thread, so the Ticket, its Decisions and its history stay together: the
 * Ticket title the person typed travels in `meta.title`, and the request itself is `text`.
 */
export function manualTrigger(input: { text: string; title: string; at: string; id?: string }): Trigger {
  const id = input.id ?? `local-${randomUUID()}`
  return { id: `trigger-${id}`, source: MANUAL_SOURCE, threads: [{ source: MANUAL_SOURCE, id }],
    actor: { source: MANUAL_SOURCE, id: MANUAL_ACTOR }, human: true, addressed: 'direct', at: input.at, text: input.text,
    meta: { title: input.title } }
}