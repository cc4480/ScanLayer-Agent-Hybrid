/**
 * Browser entry: three sidebar entries in the Harness interface, each opening its own page in the main column. Every
 * visible string comes from this bundle's locale dictionaries, read through the host locale service at render time.
 */
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-client-locale/client'
import type {} from '@deepseek-ai/dsh-client-ui-layout/client'
import type { MainPanelId } from '@deepseek-ai/dsh-client-ui-layout/client'
import type {} from '@deepseek-ai/dsh-client-ui-sidebar/client'
import type { SidebarPanelIconOwnerProps } from '@deepseek-ai/dsh-client-ui-sidebar/client'
import type {} from '@deepseek-ai/dsh-client-ui-renderer/client'
import type {} from '@deepseek-ai/dsh-client-ui-slots'

import { en, zh, type T } from './locales.ts'
import { ProofPage, ScanPage, TargetPage } from './pages.tsx'
import { STYLES } from './ui.tsx'

/** Locale namespace of this bundle's copy. */
const NS = 'dshQnx'

interface LocaleFace {
  register(ns: string, dicts: { en: Record<string, string>; zh: Record<string, string> }): () => void
  bind(ns: string): (key: string) => string
}

interface Entry {
  readonly id: string
  readonly order: number
  readonly labelKey: keyof typeof en
  readonly Icon: (props: SidebarPanelIconOwnerProps) => React.ReactElement
  readonly Page: (props: { t: T }) => React.ReactElement
}

/** The target: a board-mounted chip with pins, for an embedded system. */
function TargetIcon({ size }: SidebarPanelIconOwnerProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 36 36" fill="none" stroke="currentColor" strokeWidth={1.9} strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <rect x="10" y="10" width="16" height="16" rx="2.5" />
      <path d="M14.5 4.5v5.5M21.5 4.5v5.5M14.5 26v5.5M21.5 26v5.5M4.5 14.5H10M4.5 21.5H10M26 14.5h5.5M26 21.5h5.5" />
      <path d="M15 18h6" />
    </svg>
  )
}

/** Scan and verify: a magnifier over a check mark. */
function ScanIcon({ size }: SidebarPanelIconOwnerProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 36 36" fill="none" stroke="currentColor" strokeWidth={1.9} strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <circle cx="15.5" cy="15.5" r="9.5" />
      <path d="M22.5 22.5l8 8" />
      <path d="M11.5 15.8l2.9 2.9 5.3-5.6" />
    </svg>
  )
}

/** Scope and proof: chained links. */
function ProofIcon({ size }: SidebarPanelIconOwnerProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 36 36" fill="none" stroke="currentColor" strokeWidth={1.9} strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <rect x="4.5" y="13" width="14" height="10" rx="5" />
      <rect x="17.5" y="13" width="14" height="10" rx="5" />
      <path d="M14 18h8" />
    </svg>
  )
}

const ENTRIES: ReadonlyArray<Entry> = [
  { id: 'dsh-qnx-target', order: 20, labelKey: 'target', Icon: TargetIcon, Page: TargetPage },
  { id: 'dsh-qnx-scan', order: 21, labelKey: 'scan', Icon: ScanIcon, Page: ScanPage },
  { id: 'dsh-qnx-proof', order: 22, labelKey: 'proof', Icon: ProofIcon, Page: ProofPage },
]

/** Services this Client half needs. */
export const inject = ['slots', 'locale']

/**
 * Register the dictionaries, then one sidebar entry and its page for each feature.
 * @param ctx - the Client root context.
 */
export function apply(ctx: Context): void {
  ctx.effect(() => {
    const element = document.createElement('style')
    element.dataset.qnx = ''
    element.textContent = STYLES
    document.head.append(element)
    return () => { element.remove() }
  }, 'qnx: styles')
  ctx.effect(() => (ctx.locale as unknown as LocaleFace).register(NS, { en, zh }), 'qnx: dictionaries')
  const t = (ctx.locale as unknown as LocaleFace).bind(NS) as T
  for (const entry of ENTRIES) {
    const key = entry.id as MainPanelId
    const Page = entry.Page
    ctx.slots.inject('main', () => ctx.slots.register({ name: 'main', key }, () => <Page t={t} />))
    ctx.slots.inject('sidebar.panellist', () => ctx.slots.register({
      name: 'sidebar.panellist',
      id: entry.id,
      order: entry.order,
      label: () => t(entry.labelKey),
    }, entry.Icon))
  }
}

export { STYLES }
