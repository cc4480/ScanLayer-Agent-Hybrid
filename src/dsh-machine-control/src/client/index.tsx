/**
 * Browser entry: four sidebar entries, each opening its own page in the main column. Icons are drawn here; every visible
 * string comes from this bundle's locale dictionaries, read through the host locale service at render time.
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
import { ConsolePage, GuardPage, QuitPage, WorkPage } from './pages.tsx'
import { STYLES } from './ui.tsx'

/** Locale namespace of this bundle's copy. */
const NS = 'dshMachineControl'

/** The locale service face this half uses; the host types it per declared namespace, which this external bundle adds at runtime. */
interface LocaleFace {
  register(ns: string, dicts: { en: Record<string, string>; zh: Record<string, string> }): () => void
  bind(ns: string): (key: string) => string
}

/** One sidebar entry: its panel id, icon, label key, and page component. */
interface Entry {
  readonly id: string
  readonly order: number
  readonly labelKey: string
  readonly Icon: (props: SidebarPanelIconOwnerProps) => React.ReactElement
  readonly Page: (props: { t: T }) => React.ReactElement
}

/** The machine console: a terminal-window glyph with a prompt. */
function ConsoleIcon({ size }: SidebarPanelIconOwnerProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 36 36" fill="none" stroke="currentColor" strokeWidth={1.9} strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <rect x="4.5" y="7" width="27" height="22" rx="3" />
      <path d="M9.5 14.5l4.5 3.5-4.5 3.5" />
      <path d="M17.5 22h8" />
    </svg>
  )
}

/** Processes and services: two stacked rows. */
function WorkIcon({ size }: SidebarPanelIconOwnerProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 36 36" fill="none" stroke="currentColor" strokeWidth={1.9} strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <rect x="6" y="5.5" width="24" height="9" rx="2.4" />
      <rect x="6" y="21.5" width="24" height="9" rx="2.4" />
      <path d="M10.5 10h.02M10.5 26h.02" />
      <path d="M16 10h9M16 26h9" />
    </svg>
  )
}

/** Network and security: a shield with a check. */
function GuardIcon({ size }: SidebarPanelIconOwnerProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 36 36" fill="none" stroke="currentColor" strokeWidth={1.9} strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d="M18 4.5l11 3.6v8.2c0 6.6-4.3 12.1-11 15.2-6.7-3.1-11-8.6-11-15.2V8.1z" />
      <path d="M12.8 17.9l3.6 3.6 7-7" />
    </svg>
  )
}

/** Quit: a door with an arrow leaving it. */
function QuitIcon({ size }: SidebarPanelIconOwnerProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 36 36" fill="none" stroke="currentColor" strokeWidth={1.9} strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d="M14 6.5H7.5A2.5 2.5 0 005 9v18a2.5 2.5 0 002.5 2.5H14" />
      <path d="M22.5 11.5L30 18l-7.5 6.5" />
      <path d="M30 18H13" />
    </svg>
  )
}

const ENTRIES: ReadonlyArray<Entry> = [
  { id: 'dsh-machine-console', order: 30, labelKey: 'console', Icon: ConsoleIcon, Page: ConsolePage },
  { id: 'dsh-machine-work', order: 31, labelKey: 'work', Icon: WorkIcon, Page: WorkPage },
  { id: 'dsh-machine-guard', order: 32, labelKey: 'guard', Icon: GuardIcon, Page: GuardPage },
  { id: 'dsh-machine-quit', order: 33, labelKey: 'quit', Icon: QuitIcon, Page: QuitPage },
]

/** Services this Client half needs. */
export const inject = ['slots', 'locale']

/**
 * Register the dictionaries, one sidebar entry, and its page for each feature.
 * @param ctx - the Client root context.
 */
export function apply(ctx: Context): void {
  // The panel stylesheet is owned by this plugin run: inserted on apply, removed with the effect.
  ctx.effect(() => {
    const element = document.createElement('style')
    element.dataset.machineControl = ''
    element.textContent = STYLES
    document.head.append(element)
    return () => { element.remove() }
  }, 'machine-control: styles')
  ctx.effect(() => (ctx.locale as unknown as LocaleFace).register(NS, { en, zh }), 'machine-control: dictionaries')
  // Bind the namespace once: the resolver reads the active locale at every call, so a locale switch re-renders this copy.
  const t = (ctx.locale as unknown as LocaleFace).bind(NS) as T
  for (const entry of ENTRIES) {
    const key = entry.id as MainPanelId
    const Page = entry.Page
    ctx.slots.inject('main', () => ctx.slots.register(
      { name: 'main', key },
      () => <Page t={t} />,
    ))
    ctx.slots.inject('sidebar.panellist', () => ctx.slots.register({
      name: 'sidebar.panellist',
      id: entry.id,
      order: entry.order,
      label: () => t(entry.labelKey),
    }, entry.Icon))
  }
}

export { STYLES }
