/** The sidebar pages: a machine overview, live process and service lists, network and security, and the quit plan. */
import { useState } from 'react'
import type { PageId } from '../types.ts'
import { PAGES } from '../types.ts'
import { saveQuitPlan, usePanel, useStatus } from './api.ts'
import type { T } from './locales.ts'
import { CopyButton, PageFrame, PanelBody, Tabs } from './ui.tsx'

/** Locale key of one page's tab label. */
const LABEL_KEY: Record<PageId, string> = {
  overview: 'pageOverview',
  processes: 'pageProcesses',
  services: 'pageServices',
  startup: 'pageStartup',
  network: 'pageNetwork',
  security: 'pageSecurity',
  packages: 'pagePackages',
  disk: 'pageDisk',
}

/** A page that reads one area and offers a reload. */
function AreaPage({ first, t, areas }: { first: PageId; t: T; areas: ReadonlyArray<PageId> }) {
  const [area, setArea] = useState<PageId>(first)
  const { data, error, loading, reload } = usePanel(area)
  // A read that has not answered yet must not show the previous tab's rows under the new tab.
  const shown = data !== undefined && data.page === area ? data : undefined
  const tabs = areas.map(id => ({ id, label: t(LABEL_KEY[id]) }))
  return (
    <PageFrame
      title={t('panel')}
      subtitle={shown === undefined ? undefined : `${t('collectedAt')} ${new Date(shown.collectedAt).toLocaleTimeString()}`}
      actions={<button type="button" className="mc-button" onClick={() => { void reload() }} disabled={loading}>{t('reload')}</button>}
    >
      <Tabs tabs={tabs} value={area} onChange={setArea} />
      {error === undefined
        ? undefined
        : <div className="mc-note mc-error">{error.unreachable ? t('offline') : `${t('failed')}: ${error.message}`}</div>}
      <PanelBody data={shown} t={t} offline={shown === undefined && error === undefined ? t('loading') : undefined} />
    </PageFrame>
  )
}

/** The console: host facts, then every area as a tab. */
export function ConsolePage({ t }: { t: T }) {
  return <AreaPage first="overview" t={t} areas={PAGES} />
}

/** Processes, services, startup items and packages. */
export function WorkPage({ t }: { t: T }) {
  return <AreaPage first="processes" t={t} areas={['processes', 'services', 'startup', 'packages']} />
}

/** Network, security posture and disk. */
export function GuardPage({ t }: { t: T }) {
  return <AreaPage first="network" t={t} areas={['network', 'security', 'disk']} />
}

/** Quit actions, in the order the page lists them, with their label keys. */
const QUIT_ACTIONS: ReadonlyArray<readonly [action: string, labelKey: string]> = [
  ['reboot', 'actionReboot'],
  ['shutdown', 'actionShutdown'],
  ['reboot-update', 'actionRebootUpdate'],
  ['explorer', 'actionExplorer'],
  ['logoff', 'actionLogoff'],
  ['flush-dns', 'actionFlushDns'],
]


/**
 * The quit page: choose what happens after DSH closes and write the plan file. The Host chooses the file's location, so the
 * page shows the path the Host reports rather than composing one.
 * @param props - the translate function.
 */
export function QuitPage({ t }: { t: T }) {
  const [action, setAction] = useState('')
  const [name, setName] = useState('')
  const [saved, setSaved] = useState<string | undefined>(undefined)
  const [failed, setFailed] = useState<string | undefined>(undefined)
  const { status } = useStatus()
  const path = status?.quitPlanPath ?? ''
  const command = path === '' ? '' : `dsh-machine-control apply-plan "${path}"`
  const save = async (): Promise<void> => {
    setFailed(undefined)
    setSaved(undefined)
    if (action === '') {
      setFailed(t('quitNoAction'))
      return
    }
    try {
      const trimmed = name.trim()
      const result = await saveQuitPlan({ action, ...trimmed === '' ? {} : { name: trimmed } })
      setSaved(result.path)
    } catch (error) {
      setFailed(error instanceof Error ? error.message : String(error))
    }
  }
  return (
    <PageFrame title={t('quitTitle')} subtitle={t('quitHint')}>
      <section className="mc-quit">
        <label className="mc-field">
          <span className="mc-label">{t('quitAction')}</span>
          <select className="mc-select" value={action} onChange={(event) => { setAction(event.target.value) }}>
            <option value="">{t('quitNone')}</option>
            {QUIT_ACTIONS.map(([id, key]) => <option key={id} value={id}>{t(key)}</option>)}
          </select>
        </label>
        <label className="mc-field">
          <span className="mc-label">{t('quitName')}</span>
          <input
            className="mc-input"
            value={name}
            placeholder={t('quitNamePlaceholder')}
            onChange={(event) => { setName(event.target.value) }}
          />
        </label>
        <div className="mc-actions">
          <button type="button" className="mc-button" onClick={() => { void save() }} disabled={action === ''}>{t('quitSave')}</button>
        </div>
        {saved === undefined ? undefined : <p className="mc-ok">{t('quitSaved')}: {saved}</p>}
        {failed === undefined ? undefined : <p className="mc-note mc-error">{t('quitFailed')}: {failed}</p>}
      </section>
      <section className="mc-table-card">
        <header className="mc-table-head">
          <h2 className="mc-table-title">{t('quitHint2')}</h2>
          <CopyButton text={command} label={t('quitCopy')} copiedLabel={t('quitCopied')} />
        </header>
        <div style={{ padding: 14 }}>
          <code className="mc-code">{command}</code>
        </div>
      </section>
    </PageFrame>
  )
}
