/** The sidebar pages: a machine overview, live process and service lists, network and security, and the quit plan. */
import { useState, type ReactNode } from 'react'
import type { PageId, Table, TableRow } from '../types.ts'
import { PAGES } from '../types.ts'
import { runAction, saveQuitPlan, usePanel, useStatus } from './api.ts'
import type { T } from './locales.ts'
import { ActionBanner, CopyButton, PageFrame, PanelBody, Tabs } from './ui.tsx'

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

/** One action a table row offers: the operation, the arguments it reads from that row, and when it applies. */
interface RowAction {
  readonly labelKey: string
  readonly op: string
  readonly params: (row: TableRow) => Record<string, unknown>
  readonly confirmKey?: string
  readonly danger?: boolean
  readonly when?: (row: TableRow) => boolean
}

/** One action a page offers above its tables. */
interface PageAction {
  readonly labelKey: string
  readonly op: string
  readonly params: Record<string, unknown>
  readonly confirmKey?: string
  readonly danger?: boolean
}

/**
 * Row actions per page and table title. The columns are the ones each table declares: a process row starts with its PID, a
 * service row with its name and status.
 */
const ROW_ACTIONS: Partial<Record<PageId, Record<string, ReadonlyArray<RowAction>>>> = {
  processes: {
    'Processes by memory': [
      { labelKey: 'actEnd', op: 'process.stop', params: row => ({ id: Number(row[0]) }), confirmKey: 'confirmEnd', danger: true },
    ],
  },
  services: {
    Services: [
      { labelKey: 'actStart', op: 'service.start', params: row => ({ name: row[0] }), when: row => row[1] !== 'Running' },
      { labelKey: 'actStop', op: 'service.stop', params: row => ({ name: row[0] }), confirmKey: 'confirmStopService', danger: true, when: row => row[1] === 'Running' },
      { labelKey: 'actRestart', op: 'service.restart', params: row => ({ name: row[0] }), confirmKey: 'confirmRestartService', when: row => row[1] === 'Running' },
    ],
  },
}

/** Page-level actions: housekeeping whose target is the whole machine rather than one row. */
const PAGE_ACTIONS: Partial<Record<PageId, ReadonlyArray<PageAction>>> = {
  security: [{ labelKey: 'actQuickScan', op: 'security.scan-start', params: { scan: 'quick' } }],
  disk: [{ labelKey: 'actCleanTemp', op: 'disk.clean-temp', params: { drive: 'C' }, confirmKey: 'confirmCleanTemp', danger: true }],
  network: [{ labelKey: 'actClearDns', op: 'network.clear-dns', params: {} }],
}

/** A page that reads one area and runs the operations that area offers. */
function AreaPage({ first, t, areas }: { first: PageId; t: T; areas: ReadonlyArray<PageId> }) {
  const [area, setArea] = useState<PageId>(first)
  const { data, error, loading, reload } = usePanel(area)
  const [busy, setBusy] = useState(false)
  const [report, setReport] = useState<{ ok: boolean; title: string; text: string } | undefined>(undefined)
  // A read that has not answered yet must not show the previous tab's rows under the new tab.
  const shown = data !== undefined && data.page === area ? data : undefined
  const tabs = areas.map(id => ({ id, label: t(LABEL_KEY[id]) }))

  const run = async (labelKey: string, op: string, params: Record<string, unknown>, confirmKey?: string): Promise<void> => {
    if (confirmKey !== undefined && !window.confirm(t(confirmKey))) return
    setBusy(true)
    setReport(undefined)
    try {
      const result = await runAction(op, params)
      const output = [result.stdout.trim(), result.stderr.trim()].filter(part => part !== '').join('\n')
      const ok = result.exitCode === 0
      setReport({
        ok,
        title: `${t(labelKey)}: ${ok ? t('actionDone') : `${t('actionFailed')} (exit ${String(result.exitCode)})`}`,
        text: output === '' ? t('actionDone') : output,
      })
      await reload()
    } catch (caught) {
      setReport({
        ok: false,
        title: `${t(labelKey)}: ${t('actionFailed')}`,
        text: caught instanceof Error ? caught.message : String(caught),
      })
    } finally {
      setBusy(false)
    }
  }

  const rowActionsFor = (table: Table, row: TableRow): ReactNode => {
    const actions = (ROW_ACTIONS[area]?.[table.title] ?? []).filter(action => action.when === undefined || action.when(row))
    return actions.map(action => (
      <button
        key={action.labelKey}
        type="button"
        className={`mc-button mc-small${action.danger === true ? ' mc-danger' : ''}`}
        disabled={busy}
        onClick={() => { void run(action.labelKey, action.op, action.params(row), action.confirmKey) }}
      >
        {t(action.labelKey)}
      </button>
    ))
  }

  const pageActions = PAGE_ACTIONS[area] ?? []
  const actions = (
    <>
      {pageActions.map(action => (
        <button
          key={action.labelKey}
          type="button"
          className={`mc-button${action.danger === true ? ' mc-danger' : ''}`}
          disabled={busy}
          onClick={() => { void run(action.labelKey, action.op, action.params, action.confirmKey) }}
        >
          {t(action.labelKey)}
        </button>
      ))}
      <button type="button" className="mc-button" onClick={() => { void reload() }} disabled={loading || busy}>{busy ? t('working') : t('reload')}</button>
    </>
  )

  return (
    <PageFrame
      title={t('panel')}
      subtitle={shown === undefined ? undefined : `${t('collectedAt')} ${new Date(shown.collectedAt).toLocaleTimeString()}`}
      actions={actions}
    >
      <Tabs tabs={tabs} value={area} onChange={setArea} />
      {error === undefined
        ? undefined
        : <div className="mc-note mc-error">{error.unreachable ? t('offline') : `${t('failed')}: ${error.message}`}</div>}
      {report === undefined ? undefined : <ActionBanner report={report} t={t} onDismiss={() => { setReport(undefined) }} />}
      <PanelBody
        data={shown}
        t={t}
        offline={shown === undefined && error === undefined ? t('loading') : undefined}
        rowActions={rowActionsFor}
      />
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
