/** Presentational building blocks for the machine panels, styled with the host theme tokens. */
import { useMemo, useState, type ReactNode } from 'react'
import type { Fact, PanelData, Table, TableRow } from '../types.ts'
import type { T } from './locales.ts'

/** The stylesheet every panel needs; inserted once by the client entry. */
export const STYLES = `
.mc-page { display: flex; flex-direction: column; gap: 20px; padding: 24px 28px 40px; height: 100%; overflow: auto; box-sizing: border-box; }
.mc-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; }
.mc-title { font-size: 20px; font-weight: 600; color: var(--dsw-alias-text-primary); margin: 0; }
.mc-subtitle { font-size: 13px; color: var(--dsw-alias-text-secondary); margin: 4px 0 0; }
.mc-actions { display: flex; gap: 8px; flex: none; }
.mc-button { font: inherit; font-size: 13px; padding: 6px 12px; border-radius: 8px; cursor: pointer;
  border: 1px solid var(--dsw-alias-border-default, rgba(127,127,127,.35)); background: transparent;
  color: var(--dsw-alias-text-primary); }
.mc-button:hover:not([disabled]) { background: rgba(127,127,127,.14); }
.mc-button[disabled] { opacity: .55; cursor: default; }
.mc-tabs { display: flex; flex-wrap: wrap; gap: 4px; border-bottom: 1px solid rgba(127,127,127,.24); }
.mc-tab { font: inherit; font-size: 13px; padding: 8px 12px; cursor: pointer; color: var(--dsw-alias-text-secondary);
  background: none; border: none; border-bottom: 2px solid transparent; margin-bottom: -1px; }
.mc-tab[aria-selected="true"] { color: var(--dsw-alias-text-primary); border-bottom-color: #22c55e; font-weight: 600; }
.mc-facts { display: grid; grid-template-columns: repeat(auto-fill, minmax(210px, 1fr)); gap: 12px; flex: none; }
.mc-fact { padding: 12px 14px; border-radius: 10px; border: 1px solid rgba(127,127,127,.24);
  background: rgba(127,127,127,.06); min-width: 0; }
.mc-fact-label { font-size: 11px; text-transform: uppercase; letter-spacing: .04em; color: var(--dsw-alias-text-secondary); margin: 0 0 6px; }
.mc-fact-value { font-size: 14px; font-weight: 600; margin: 0; overflow-wrap: anywhere; }
.mc-table-card { border: 1px solid rgba(127,127,127,.24); border-radius: 10px; overflow: hidden; flex: none; }
.mc-table-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; padding: 10px 14px;
  border-bottom: 1px solid rgba(127,127,127,.24); }
.mc-table-title { font-size: 13px; font-weight: 600; margin: 0; }
.mc-table-count { font-size: 12px; color: var(--dsw-alias-text-secondary); }
.mc-scroll { overflow: auto; max-height: 46vh; }
.mc-table { border-collapse: collapse; width: 100%; font-size: 12.5px; }
.mc-table th { position: sticky; top: 0; text-align: left; font-weight: 600; padding: 8px 12px; white-space: nowrap;
  background: rgba(127,127,127,.10); color: var(--dsw-alias-text-secondary);
  border-bottom: 1px solid rgba(127,127,127,.24); }
.mc-table td { padding: 7px 12px; border-bottom: 1px solid rgba(127,127,127,.12); vertical-align: top; }
.mc-table tr:last-child td { border-bottom: none; }
.mc-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
.mc-wrap { max-width: min(460px, 42vw); overflow-wrap: anywhere; word-break: break-word; }
.mc-note { font-size: 12.5px; padding: 10px 14px; border-radius: 8px; color: var(--dsw-alias-text-secondary);
  border: 1px solid rgba(127,127,127,.24); background: rgba(127,127,127,.06); flex: none; }
.mc-error { border-color: #f87171; color: var(--dsw-alias-text-primary); }
.mc-empty { padding: 32px; text-align: center; color: var(--dsw-alias-text-secondary); font-size: 13px; }
.mc-field { display: flex; flex-direction: column; gap: 6px; max-width: 420px; }
.mc-label { font-size: 12px; color: var(--dsw-alias-text-secondary); }
.mc-input, .mc-select { font: inherit; font-size: 13px; padding: 8px 10px; border-radius: 8px;
  border: 1px solid rgba(127,127,127,.35); background: transparent; color: var(--dsw-alias-text-primary); }
.mc-quit { display: flex; flex-direction: column; gap: 14px; padding: 18px; border-radius: 10px;
  border: 1px solid rgba(127,127,127,.24); }
.mc-code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; padding: 10px 12px;
  border-radius: 8px; overflow-x: auto; white-space: pre; background: rgba(127,127,127,.12); display: block; }
.mc-ok { color: #22c55e; font-size: 12.5px; }
.mc-row-actions { display: flex; gap: 6px; white-space: nowrap; justify-content: flex-end; }
.mc-button.mc-small { padding: 3px 9px; font-size: 12px; border-radius: 6px; }
.mc-button.mc-danger { border-color: rgba(248,113,113,.55); color: #f87171; }
.mc-button.mc-danger:hover:not([disabled]) { background: rgba(248,113,113,.12); }
.mc-banner { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; line-height: 1.5;
  white-space: pre-wrap; max-height: 30vh; overflow: auto; padding: 12px 14px; border-radius: 8px; flex: none;
  border: 1px solid rgba(127,127,127,.3); background: rgba(127,127,127,.08); }
.mc-banner.mc-banner-error { border-color: #f87171; }
.mc-banner-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 8px;
  font-family: inherit; font-weight: 600; }
`

/** One fact card. */
export function FactCard({ fact }: { fact: Fact }) {
  return (
    <div className="mc-fact">
      <p className="mc-fact-label">{fact.label}</p>
      <p className="mc-fact-value">{fact.value}</p>
    </div>
  )
}

/** Whether a cell reads as an id, a number, or a timestamp, which the monospace face fits better. */
function monospace(cell: string): boolean {
  return cell !== '' && /^[\d.,:%/_ -]+$/u.test(cell)
}

/** Length past which a cell wraps inside a bounded column instead of widening the table. */
const WRAP_AFTER = 48

/** One body cell: a long value wraps in a bounded box so the table stays readable. */
function Cell({ text, className }: { text: string; className: string | undefined }) {
  if (text.length <= WRAP_AFTER) return <td className={className}>{text}</td>
  return (
    <td className={className}>
      <div className="mc-wrap" title={text}>{text}</div>
    </td>
  )
}

/** One rendered table with its own scrolling body and, when given, one action cell per row. */
export function DataTable({ table, t, rowActions }: {
  table: Table
  t: T
  rowActions?: ((row: TableRow) => ReactNode) | undefined
}) {
  const count = table.truncated === undefined ? String(table.rows.length) : `${String(table.rows.length)} (+${String(table.truncated)} ${t('truncated')})`
  return (
    <section className="mc-table-card">
      <header className="mc-table-head">
        <h2 className="mc-table-title">{table.title}</h2>
        <span className="mc-table-count">{count}</span>
      </header>
      <div className="mc-scroll">
        <table className="mc-table">
          <thead>
            <tr>
              {table.columns.map(column => <th key={column}>{column}</th>)}
              {rowActions === undefined ? undefined : <th aria-label={t('actions')} />}
            </tr>
          </thead>
          <tbody>
            {table.rows.length === 0
              ? <tr><td colSpan={table.columns.length + (rowActions === undefined ? 0 : 1)} className="mc-empty">{t('noRows')}</td></tr>
              : table.rows.map((row, index) => (
                <tr key={index}>
                  {row.map((cell, column) => <Cell key={column} text={cell} className={monospace(cell) ? 'mc-mono' : undefined} />)}
                  {rowActions === undefined ? undefined : <td className="mc-row-actions">{rowActions(row)}</td>}
                </tr>
              ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}

/** A tab strip over the pages. */
export function Tabs<TId extends string>({ tabs, value, onChange }: {
  tabs: ReadonlyArray<{ readonly id: TId; readonly label: string }>
  value: TId
  onChange: (id: TId) => void
}) {
  return (
    <div className="mc-tabs" role="tablist">
      {tabs.map(tab => (
        <button
          key={tab.id}
          type="button"
          role="tab"
          className="mc-tab"
          aria-selected={tab.id === value}
          onClick={() => { onChange(tab.id) }}
        >
          {tab.label}
        </button>
      ))}
    </div>
  )
}

/** The frame every page shares: a title, actions, and the body. */
export function PageFrame({ title, subtitle, actions, children }: {
  title: string
  subtitle?: string
  actions?: ReactNode
  children: ReactNode
}) {
  return (
    <div className="mc-page">
      <header className="mc-head">
        <div>
          <h1 className="mc-title">{title}</h1>
          {subtitle === undefined ? undefined : <p className="mc-subtitle">{subtitle}</p>}
        </div>
        {actions === undefined ? undefined : <div className="mc-actions">{actions}</div>}
      </header>
      {children}
    </div>
  )
}

/** Facts and tables for one collected page. */
export function PanelBody({ data, t, offline, rowActions }: {
  data: PanelData | undefined
  t: T
  offline?: string | undefined
  rowActions?: ((table: Table, row: TableRow) => ReactNode) | undefined
}) {
  const tables = useMemo(() => data === undefined ? [] : data.tables, [data])
  if (data === undefined) return <div className="mc-empty">{offline ?? t('loading')}</div>
  return (
    <>
      {offline === undefined ? undefined : <div className="mc-note">{offline}</div>}
      {data.facts.length === 0 ? undefined : (
        <div className="mc-facts">{data.facts.map(fact => <FactCard key={fact.label} fact={fact} />)}</div>
      )}
      {tables.map(table => (
        <DataTable
          key={table.title}
          table={table}
          t={t}
          rowActions={rowActions === undefined ? undefined : row => rowActions(table, row)}
        />
      ))}
      {data.notes.map(note => <div key={note} className="mc-note">{note}</div>)}
      {data.facts.length === 0 && tables.length === 0 && <div className="mc-empty">{t('noRows')}</div>}
    </>
  )
}

/** The result of the last action the reader ran, with a dismiss. */
export function ActionBanner({ report, t, onDismiss }: {
  report: { readonly ok: boolean; readonly title: string; readonly text: string }
  t: T
  onDismiss: () => void
}) {
  return (
    <div className={`mc-banner${report.ok ? '' : ' mc-banner-error'}`}>
      <div className="mc-banner-head">
        <span>{report.title}</span>
        <button type="button" className="mc-button mc-small" onClick={onDismiss}>{t('dismiss')}</button>
      </div>
      {report.text}
    </div>
  )
}

/** A small copy-on-click button for a command line. */
export function CopyButton({ text, label, copiedLabel }: { text: string; label: string; copiedLabel: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      type="button"
      className="mc-button"
      onClick={() => {
        void navigator.clipboard.writeText(text).then(() => {
          setCopied(true)
          setTimeout(() => { setCopied(false) }, 1500)
        }, () => { setCopied(false) })
      }}
    >
      {copied ? copiedLabel : label}
    </button>
  )
}
