/** Presentational pieces for the QNX pages, styled with the Harness theme tokens so they sit inside its interface. */
import type { ReactNode } from 'react'
import type { AuditEntry, State } from './api.ts'
import type { T } from './locales.ts'

/** The stylesheet every page needs; inserted once by the client entry. */
export const STYLES = `
.qx-page { display: flex; flex-direction: column; gap: 22px; padding: 24px 28px 48px; height: 100%; overflow: auto; box-sizing: border-box;
  color: var(--dsw-alias-text-primary); --qx-allow: #d97706; --qx-deny: #dc2626; --qx-verified: #0891b2; --qx-line: rgba(127,127,127,.24); }
@media (prefers-color-scheme: dark) { .qx-page { --qx-allow: #f59e0b; --qx-deny: #f87171; --qx-verified: #22d3ee; } }
.qx-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
.qx-title { font-size: 20px; font-weight: 600; margin: 0; }
.qx-subtitle { font-size: 13px; color: var(--dsw-alias-text-secondary); margin: 4px 0 0; max-width: 72ch; }
.qx-gauges { display: flex; flex-wrap: wrap; gap: 10px 22px; }
.qx-gauge { display: grid; line-height: 1.2; }
.qx-gauge b { font-size: 16px; font-weight: 650; font-variant-numeric: tabular-nums; }
.qx-gauge span { font-size: 12px; color: var(--dsw-alias-text-secondary); }
.qx-good b { color: var(--qx-verified); } .qx-bad b { color: var(--qx-deny); } .qx-warn b { color: var(--qx-allow); }
.qx-note { font-size: 12.5px; padding: 9px 13px; border-radius: 8px; color: var(--dsw-alias-text-secondary); border: 1px solid var(--qx-line); background: rgba(127,127,127,.06); }
.qx-note.qx-error { border-color: var(--qx-deny); color: var(--dsw-alias-text-primary); }
.qx-split { display: grid; grid-template-columns: minmax(300px, 38%) 1fr; gap: 24px; min-height: 0; }
@media (max-width: 980px) { .qx-split { grid-template-columns: 1fr; } }
.qx-section { display: flex; flex-direction: column; gap: 10px; min-width: 0; }
.qx-h2 { font-size: 15px; font-weight: 600; margin: 0; }
.qx-hint { font-size: 12.5px; color: var(--dsw-alias-text-secondary); margin: 0; max-width: 72ch; }
.qx-row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.qx-button { font: inherit; font-size: 13px; padding: 6px 12px; border-radius: 8px; cursor: pointer; border: 1px solid var(--dsw-alias-border-default, rgba(127,127,127,.35));
  background: transparent; color: var(--dsw-alias-text-primary); }
.qx-button:hover:not([disabled]) { background: rgba(127,127,127,.14); }
.qx-button[disabled] { opacity: .55; cursor: progress; }
.qx-button.qx-primary { border-color: var(--qx-allow); color: var(--qx-allow); font-weight: 600; }
.qx-meta { font-size: 12.5px; color: var(--dsw-alias-text-secondary); }
.qx-input, .qx-code { font: inherit; font-size: 13px; padding: 8px 10px; border-radius: 8px; border: 1px solid rgba(127,127,127,.35); background: transparent; color: var(--dsw-alias-text-primary); }
.qx-input { flex: 1; min-width: 180px; }
.qx-code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px; line-height: 1.5; width: 100%; min-height: 140px; resize: vertical; box-sizing: border-box; tab-size: 2; }
.qx-out { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; white-space: pre-wrap; word-break: break-word; max-height: 320px; overflow: auto;
  padding: 10px 12px; border-radius: 8px; border: 1px solid var(--qx-line); border-left: 3px solid var(--qx-line); background: rgba(127,127,127,.06); }
.qx-out.qx-ok { border-left-color: var(--qx-allow); } .qx-out.qx-fail { border-left-color: var(--qx-deny); }
.qx-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
/* the gate tape */
.qx-tape { border: 1px solid var(--qx-line); border-radius: 10px; max-height: calc(100vh - 230px); min-height: 280px; overflow: auto; }
.qx-e { position: relative; padding: 8px 14px 9px 32px; border-top: 1px solid var(--qx-line); font-size: 13px; }
.qx-e:first-child { border-top: none; }
.qx-e::before { content: ""; position: absolute; left: 15px; top: 0; bottom: 0; width: 2px; background: var(--qx-line); }
.qx-e::after { content: ""; position: absolute; left: 11px; top: 13px; width: 8px; height: 8px; border-radius: 50%; border: 2px solid var(--dsw-alias-text-secondary); background: var(--dsw-alias-bg-primary, transparent); }
.qx-e.qx-allow::after { border-color: var(--qx-allow); background: var(--qx-allow); }
.qx-e.qx-deny::after { border-color: var(--qx-deny); }
.qx-e.qx-deny { background: linear-gradient(90deg, rgba(220,38,38,.08), transparent 70%); }
.qx-e.qx-verdict::after { border-color: var(--qx-verified); }
.qx-e.qx-meta-e { display: flex; gap: 8px; color: var(--dsw-alias-text-secondary); font-size: 12px; padding-top: 5px; padding-bottom: 5px; }
.qx-e.qx-meta-e::after { width: 4px; height: 4px; left: 13px; top: 11px; border-width: 0; background: var(--qx-line); }
.qx-e-top { display: flex; gap: 8px; align-items: baseline; }
.qx-e-what { font-weight: 600; }
.qx-allow .qx-e-what { color: var(--qx-allow); } .qx-deny .qx-e-what { color: var(--qx-deny); }
.qx-e-seq { margin-left: auto; color: var(--dsw-alias-text-secondary); font-size: 11.5px; font-variant-numeric: tabular-nums; }
.qx-e-argv { display: block; word-break: break-all; margin-top: 2px; }
.qx-e-why { margin-top: 2px; color: var(--dsw-alias-text-secondary); }
.qx-deny .qx-e-why { color: var(--dsw-alias-text-primary); }
.qx-e-link { margin-top: 2px; color: var(--dsw-alias-text-secondary); font-size: 11px; }
.qx-tag { display: inline-block; margin: 3px 6px 0 0; padding: 0 6px; border-radius: 4px; font-size: 11.5px; border: 1px solid var(--qx-line); }
.qx-tag.qx-in { border-color: var(--qx-verified); color: var(--qx-verified); } .qx-tag.qx-out { border-color: var(--qx-deny); color: var(--qx-deny); }
/* tables */
.qx-table { border-collapse: collapse; width: 100%; font-size: 13px; }
.qx-table th { text-align: left; font-weight: 600; font-size: 12px; padding: 7px 10px 7px 0; color: var(--dsw-alias-text-secondary); border-bottom: 1px solid var(--qx-line); }
.qx-table td { padding: 8px 10px 8px 0; border-bottom: 1px solid rgba(127,127,127,.12); vertical-align: top; }
.qx-ex { display: block; margin-top: 3px; color: var(--dsw-alias-text-secondary); white-space: pre-wrap; word-break: break-all; }
.qx-sev-high, .qx-sev-critical { color: var(--qx-deny); font-weight: 600; } .qx-sev-medium { color: var(--qx-allow); font-weight: 600; } .qx-sev-low, .qx-sev-info { color: var(--dsw-alias-text-secondary); font-weight: 600; }
.qx-v-CONFIRMED { color: var(--qx-verified); font-weight: 650; } .qx-v-REFUTED { color: var(--qx-deny); font-weight: 650; } .qx-v-UNPROVEN { color: var(--qx-allow); font-weight: 650; }
.qx-v-OPEN, .qx-v-LOCKED { color: var(--dsw-alias-text-secondary); }
.qx-stubs { list-style: none; margin: 0; padding: 0; }
.qx-stubs li { padding: 7px 0; border-top: 1px solid var(--qx-line); font-size: 13px; }
.qx-stubs .qx-off .qx-n { color: var(--dsw-alias-text-secondary); text-decoration: line-through; text-decoration-color: var(--qx-deny); }
.qx-n { font-weight: 600; }
.qx-facts { display: grid; grid-template-columns: max-content 1fr; gap: 6px 18px; margin: 0; font-size: 13px; }
.qx-facts dt { color: var(--dsw-alias-text-secondary); } .qx-facts dd { margin: 0; overflow-wrap: anywhere; }
.qx-signed { padding: 10px 13px; border-radius: 8px; border: 1px solid var(--qx-verified); font-size: 13px; }
.qx-form { display: flex; flex-wrap: wrap; gap: 8px; align-items: flex-end; }
.qx-form label { display: flex; flex-direction: column; gap: 4px; font-size: 12px; color: var(--dsw-alias-text-secondary); }
.qx-form .qx-input { min-width: 140px; }
.qx-link { color: var(--qx-verified); font-size: 13px; }
`

/** The identity bar shared by every page: what the target is and the state of the gate. */
export function TargetBar({ state, t, title, subtitle }: { state: State; t: T; title: string; subtitle: string }) {
  const s = state
  const os = s.target.os === 'QNX' ? `QNX ${s.target.qnx_version ?? s.target.release} · ${s.target.machine}` : `${s.target.os} ${s.target.release} · ${s.target.machine}`
  const netDenied = /denied/.test(s.policy.sandbox.network)
  return (
    <>
      <header className="qx-head">
        <div>
          <h1 className="qx-title">{title}</h1>
          <p className="qx-subtitle">{t('targetLabel')}: <b>{s.target.hostname}</b>, {os}. {subtitle}</p>
        </div>
        <div className="qx-gauges">
          <Gauge value={`${String(s.policy.destructive_mode === 'ask' ? (s.catalog.free ?? s.catalog.visible) : s.catalog.visible)} / ${String(s.catalog.tools)}`} label={s.policy.destructive_mode === 'ask' ? t('callableAsk') : t('callable')} />
          <Gauge value={s.policy.destructive_mode === 'ask' ? t('askEach') : s.policy.allow_destructive ? t('enabled') : t('off')} label={t('destructive')} tone={s.policy.destructive_mode === 'ask' ? 'warn' : s.policy.allow_destructive ? 'bad' : 'good'} />
          <Gauge value={String(s.engagements.verified.length)} label={t('engagements')} />
          <Gauge value={s.audit.ok ? t('intact') : t('broken')} label={`${t('chain')}, ${String(s.audit.count)} ${t('entries')}`} tone={s.audit.ok ? 'good' : 'bad'} />
          <Gauge value={netDenied ? t('denied') : t('notOsDenied')} label={t('sandboxNet')} tone={netDenied ? 'good' : 'warn'} />
        </div>
      </header>
      {s.bundle.target === 'standin' || s.target.os !== 'QNX' ? <p className="qx-note">{t('standin')}</p> : undefined}
    </>
  )
}

function Gauge({ value, label, tone }: { value: string; label: string; tone?: 'good' | 'bad' | 'warn' }) {
  return <div className={`qx-gauge${tone === undefined ? '' : ` qx-${tone}`}`}><b>{value}</b><span>{label}</span></div>
}

/** One entry of the gate tape. */
function TapeEntry({ e, t }: { e: AuditEntry; t: T }) {
  const link = <div className="qx-e-link qx-mono">#{e.seq} {e.prev.slice(0, 8)} → {e.hash.slice(0, 8)}</div>
  const time = <span className="qx-e-seq">{e.ts.slice(11, 19)}</span>
  if (e.kind === 'call') {
    const allow = e.decision === 'allow'
    const deny = e.decision === 'deny'
    return (
      <div className={`qx-e ${allow ? 'qx-allow' : deny ? 'qx-deny' : 'qx-meta-e'}`} data-hash={e.hash}>
        <div className="qx-e-top"><span className="qx-e-what">{allow ? t('allowed') : deny ? t('deniedWord') : t('errorWord')}</span><span>{e.seat ?? ''}</span>{time}</div>
        <code className="qx-e-argv qx-mono">{allow ? (e.argv ?? []).join(' ') : e.tool ?? ''}</code>
        {allow
          ? <div className="qx-e-why">exit {String(e.exit)}, {String(e.stdout_bytes)} B, {String(e.duration_ms)} ms</div>
          : <div className="qx-e-why">{e.reason}{e.spawned === false ? ` — ${t('nothingSpawned')}` : ''}</div>}
        {(e.targets ?? []).map(x => <span key={x.target} className={`qx-tag ${x.in_scope ? 'qx-in' : 'qx-out'}`}>{x.target} {x.in_scope ? t('inScope') : t('outOfScope')}</span>)}
        {link}
      </div>
    )
  }
  if (e.kind === 'board_verdict' && e.ok === true) {
    return (
      <div className="qx-e qx-verdict" data-hash={e.hash}>
        <div className="qx-e-top"><span className={`qx-e-what qx-v-${String(e.verdict)}`}>{String(e.verdict)}</span><span>{e.seat ?? ''}</span>{time}</div>
        <div className="qx-e-why">{String(e.claim).split('#').pop()}</div>
        {link}
      </div>
    )
  }
  if (e.kind === 'board_lock' || e.kind === 'keepalive') return null
  const label: Record<string, string> = {
    execute_start: 'Program started',
    execute_end: `Program ${e.decision === 'allow' ? 'finished' : `aborted (${String(e.decision)})`} after ${String(e.calls)} ${e.calls === 1 ? 'call' : 'calls'}`,
    search: `Search "${String(e.query)}"`,
    list: 'Listed tools',
    gateway_start: `Engine started: ${String(e.visible_tools)} of ${String(e.catalog_tools)} tools callable`,
    report: `Signed ${String(e.report_kind)} report: ${String(e.findings)} findings`,
    board_post: `Posted ${String(e.added)} ${e.added === 1 ? 'claim' : 'claims'}`,
    smith_run: 'Agent Smith finished',
    board_reset: 'Board cleared',
  }
  return <div className="qx-e qx-meta-e" data-hash={e.hash}>{label[e.kind] ?? e.kind}<span className="qx-e-seq">#{e.seq}</span></div>
}

/** The live, hash-linked feed of every gate decision. */
export function GateTape({ entries, t }: { entries: ReadonlyArray<AuditEntry>; t: T }) {
  return (
    <div className="qx-tape" role="log" aria-live="polite" aria-label={t('tape')}>
      {entries.length === 0 ? <p className="qx-note" style={{ margin: 12 }}>{t('tapeEmpty')}</p> : entries.map(e => <TapeEntry key={e.seq} e={e} t={t} />)}
    </div>
  )
}

/** Scroll the tape to one receipt and flash it. */
export function jumpTo(hash: string): void {
  const el = document.querySelector(`.qx-tape [data-hash="${CSS.escape(hash)}"]`)
  if (el instanceof HTMLElement) {
    el.scrollIntoView({ block: 'center', behavior: 'smooth' })
    el.animate?.([{ backgroundColor: 'rgba(8,145,178,.22)' }, { backgroundColor: 'transparent' }], { duration: 1400 })
  }
}

/** The page shell: shows the engine's state or why it is not running. */
export function Frame({ state, error, t, children }: { state: State | undefined; error: Error | undefined; t: T; children: (s: State) => ReactNode }) {
  if (state !== undefined) return <div className="qx-page">{children(state)}</div>
  return (
    <div className="qx-page">
      <h1 className="qx-title">{t('target')}</h1>
      {error === undefined ? <p className="qx-note">{t('starting')}</p> : <p className="qx-note qx-error"><b>{t('notRunning')}.</b> {error.message}</p>}
    </div>
  )
}
