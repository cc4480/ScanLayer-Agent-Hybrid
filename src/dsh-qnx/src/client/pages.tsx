/** The three sidebar pages: the QNX target with its live gate tape, scan and verification, and scope and proof. */
import { useState, type FormEvent } from 'react'
import { call, useAuditTape, useQnxState, type State } from './api.ts'
import type { T } from './locales.ts'
import { Frame, GateTape, TargetBar, jumpTo } from './ui.tsx'

/** Example programs: the same shape the agent writes for qnx_execute. */
const PRESETS: Record<'presetListen' | 'presetProcs' | 'presetScope' | 'presetKill' | 'presetEscape', string> = {
  presetListen: `// Every socket in LISTEN state, parsed from the target's netstat (io-sock on QNX 8).
const r = await tools.netstat(["-an"]);
return parse.listeners(r.stdout).map((l) => l.proto + " " + l.addr + ":" + l.port);`,
  presetProcs: `// QNX: pidin is authoritative; the stand-in uses ps.
const isQNX = catalog.meta.os === "QNX";
const r = isQNX ? await tools.pidin(["arg"]) : await tools.ps(["-A", "-o", "pid=", "-o", "comm="]);
const procs = parse.processes(r.stdout);
return { count: procs.length, names: [...new Set(procs.map((p) => p.name))].slice(0, 40) };`,
  presetScope: `// 198.51.100.23 is not the target and no engagement names it.
// The gate refuses before anything spawns: no process, no packet.
return await tools.ping(["-c", "1", "-W", "1", "198.51.100.23"]);`,
  presetKill: `// slay and kill change the system. On a safety-critical OS they are off
// unless an operator enables destructive tools explicitly.
return await tools.kill(["-TERM", "1"]);`,
  presetEscape: `// Each attempt is caught inside the sandbox; the outcomes come back as data.
const attempt = (f) => { try { return String(f()); } catch (e) { return e.name + ": " + e.message; } };
return {
  fetch: typeof fetch, require: typeof require, process: typeof process,
  eval: attempt(() => eval("1+1")),
  constructorEscape: attempt(() => tools.uname.constructor.constructor("return process")()),
};`,
}

interface RunResult { ok?: boolean; value?: unknown; truncated?: boolean; calls?: number; receipt?: string; error?: { kind: string; code?: string; message: string } }

/** Page 1: the target, the live gate tape, and the two Code Mode tools driven by hand. */
export function TargetPage({ t }: { t: T }) {
  const { data, error } = useQnxState()
  const entries = useAuditTape()
  const [program, setProgram] = useState(PRESETS.presetListen)
  const [result, setResult] = useState<RunResult | { failure: string } | undefined>()
  const [busy, setBusy] = useState(false)
  const [query, setQuery] = useState('')
  const [stubs, setStubs] = useState<Array<{ name: string; class: string; callable: boolean; summary: string; stub: string }> | undefined>()

  const run = async (): Promise<void> => {
    setBusy(true)
    try { setResult(await call<RunResult>('POST', 'execute', { program, timeout_ms: 60000 })) } catch (e) { setResult({ failure: (e as Error).message }) }
    setBusy(false)
  }
  const search = async (event: FormEvent): Promise<void> => {
    event.preventDefault()
    try { setStubs((await call<{ matches: typeof stubs }>('GET', `search?q=${encodeURIComponent(query)}`)).matches) } catch { setStubs([]) }
  }

  return (
    <Frame state={data} error={error} t={t}>
      {(s: State) => (
        <>
          <TargetBar state={s} t={t} title={t('target')} subtitle={t('tapeHint')} />
          <div className="qx-split">
            <section className="qx-section">
              <h2 className="qx-h2">{t('tape')}</h2>
              <GateTape entries={entries} t={t} />
            </section>
            <div className="qx-section" style={{ gap: 26 }}>
              <section className="qx-section">
                <h2 className="qx-h2">{t('drive')}</h2>
                <p className="qx-hint">{t('driveHint')}</p>
                <div className="qx-row">
                  {(Object.keys(PRESETS) as Array<keyof typeof PRESETS>).map(k => (
                    <button key={k} type="button" className="qx-button" onClick={() => { setProgram(PRESETS[k]); setResult(undefined) }}>{t(k)}</button>
                  ))}
                </div>
                <textarea className="qx-code" spellCheck={false} value={program} onChange={e => { setProgram(e.target.value) }} aria-label={t('drive')} />
                <div className="qx-row">
                  <button type="button" className="qx-button qx-primary" disabled={busy} onClick={() => { void run() }}>{busy ? t('running') : t('run')}</button>
                  {result !== undefined && !('failure' in result) ? <span className="qx-meta">{result.ok === true ? t('returned') : t('stopped')} {String(result.calls)} {result.calls === 1 ? t('call') : t('calls')}, {t('receipt')} <span className="qx-mono">{result.receipt?.slice(0, 12)}</span></span> : undefined}
                </div>
                {result === undefined ? undefined : 'failure' in result
                  ? <pre className="qx-out qx-fail">{result.failure}</pre>
                  : <pre className={`qx-out ${result.ok === true ? 'qx-ok' : 'qx-fail'}`}>{result.ok === true
                    ? (typeof result.value === 'string' ? result.value : JSON.stringify(result.value, undefined, 2))
                    : `${result.error?.kind ?? ''}${result.error?.code === undefined ? '' : ` / ${result.error.code}`}\n${result.error?.message ?? ''}`}</pre>}
              </section>
              <section className="qx-section">
                <h2 className="qx-h2">{t('search')}</h2>
                <p className="qx-hint">{t('searchHint')}</p>
                <form className="qx-row" onSubmit={e => { void search(e) }}>
                  <input className="qx-input" value={query} placeholder={t('searchPlaceholder')} onChange={e => { setQuery(e.target.value) }} aria-label={t('search')} />
                  <button className="qx-button" type="submit">{t('searchButton')}</button>
                </form>
                {stubs === undefined ? undefined : stubs.length === 0 ? <p className="qx-note">{t('noMatches')}</p> : (
                  <ul className="qx-stubs">
                    {stubs.map(m => (
                      <li key={m.name} className={m.callable ? '' : 'qx-off'}>
                        <span className="qx-n">{m.name}</span> <span className="qx-meta">{m.class}{m.callable ? '' : ` — ${t('notCallable')}`}</span>
                        <span className="qx-ex">{m.summary}</span>
                        <code className="qx-mono">{m.stub.replace(/ -> Promise<.*$/, '')}</code>
                      </li>
                    ))}
                  </ul>
                )}
              </section>
            </div>
          </div>
        </>
      )}
    </Frame>
  )
}

interface Finding { id: string; severity: string; title: string; evidence: Array<{ receipt: string; tool: string; args?: string[]; excerpt: string; seq?: number }> }
interface Report { findings: Finding[]; rejected: unknown[]; checks: Array<{ check: string; ok: boolean; error?: { message: string } }>; signature: { key_id: string; sig: string } }
interface Claim { id: string; status: string; author_seat: string; finding: Finding; verdict?: { observed?: string; run_receipt?: string } | null }

/** Page 2: the five checks, the claims board and Agent Smith. */
export function ScanPage({ t }: { t: T }) {
  const { data, error } = useQnxState()
  const entries = useAuditTape(120)
  const [report, setReport] = useState<Report | undefined>()
  const [board, setBoard] = useState<Claim[] | undefined>()
  const [verified, setVerified] = useState<{ findings: unknown[]; board: { refuted: number; unproven: number }; audit: { verified: boolean; entries: number }; signature: { sig: string } } | undefined>()
  const [busy, setBusy] = useState<string | undefined>()
  const [message, setMessage] = useState<string | undefined>()

  const loadBoard = async (): Promise<Claim[]> => {
    const d = await call<{ claims: Claim[] }>('GET', 'board')
    setBoard(d.claims)
    return d.claims
  }
  const act = async (name: string, fn: () => Promise<void>): Promise<void> => {
    setBusy(name); setMessage(undefined)
    try { await fn() } catch (e) { setMessage((e as Error).message) }
    setBusy(undefined)
  }
  const runChecks = (): Promise<void> => act('checks', async () => { setReport(await call<Report>('POST', 'checks')); await loadBoard() })
  const startSmith = (): Promise<void> => act('smith', async () => {
    await call('POST', 'smith')
    for (let i = 0; i < 60; i++) {
      await new Promise(r => setTimeout(r, 1000))
      const claims = await loadBoard()
      if (!claims.some(c => c.status === 'OPEN' || c.status === 'LOCKED')) break
    }
  })

  return (
    <Frame state={data} error={error} t={t}>
      {(s: State) => (
        <>
          <TargetBar state={s} t={t} title={t('scan')} subtitle={t('checksHint')} />
          {message === undefined ? undefined : <p className="qx-note qx-error">{message}</p>}
          <div className="qx-split">
            <section className="qx-section">
              <h2 className="qx-h2">{t('tape')}</h2>
              <GateTape entries={entries} t={t} />
            </section>
            <div className="qx-section" style={{ gap: 26 }}>
              <section className="qx-section">
                <h2 className="qx-h2">{t('checks')}</h2>
                <div className="qx-row">
                  <button type="button" className="qx-button qx-primary" disabled={busy !== undefined} onClick={() => { void runChecks() }}>{busy === 'checks' ? t('runningChecks') : t('runChecks')}</button>
                  {report === undefined ? undefined : <span className="qx-meta">{report.findings.length} {t('findings')}, {t('signedWith')} <span className="qx-mono">{report.signature.key_id}</span>, {report.rejected.length} {t('unbacked')}</span>}
                  {report === undefined ? undefined : <a className="qx-link" href="/qnx/api/report/scan.html" target="_blank" rel="noreferrer">{t('openScan')}</a>}
                </div>
                {report === undefined ? undefined : (
                  <>
                    {report.checks.some(c => !c.ok) ? <p className="qx-note qx-error">{t('checkFailed')}: {report.checks.filter(c => !c.ok).map(c => `${c.check} (${c.error?.message ?? ''})`).join(', ')}</p> : undefined}
                    {report.findings.length === 0 ? <p className="qx-note">{t('noFindings')}</p> : (
                      <table className="qx-table">
                        <thead><tr><th>{t('severity')}</th><th>{t('finding')}</th><th>{t('receipt')}</th></tr></thead>
                        <tbody>
                          {report.findings.map(f => {
                            const ev = f.evidence[0]
                            return (
                              <tr key={f.id}>
                                <td className={`qx-sev-${f.severity}`}>{f.severity}</td>
                                <td>{f.title}{ev === undefined ? undefined : <span className="qx-ex qx-mono">{ev.tool} {(ev.args ?? []).join(' ').slice(0, 80)}{'\n'}{ev.excerpt.split('\n')[0]?.slice(0, 160)}</span>}</td>
                                <td>{ev === undefined ? undefined : <button type="button" className="qx-button" style={{ padding: '2px 8px', fontSize: 12 }} onClick={() => { jumpTo(ev.receipt) }}>#{String(ev.seq)}</button>}</td>
                              </tr>
                            )
                          })}
                        </tbody>
                      </table>
                    )}
                  </>
                )}
              </section>
              <section className="qx-section">
                <h2 className="qx-h2">{t('verify')}</h2>
                <p className="qx-hint">{t('verifyHint')}</p>
                <div className="qx-row">
                  <button type="button" className="qx-button" disabled={busy !== undefined} onClick={() => { void act('post', async () => { await call('POST', 'board/post'); await loadBoard() }) }}>{t('post')}</button>
                  <button type="button" className="qx-button" disabled={busy !== undefined} onClick={() => { void act('plant', async () => { await call('POST', 'board/plant'); await loadBoard() }) }}>{t('plant')}</button>
                  <button type="button" className="qx-button qx-primary" disabled={busy !== undefined} onClick={() => { void startSmith() }}>{busy === 'smith' ? t('reproducing') : t('smith')}</button>
                  <button type="button" className="qx-button" disabled={busy !== undefined} onClick={() => { void act('verified', async () => { setVerified(await call('POST', 'report/verified')) }) }}>{t('signVerified')}</button>
                  <button type="button" className="qx-button" disabled={busy !== undefined} onClick={() => { void act('reset', async () => { await call('POST', 'board/reset'); setVerified(undefined); await loadBoard() }) }}>{t('clearBoard')}</button>
                </div>
                {board === undefined || board.length === 0 ? <p className="qx-note">{t('boardEmpty')}</p> : (
                  <table className="qx-table">
                    <thead><tr><th>{t('claim')}</th><th>{t('status')}</th><th>{t('observed')}</th></tr></thead>
                    <tbody>
                      {board.map(c => (
                        <tr key={c.id}>
                          <td>{c.finding.title}<span className="qx-ex">{t('by')} {c.author_seat}</span></td>
                          <td className={`qx-v-${c.status}`}>{c.status}</td>
                          <td>{c.verdict?.observed ?? (c.status === 'LOCKED' ? t('reproducing') : t('waiting'))}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                {verified === undefined ? undefined : (
                  <p className="qx-signed"><b>{t('verifiedDone')}</b> {verified.findings.length} {t('confirmedFindings')}; {verified.board.refuted + verified.board.unproven} {t('leftOut')}. {t('chain')}: {verified.audit.verified ? t('intact') : t('broken')}, {verified.audit.entries} {t('entries')}. <span className="qx-mono">{verified.signature.sig.slice(0, 40)}…</span> <a className="qx-link" href="/qnx/api/report/verified.html" target="_blank" rel="noreferrer">{t('openVerified')}</a></p>
                )}
              </section>
            </div>
          </div>
        </>
      )}
    </Frame>
  )
}

/** Page 3: what the agent may reach, and the proof that history was not edited. */
export function ProofPage({ t }: { t: T }) {
  const { data, error, reload } = useQnxState()
  const [out, setOut] = useState<{ ok: boolean; text: string } | undefined>()
  const [engage, setEngage] = useState({ id: '', targets: '', hours: '24' })
  const [note, setNote] = useState<{ ok: boolean; text: string } | undefined>()
  const act = async (fn: () => Promise<string>): Promise<void> => {
    try { setNote({ ok: true, text: await fn() }) } catch (e) { setNote({ ok: false, text: (e as Error).message }) }
    await reload()
  }
  const sign = (event: FormEvent): Promise<void> => {
    event.preventDefault()
    return act(async () => {
      const r = await call<{ id: string; targets: string[]; expires_at: string }>('POST', 'engagements/add', { id: engage.id.trim(), targets: engage.targets.split(/[\s,]+/).filter(Boolean), hours: Number(engage.hours) })
      setEngage({ id: '', targets: '', hours: '24' })
      return `${t('engageSigned')}: ${r.id} (${r.targets.join(', ')}) ${t('until')} ${r.expires_at}`
    })
  }
  return (
    <Frame state={data} error={error} t={t}>
      {(s: State) => (
        <>
          <TargetBar state={s} t={t} title={t('proof')} subtitle={t('integrityHint')} />
          <section className="qx-section">
            <h2 className="qx-h2">{t('scope')}</h2>
            <p className="qx-hint">{t('scopeHint')}</p>
            <dl className="qx-facts">
              <dt>{t('always')}</dt><dd className="qx-mono">{s.policy.self_scope.join(', ')}</dd>
              <dt>{t('engagements')}</dt>
              <dd>
                {s.engagements.verified.length === 0 ? t('noEngagements') : s.engagements.verified.map(e => (
                  <div key={e.id}><b>{e.id}</b>: <span className="qx-mono">{e.targets.join(', ')}</span> {t('until')} {e.expires_at ?? '—'}{' '}
                    <button type="button" className="qx-button" style={{ padding: '1px 8px', fontSize: 12 }} onClick={() => { void act(async () => { await call('POST', 'engagements/revoke', { id: e.id }); return `${t('revoked')}: ${e.id}` }) }}>{t('revoke')}</button>
                  </div>
                ))}
                {s.engagements.rejected.length === 0 ? undefined : <div>{t('rejected')}: {s.engagements.rejected.map(r => `${r.id} (${r.reason})`).join(', ')}</div>}
              </dd>
              <dt>{t('sandbox')}</dt><dd>{s.policy.sandbox.process}. Network: {s.policy.sandbox.network}.</dd>
              <dt>{t('listeners')}</dt><dd className="qx-mono">{s.catalog.listeners.map(l => `${l.proto} ${l.addr}:${String(l.port)}`).join(', ') || '—'}</dd>
              <dt>{t('verifierPort')}</dt><dd className="qx-mono">{s.bundle.mcp === undefined ? '—' : `${s.bundle.mcp}/mcp`}</dd>
            </dl>
            <h3 className="qx-h2" style={{ fontSize: 14, marginTop: 8 }}>{t('engageAdd')}</h3>
            <p className="qx-hint">{t('engageHint')}</p>
            <form className="qx-form" onSubmit={e => { void sign(e) }}>
              <label>{t('engageId')}<input className="qx-input" value={engage.id} placeholder="lab" onChange={e => { setEngage({ ...engage, id: e.target.value }) }} /></label>
              <label style={{ flex: 1 }}>{t('engageTargets')}<input className="qx-input" value={engage.targets} placeholder="10.0.2.0/24, qnet:ecu2" onChange={e => { setEngage({ ...engage, targets: e.target.value }) }} /></label>
              <label>{t('engageHours')}<input className="qx-input" style={{ minWidth: 70, width: 80 }} type="number" min="1" max="720" value={engage.hours} onChange={e => { setEngage({ ...engage, hours: e.target.value }) }} /></label>
              <button className="qx-button qx-primary" type="submit">{t('engageSign')}</button>
            </form>
            <div className="qx-row" style={{ marginTop: 6 }}>
              <button type="button" className="qx-button" onClick={() => { void act(async () => { const r = await call<{ tools: number; callable: number; free: number }>('POST', 'catalog/refresh'); return `${t('refreshed')}: ${String(r.tools)} tools, ${String(r.free)} callable freely` }) }}>{t('refresh')}</button>
              <span className="qx-meta">{t('refreshHint')}</span>
            </div>
            {note === undefined ? undefined : <p className={`qx-note${note.ok ? '' : ' qx-error'}`}>{note.text}</p>}
          </section>
          <section className="qx-section">
            <h2 className="qx-h2">{t('integrity')}</h2>
            <dl className="qx-facts">
              <dt>{t('chain')}</dt><dd>{s.audit.ok ? t('intact') : `${t('broken')} (line ${String(s.audit.bad_line)}: ${String(s.audit.reason)})`}, {s.audit.count} {t('entries')}</dd>
              <dt>{t('head')}</dt><dd className="qx-mono">{s.audit.head}</dd>
              <dt>{t('signingKey')}</dt><dd className="qx-mono">{s.signing_key.key_id} (ed25519)</dd>
            </dl>
            <div className="qx-row">
              <button type="button" className="qx-button" onClick={() => { void reload().then(() => { setOut({ ok: s.audit.ok, text: s.audit.ok ? `${t('chainOk')}\n${String(s.audit.count)} ${t('entries')}, head ${s.audit.head}` : `${t('chainBroken')} ${String(s.audit.bad_line)}: ${String(s.audit.reason)}` }) }) }}>{t('verifyChain')}</button>
              <button type="button" className="qx-button" onClick={() => { void call<Record<string, unknown>>('GET', 'seal').then(seal => { setOut({ ok: true, text: JSON.stringify(seal, undefined, 2) }) }, (e: Error) => { setOut({ ok: false, text: e.message }) }) }}>{t('getSeal')}</button>
            </div>
            {out === undefined ? undefined : <pre className={`qx-out ${out.ok ? 'qx-ok' : 'qx-fail'}`}>{out.text}</pre>}
          </section>
        </>
      )}
    </Frame>
  )
}
