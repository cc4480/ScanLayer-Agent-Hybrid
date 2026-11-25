/**
 * The agent tools this bundle contributes. The model gets the QNX target the Code Mode way: two tools, `qnx_search` and
 * `qnx_execute`. Every `tools.*` call a program makes goes through the engine's gate (catalog, destructive-off, argument
 * rules, protected paths, scope) before anything reaches the target, and lands in the audit chain the sidebar shows.
 */
import type { Context } from '@deepseek-ai/cordis'
import type { ToolOutputDefinition } from '@deepseek-ai/dsh-tools'
import type { Engine } from './engine.ts'

/** The seat the Harness agent acts as; it shows on every audit line it causes. */
export const AGENT_SEAT = 'harness'

/** The QNX section added to the system prompt; fixed text from this plugin. */
const GUIDE = [
  '## QNX 8.0 target',
  '',
  'A QNX target (QEMU x86_64, or the Linux stand-in before the SDP is installed) is attached. You reach it through two tools:',
  '',
  '- qnx_search: find tools on the target by intent ("open ports", "process threads", "slog2 logs"). It returns typed stubs',
  '  like `netstat(args?: string[], opts?) -> {exit, stdout, stderr, receipt}`. Destructive tools are listed but not callable.',
  '- qnx_execute: run a JavaScript async function body. Call stubs as `await tools.netstat(["-an"])`. Globals: `catalog`',
  '  (target meta, processes, listeners, /dev resource managers), `manifest` (what the image declares), and `parse`',
  '  (`parse.listeners`, `parse.processes`, `parse.lsl`, `parse.lines`) for QNX io-sock/pidin output. Only your `return`',
  '  value comes back (40,000 chars max), so filter and summarize inside the program. There is no network, file system,',
  '  require or eval in the program.',
  '',
  '',
  'The security audit is available inside qnx_execute as `qnx`: `await qnx.checks()` lists the checks, `await qnx.scan()`',
  'runs them all and signs a scan report, `await qnx.verify()` has Agent Smith (a separate seat) reproduce every finding,',
  'and `await qnx.report()` signs the verified report with only the confirmed findings. A full audit is one program:',
  '`const scan = await qnx.scan(); const verified = await qnx.verify(); return { scan, verified, report: await qnx.report() }`',
  'with timeout_ms 300000. Report confirmed findings with their receipts; say which claims were refuted or unproven.',
  '',
  'Scope: the target itself is always in scope. Any other address, host, CIDR or Qnet node (`/net/<node>/...`, `on -n`)',
  'needs an engagement the operator signed. A call outside scope, a destructive tool, or a refused argument aborts the run',
  'with `scope_denied`. Report that plainly; never try to work around it. Destructive tools are off by default; when the',
  'operator sets them to ask, each such call shows the user an approval prompt and runs only if they allow it. Every call',
  'and denial is in a hash-chained audit log the user can see in the QNX sidebar pages, so cite the receipt.',
].join('\n')

/** The qnx-audit skill: the full audit, step by step, for the model or the user to invoke. */
export const AUDIT_SKILL = {
  name: 'qnx-audit',
  description: 'Run a full security audit of the attached QNX 8.0 target: the native checks, independent verification by Agent Smith, and a signed report of confirmed findings with receipts.',
  content: [
    '# QNX security audit',
    '',
    'Use the qnx_execute tool. Run the whole audit as one program, with timeout_ms 300000:',
    '',
    '```js',
    'const scan = await qnx.scan()          // all checks, signed scan report',
    'const verified = await qnx.verify()   // Agent Smith reproduces each finding from its own seat',
    'const report = await qnx.report()     // signed report with only the confirmed findings',
    'return { counts: scan.counts, checks: scan.checks, verdicts: verified.claims, confirmed: report.confirmed, signature: report.signature, chain: report.audit }',
    '```',
    '',
    'Then answer the user with:',
    '1. The target (QNX version, or that it is the stand-in) and whether the audit chain verified.',
    '2. Each CONFIRMED finding: severity, title, and its receipt number. Lead with high severity.',
    '3. The claims that were REFUTED or UNPROVEN, and why, in one line each. They are not findings.',
    '4. Where to see the evidence: the Scan & verify page in the sidebar, which also opens the signed report.',
    '',
    'Never claim a finding that is not CONFIRMED. If a check failed to run, say which one and why.',
  ].join('\n'),
}

/** Holds the agent whose qnx_execute call is running, so an approval prompt is asked on its behalf. */
export const running: { agent: unknown } = { agent: undefined }

const SEARCH_PARAMETERS = {
  type: 'object',
  properties: {
    query: { type: 'string', description: 'What you want to do on the target, e.g. "open ports" or "process threads".' },
    names: { type: 'array', items: { type: 'string' }, description: 'Exact tool names to fetch stubs for.' },
    limit: { type: 'integer', minimum: 1, maximum: 20, description: 'Most stubs to return (default 8).' },
  },
  additionalProperties: false,
}

const EXECUTE_PARAMETERS = {
  type: 'object',
  properties: {
    program: { type: 'string', description: 'Async JavaScript function body. Call tools as `await tools.<ident>(args)`; `return` the answer.' },
    timeout_ms: { type: 'integer', minimum: 100, maximum: 300000, description: 'Wall-clock budget for the whole program (default 120000).' },
  },
  required: ['program'],
  additionalProperties: false,
}

function text(value: unknown): string {
  return typeof value === 'string' ? value : JSON.stringify(value, undefined, 2)
}

/**
 * Register qnx_search and qnx_execute.
 * @param ctx - the plugin context.
 * @param engine - the running engine, read at call time.
 * @returns disposers.
 */
export function registerTools(ctx: Context, engine: () => Engine | undefined): Array<() => void> {
  const textOutput: ToolOutputDefinition = { schema: { type: 'string' }, render: (_args: unknown, value: unknown) => [{ type: 'text', text: String(value) }] }
  const need = (): Engine => {
    const e = engine()
    if (e === undefined) throw new Error('The QNX engine is not running. Open the QNX target page in the sidebar to see why.')
    return e
  }
  const tools = [
    {
      name: 'qnx_search',
      description: 'Find tools on the attached QNX target by intent and get typed stubs to call inside qnx_execute.',
      parameters: SEARCH_PARAMETERS,
      output: textOutput,
      execute: async (args: unknown) => {
        const input = (typeof args === 'object' && args !== null ? args : {}) as { query?: unknown; names?: unknown; limit?: unknown }
        const query = typeof input.query === 'string' ? input.query : ''
        const names = Array.isArray(input.names) ? input.names.filter((n): n is string => typeof n === 'string') : undefined
        if (query.trim() === '' && (names === undefined || names.length === 0)) throw new Error('Give a query or names.')
        const e = need()
        const result = e.search({ query, ...(names === undefined ? {} : { names }), limit: typeof input.limit === 'number' ? input.limit : 8 })
        e.audit.append({ kind: 'search', seat: AGENT_SEAT, tool: 'codemode.search', query: query.slice(0, 200), matches: result.matches.map(m => m.name) })
        return text(result)
      },
    },
    {
      name: 'qnx_execute',
      description: 'Run a JavaScript program against the QNX target. Its tools.* calls go through the scope gate and are receipted; qnx.scan()/verify()/report() run the security audit. Only the return value comes back.',
      parameters: EXECUTE_PARAMETERS,
      output: textOutput,
      execute: async (args: unknown, run?: { agent?: unknown }) => {
        const input = (typeof args === 'object' && args !== null ? args : {}) as { program?: unknown; timeout_ms?: unknown }
        if (typeof input.program !== 'string' || input.program.trim() === '') throw new Error('program must be a non-empty string.')
        running.agent = run?.agent
        const r = await need().execute(AGENT_SEAT, input.program, typeof input.timeout_ms === 'number' ? input.timeout_ms : undefined)
        if (r.invalid !== undefined) throw new Error(r.invalid)
        if (r.ok === true) return text({ value: r.value, truncated: r.truncated, calls: r.calls, receipt: r.receipt })
        return text({ error: r.error, calls: r.calls, receipt: r.receipt })
      },
    },
  ]
  return tools.map(tool => ctx.tools.register({
    name: tool.name,
    description: tool.description,
    parameters: tool.parameters,
    output: tool.output,
    execute: tool.execute,
  } as never))
}

/** Add the QNX section to the system prompt. */
export function registerGuide(ctx: Context): () => void {
  return ctx.systemPrompt.section({ name: 'qnx-agent', order: 61, text: GUIDE })
}
