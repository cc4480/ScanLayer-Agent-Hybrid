// Applies the BUILT Host half (lib/index.js) to a recording Harness context and calls the registered agent tools the way
// the agent loop does. Proves: the bundle registers exactly qnx_search and qnx_execute plus a system-prompt section and the
// /qnx panel route, and the tools reach the real engine and gate.
// Run after `pnpm build`:  node --test test/bundle.test.mjs   (uses the stand-in target; ports 7781/8095 must be free)
import test from 'node:test'
import assert from 'node:assert/strict'
import { apply, TOOL_NAMES } from '../lib/index.js'

const tools = new Map()
const sections = []
const routes = []
const effects = []
const logs = []
const skills = []
let approvalAnswer
const ctx = {
  get: (name) => name === 'approval' && approvalAnswer !== undefined ? { request: async (req) => { approvalAnswer.asked = req; return approvalAnswer.outcome } } : name === 'agents' ? { list: () => [{ id: 'agent-1' }] } : undefined,
  tools: { register: t => { tools.set(t.name, t); return () => tools.delete(t.name) } },
  systemPrompt: { section: s => { sections.push(s); return () => {} } },
  logger: { info: (...a) => logs.push(a), warn: (...a) => logs.push(['WARN', ...a]) },
  effect: (fn) => { const d = fn(); effects.push(d); return d },
  inject: (_names, cb) => cb({ webServer: { getOrigin: () => 'http://127.0.0.1:3999', register: r => { routes.push(r); return () => {} } }, skills: { register: s => { skills.push(s); return () => {} } }, effect: (fn) => effects.push(fn()) }),
}

const waitForEngine = async () => {
  for (let i = 0; i < 100; i++) {
    try { await tools.get('qnx_search').execute({ query: 'ports' }); return } catch (e) { if (!/not running/.test(e.message)) throw e }
    await new Promise(r => setTimeout(r, 200))
  }
  throw new Error('engine did not start: ' + JSON.stringify(logs.filter(l => l[0] === 'WARN')))
}

test.before(async () => {
  apply(ctx, { target: 'standin', engineConfig: '', destructive: 'ask', tools: true, guide: true, maxBodyBytes: 262144 })
  await waitForEngine()
})
test.after(() => { for (const d of effects) if (typeof d === 'function') d() })

test('registers exactly two agent tools, a system-prompt section, and the /qnx panel route', () => {
  assert.deepEqual([...tools.keys()].sort(), [...TOOL_NAMES].sort())
  assert.deepEqual([...tools.keys()].sort(), ['qnx_execute', 'qnx_search'])
  assert.equal(sections.length, 1)
  assert.match(sections[0].text, /QNX 8\.0 target/)
  assert.equal(routes.length, 1)
  assert.equal(routes[0].path, '/qnx')
  assert.equal(routes[0].auth, 'required')
  assert.deepEqual(skills.map(s => s.name), ['qnx-audit'])
  assert.match(skills[0].content, /qnx\.scan\(\)/)
  assert.match(sections[0].text, /qnx\.verify\(\)/)
})

// Call a panel route the way the browser does (same-origin) and return [status, body].
async function panel(method, path, body) {
  const chunks = body === undefined ? [] : [Buffer.from(JSON.stringify(body))]
  const req = { url: `/qnx/api/${path}`, method, headers: { host: '127.0.0.1:3999' }, async *[Symbol.asyncIterator]() { yield* chunks } }
  const res = { status: 0, body: '', headers: {}, writeHead(s, h) { this.status = s; this.headers = h ?? {} }, end(b) { this.body = String(b ?? '') }, write() {} }
  await routes[0].handler(req, res)
  return [res.status, res.headers['content-type']?.startsWith('application/json') ? JSON.parse(res.body) : res.body]
}

test('destructive tools in ask mode: the agent is asked through the approval prompt; a run from the page is the operator\'s', async () => {
  approvalAnswer = { outcome: 'denied' }
  const no = JSON.parse(await tools.get('qnx_execute').execute({ program: 'return await tools.kill(["-0", "1"])' }, { agent: { id: 'agent-1' } }))
  assert.equal(no.error.code, 'not_approved')
  assert.equal(approvalAnswer.asked.toolName, 'qnx: kill')
  assert.match(approvalAnswer.asked.reason, /kill -0 1/)
  approvalAnswer = { outcome: 'allowed-once' }
  const yes = JSON.parse(await tools.get('qnx_execute').execute({ program: 'const r = await tools.kill(["-0", "1"]); return r.exit' }, { agent: { id: 'agent-1' } }))
  assert.equal(yes.value, 0)
  approvalAnswer = undefined
  const none = JSON.parse(await tools.get('qnx_execute').execute({ program: 'return await tools.kill(["-0", "1"])' }))
  assert.match(none.error.message, /no approval prompt is available/)
  const [status, page] = await panel('POST', 'execute', { program: 'const r = await tools.kill(["-0", "1"]); return r.exit' })
  assert.equal(status, 200)
  assert.equal(page.value, 0, 'the operator running it from the page is the approval')
})

test('the panel signs and revokes engagements, refreshes the catalog, and serves the report as HTML', async () => {
  const [bad, err] = await panel('POST', 'engagements/add', { id: 'lab', targets: ['nope!'] })
  assert.equal(bad, 400); assert.match(err.error, /not a valid target/)
  const [ok, e] = await panel('POST', 'engagements/add', { id: 'lab', targets: ['192.0.2.0/24'], hours: 1 })
  assert.equal(ok, 200); assert.deepEqual(e.targets, ['192.0.2.0/24'])
  const [, state] = await panel('GET', 'state')
  assert.ok(state.engagements.verified.some(x => x.id === 'lab'))
  assert.equal(state.policy.destructive_mode, 'ask')
  assert.deepEqual((await panel('POST', 'engagements/revoke', { id: 'lab' }))[1], { removed: true })
  const [rs, r] = await panel('POST', 'catalog/refresh')
  assert.equal(rs, 200, JSON.stringify(r)); assert.ok(r.tools > 100)
})

test('the audit runs from qnx_execute and the signed reports open as HTML', async () => {
  const out = JSON.parse(await tools.get('qnx_execute').execute({ program: 'const s = await qnx.scan(); const v = await qnx.verify(); const r = await qnx.report(); return { checks: s.checks.length, verdicts: v.claims.length, chain: r.audit.verified }', timeout_ms: 300000 }))
  assert.equal(out.value.checks, 6)
  assert.equal(out.value.chain, true)
  const [s, html] = await panel('GET', 'report/verified.html')
  assert.equal(s, 200)
  assert.match(html, /Verified findings/)
})

test('qnx_search returns typed stubs from the real target catalog', async () => {
  const r = JSON.parse(await tools.get('qnx_search').execute({ query: 'open ports listening sockets', limit: 3 }))
  assert.equal(r.matches[0].name, 'netstat')
  assert.match(r.matches[0].stub, /^netstat\(args\?: string\[\]/)
  assert.ok(r.catalog_size > 100)
  const kill = JSON.parse(await tools.get('qnx_search').execute({ names: ['kill'] })).matches[0]
  assert.equal(kill.needs_approval, true, 'in ask mode a destructive tool is listed as needing approval')
})

test('qnx_execute runs on the target through the gate, and the gate denies out-of-scope calls', async () => {
  const ok = JSON.parse(await tools.get('qnx_execute').execute({ program: 'const u = await tools.uname(["-s"]); return u.stdout.trim()' }))
  assert.equal(ok.value, 'Linux')
  assert.match(ok.receipt, /^[0-9a-f]{64}$/)
  const denied = JSON.parse(await tools.get('qnx_execute').execute({ program: 'return await tools.ping(["-c","1","198.51.100.23"])' }))
  assert.equal(denied.error.kind, 'scope_denied')
  assert.equal(denied.error.code, 'out_of_scope')
  const destructive = JSON.parse(await tools.get('qnx_execute').execute({ program: 'return await tools.kill(["-0","1"])' }))
  assert.equal(destructive.error.code, 'not_approved', 'ask mode with no approval prompt fails closed')
})
