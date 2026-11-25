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
const ctx = {
  tools: { register: t => { tools.set(t.name, t); return () => tools.delete(t.name) } },
  systemPrompt: { section: s => { sections.push(s); return () => {} } },
  logger: { info: (...a) => logs.push(a), warn: (...a) => logs.push(['WARN', ...a]) },
  effect: (fn) => { const d = fn(); effects.push(d); return d },
  inject: (_names, cb) => cb({ webServer: { getOrigin: () => 'http://127.0.0.1:3999', register: r => { routes.push(r); return () => {} } }, effect: (fn) => effects.push(fn()) }),
}

const waitForEngine = async () => {
  for (let i = 0; i < 100; i++) {
    try { await tools.get('qnx_search').execute({ query: 'ports' }); return } catch (e) { if (!/not running/.test(e.message)) throw e }
    await new Promise(r => setTimeout(r, 200))
  }
  throw new Error('engine did not start: ' + JSON.stringify(logs.filter(l => l[0] === 'WARN')))
}

test.before(async () => {
  apply(ctx, { target: 'standin', engineConfig: '', tools: true, guide: true, maxBodyBytes: 262144 })
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
})

test('qnx_search returns typed stubs from the real target catalog', async () => {
  const r = JSON.parse(await tools.get('qnx_search').execute({ query: 'open ports listening sockets', limit: 3 }))
  assert.equal(r.matches[0].name, 'netstat')
  assert.match(r.matches[0].stub, /^netstat\(args\?: string\[\]/)
  assert.ok(r.catalog_size > r.visible_size)
})

test('qnx_execute runs on the target through the gate, and the gate denies out-of-scope calls', async () => {
  const ok = JSON.parse(await tools.get('qnx_execute').execute({ program: 'const u = await tools.uname(["-s"]); return u.stdout.trim()' }))
  assert.equal(ok.value, 'Linux')
  assert.match(ok.receipt, /^[0-9a-f]{64}$/)
  const denied = JSON.parse(await tools.get('qnx_execute').execute({ program: 'return await tools.ping(["-c","1","198.51.100.23"])' }))
  assert.equal(denied.error.kind, 'scope_denied')
  assert.equal(denied.error.code, 'out_of_scope')
  const destructive = JSON.parse(await tools.get('qnx_execute').execute({ program: 'return await tools.kill(["-0","1"])' }))
  assert.equal(destructive.error.code, 'destructive_off')
})
