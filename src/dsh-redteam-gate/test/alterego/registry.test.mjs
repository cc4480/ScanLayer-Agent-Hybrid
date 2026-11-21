// The app's AlterEgo tools: names, schemas, the no-collision rule, and call results.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { alterEgoTools, CATALOG } from '../../src/engines/alterego/registry.mjs'
import { nativeTools } from '../../src/tools.mjs'
import { redteamTools } from '../../src/redteam-tools.mjs'

const registered = CATALOG.tools.filter((t) => t.registered)
const tools = alterEgoTools({ invoke: async () => ({ ok: true, result: {} }) })

test('one ae_ tool per registered catalog entry, and macro_replay is not among them', () => {
  assert.equal(tools.length, registered.length)
  assert.equal(new Set(tools.map((t) => t.name)).size, tools.length, 'names are unique')
  assert.ok(tools.every((t) => t.name.startsWith('ae_')))
  assert.ok(!tools.some((t) => t.name === 'ae_macro_replay'))
  assert.equal(CATALOG.registered, registered.length)
})

test('no AlterEgo tool name collides with a scanner or red-team tool name', () => {
  const verifier = { isVerified: async () => false }
  const existing = new Set([...nativeTools, ...redteamTools(verifier)].map((t) => t.name))
  for (const t of tools) assert.equal(existing.has(t.name), false, `${t.name} collides`)
})

test('the four names that collide with harness tools are prefixed', () => {
  for (const base of ['exec', 'file', 'web_fetch', 'web_search']) {
    assert.ok(tools.some((t) => t.name === `ae_${base}`), `ae_${base} missing`)
  }
})

test('schemas carry explicit additionalProperties and required fields from the catalog', () => {
  const tcp = tools.find((t) => t.name === 'ae_tcp_check')
  assert.ok(tcp, 'ae_tcp_check registered')
  assert.deepEqual([...(tcp.parameters.required ?? [])].sort(), ['host', 'ports'])
  assert.equal(tcp.parameters.properties.ports.type, 'array')
  assert.equal(tcp.parameters.properties.ports.items.type, 'integer')
})

test('a call sends the catalog name and arguments, and returns the wrapper result', async () => {
  const seen = []
  const live = alterEgoTools({
    invoke: async (name, args, opts) => { seen.push({ name, args, timeoutMs: opts.timeoutMs }); return { ok: true, result: { hello: 'world' } } },
  })
  const tool = live.find((t) => t.name === 'ae_system_info')
  const out = await tool.execute({}, {})
  assert.deepEqual(out, { hello: 'world' })
  assert.equal(seen[0].name, 'system_info')
  assert.equal(seen[0].timeoutMs, 90_000)
})

test('a wrapper error becomes a thrown error with the adapter message', async () => {
  const bad = alterEgoTools({ invoke: async () => ({ ok: false, refused: false, error: 'boom: wrapper failed' }) })
  const tool = bad.find((t) => t.name === 'ae_read_file')
  await assert.rejects(() => tool.execute({ path: 'x' }, {}), /boom: wrapper failed/)
})

test('a shell call gets a timeout that covers its own timeout_s', async () => {
  let timeoutMs = 0
  const live = alterEgoTools({ invoke: async (_n, _a, opts) => { timeoutMs = opts.timeoutMs; return { ok: true, result: {} } } })
  await live.find((t) => t.name === 'ae_shell_exec').execute({ command: 'whoami', timeout_s: 300 }, {})
  assert.equal(timeoutMs, 330_000)
})
