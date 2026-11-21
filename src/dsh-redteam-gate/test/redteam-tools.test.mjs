import { test } from 'node:test'
import assert from 'node:assert/strict'
import { plugin, apply } from '../src/plugin.mjs'
import { redteamTools } from '../src/redteam-tools.mjs'
import { parseOptionString } from '../src/redteam-tools.mjs'
import { ACTIVE_TOOLS } from '../src/scope.mjs'

test('the plugin loads and registers native scanners plus red-team tools, and hooks the scope gate', () => {
  const registered = []
  const hooks = []
  const ctx = { tools: { register: (t) => registered.push(t.name) }, on: (name) => hooks.push(name) }
  apply(ctx)
  assert.equal(plugin.name, 'dsh-redteam-gate')
  assert.deepEqual(hooks, ['tools/pre-execute'])
  for (const n of ['nmap', 'nuclei', 'ffuf', 'gobuster', 'sqlmap', 'nikto', 'john']) assert.ok(registered.includes(n), n)
  for (const n of ['secscan_fetch', 'seclayer_probe', 'msfconsole', 'recon_passive']) assert.ok(registered.includes(n), n)
  assert.equal(registered.length, 11)
})

test('every target-sending red-team tool is gate-active', () => {
  for (const n of ['secscan_fetch', 'seclayer_probe', 'msfconsole']) assert.ok(ACTIVE_TOOLS.has(n), n)
  assert.equal(ACTIVE_TOOLS.has('recon_passive'), false)
})

test('the tool list matches what is exported', () => {
  const names = redteamTools({ isVerified: async () => false }).map((t) => t.name).sort()
  assert.deepEqual(names, ['msfconsole', 'recon_passive', 'seclayer_probe', 'secscan_fetch'])
})

test('option strings parse to NAME=value and reject malformed tokens', () => {
  assert.deepEqual(parseOptionString('RHOSTS=127.0.0.1 PORTS=1-100'), { RHOSTS: '127.0.0.1', PORTS: '1-100' })
  assert.deepEqual(parseOptionString(''), {})
  assert.throws(() => parseOptionString('RHOSTS'), /NAME=value/)
})
