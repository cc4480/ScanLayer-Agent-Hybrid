import { test } from 'node:test'
import assert from 'node:assert/strict'
import { plugin, apply } from '../src/plugin.mjs'
import { redteamTools } from '../src/redteam-tools.mjs'
import { parseOptionString } from '../src/redteam-tools.mjs'
import { ACTIVE_TOOLS } from '../src/scope.mjs'

import { CATALOG as AE_CATALOG } from '../src/engines/alterego/registry.mjs'
const alterEgoCount = () => AE_CATALOG.tools.filter((t) => t.registered).length

test('the plugin loads and registers native scanners plus red-team tools, and hooks the scope gate', () => {
  const registered = []
  const hooks = []
  const ctx = { tools: { register: (t) => registered.push(t.name) }, on: (name) => hooks.push(name) }
  apply(ctx)
  assert.equal(plugin.name, 'dsh-redteam-gate')
  assert.deepEqual(hooks, ['tools/pre-execute'])
  for (const n of ['nmap', 'nuclei', 'ffuf', 'gobuster', 'sqlmap', 'nikto', 'john']) assert.ok(registered.includes(n), n)
  for (const n of ['secscan_fetch', 'seclayer_probe', 'msfconsole', 'recon_passive']) assert.ok(registered.includes(n), n)
  for (const n of ['webapp_scan', 'seclayer_scan']) assert.ok(registered.includes(n), n)
  // The 13 scanner, red-team and verbatim-scan tools, plus one ae_ tool per registered AlterEgo catalog entry.
  const harness = registered.filter((n) => !n.startsWith('ae_'))
  assert.equal(harness.length, 13)
  assert.ok(registered.some((n) => n.startsWith('ae_')), 'AlterEgo tools are registered')
  assert.equal(registered.filter((n) => n.startsWith('ae_')).length, alterEgoCount())
})

test('the plugin Config satisfies the harness Standard Schema contract (a plain object stops the plugin loading)', () => {
  // The harness calls Config['~standard'].validate(config) before activation. Without it the plugin
  // does not start, and the scope gate and every tool it registers are missing.
  const std = plugin.Config?.['~standard']
  assert.ok(std, 'Config must expose ~standard')
  assert.equal(typeof std.validate, 'function')
  assert.deepEqual(std.validate({}), { value: { labHosts: [] } })
  assert.deepEqual(std.validate({ labHosts: ['127.0.0.1'] }), { value: { labHosts: ['127.0.0.1'] } })
  assert.deepEqual(std.validate(undefined), { value: { labHosts: [] } })
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
