// Optional tools are registered only when their program is installed. Run with: node --import tsx --test test/availability.test.mjs
import { test } from 'node:test'
import assert from 'node:assert/strict'
import path from 'node:path'
import { checkAvailability, toolRequirements } from '../src/availability.mjs'
import { apply } from '../src/plugin.mjs'
import { decideScope } from '../src/scope.mjs'

const OPTIONAL = ['nmap', 'nuclei', 'ffuf', 'gobuster', 'sqlmap', 'john', 'nikto', 'msfconsole', 'alterego']
const ALWAYS = ['webapp_scan', 'seclayer_scan', 'domain_verify_start', 'domain_verify_check', 'secscan_fetch', 'seclayer_probe', 'recon_passive', 'generate_scan_report']

function registered(config) {
  const names = []
  apply({ tools: { register: (t) => names.push(t.name) }, on: () => {} }, config)
  return names
}

test('nothing installed: every optional tool is reported missing with the files it needs', () => {
  const { available, missing } = checkAvailability({ exists: () => false, env: {} })
  assert.equal(available.size, 0)
  assert.deepEqual(Object.keys(missing).sort(), [...OPTIONAL].sort())
  assert.ok(missing.nikto.length === 2, 'nikto needs both Perl and the nikto script')
})

test('everything installed: every optional tool is available', () => {
  const { available, missing } = checkAvailability({ exists: () => true, env: {} })
  assert.deepEqual([...available].sort(), [...OPTIONAL].sort())
  assert.deepEqual(missing, {})
})

test('the AlterEgo check follows ALTEREGO_PC_AGENT_DIR', () => {
  const req = toolRequirements({ ALTEREGO_PC_AGENT_DIR: path.join('C:', 'ae') }).alterego[0]
  assert.equal(path.basename(req), 'tool_wrappers.py')
  assert.equal(path.dirname(req), path.join('C:', 'ae'))
})

test('on this machine the plugin registers exactly the installed optional tools, plus every scan tool', () => {
  const { available } = checkAvailability()
  const names = registered({})
  for (const n of ALWAYS) assert.ok(names.includes(n), `${n} is always registered`)
  for (const n of OPTIONAL.filter((x) => x !== 'alterego')) {
    assert.equal(names.includes(n), available.has(n), `${n}: registered only when installed`)
  }
  assert.equal(names.some((n) => n.startsWith('ae_')), available.has('alterego'))
})

test('registerUnavailable: true registers everything regardless', () => {
  const names = registered({ registerUnavailable: true })
  for (const n of OPTIONAL.filter((x) => x !== 'alterego')) assert.ok(names.includes(n), n)
  assert.ok(names.some((n) => n.startsWith('ae_')))
})

test('a hidden tool is still gated when a shell command names it', async () => {
  const d = await decideScope({ toolName: 'shell', arguments: { command: 'nmap -sT not-mine.example' } }, { isVerified: async () => false })
  assert.equal(d.kind, 'deny')
})
