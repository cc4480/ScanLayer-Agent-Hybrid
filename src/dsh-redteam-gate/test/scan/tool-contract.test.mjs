// Calls the scan tools the way the harness does: the defineTool wrapper's execute(), then output.render().
// The handler-level tests did not catch "userRender is not a function"; these go through the wrapper.
// Run with: node --import tsx --test test/scan/tool-contract.test.mjs (needs DATABASE_URL for the live case).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs'
import { apply } from '../../src/plugin.mjs'
import { scanTools } from '../../src/scan-tools.mjs'
import { LocalDomainVerifier } from '../../src/verifier.mjs'

const EXEC = { signal: new AbortController().signal }

function registeredTools() {
  const tools = []
  apply({ tools: { register: (t) => tools.push(t) }, on: () => {} })
  return tools
}

test('every tool the plugin registers renders its output', () => {
  const broken = []
  for (const t of registeredTools()) {
    try {
      const blocks = t.output.render({}, '{"status":"ok"}')
      if (!Array.isArray(blocks)) broken.push(`${t.name}: render returned ${typeof blocks}`)
    } catch (err) {
      broken.push(`${t.name}: ${err.message}`)
    }
  }
  assert.deepEqual(broken, [])
})

test('domain_verify_start and domain_verify_check run end to end through the tool wrapper', async () => {
  const store = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'contract-')), 'v.json')
  let published = []
  const verifier = new LocalDomainVerifier({ storeFile: store, resolveTxt: async () => published })
  const byName = Object.fromEntries(scanTools(verifier).map((t) => [t.name, t]))

  const startArgs = { domain: 'mine.example' }
  const started = await byName.domain_verify_start.execute(startArgs, EXEC)
  const startText = byName.domain_verify_start.output.render(startArgs, started)[0].text
  const challenge = JSON.parse(startText)
  assert.equal(challenge.status, 'challenge_issued')

  published = [[challenge.txt_record_value]]
  const checked = await byName.domain_verify_check.execute(startArgs, EXEC)
  assert.equal(JSON.parse(byName.domain_verify_check.output.render(startArgs, checked)[0].text).status, 'verified')
})

test('webapp_scan and seclayer_scan refuse an unverified domain through the tool wrapper', async () => {
  const store = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'contract-')), 'v.json')
  const byName = Object.fromEntries(scanTools(new LocalDomainVerifier({ storeFile: store })).map((t) => [t.name, t]))
  for (const name of ['webapp_scan', 'seclayer_scan']) {
    const args = { url: 'https://not-mine.example/' }
    const value = await byName[name].execute(args, EXEC)
    assert.equal(JSON.parse(byName[name].output.render(args, value)[0].text).status, 'refused', name)
  }
})

test('webapp_scan and seclayer_scan complete a loopback scan through the tool wrapper', { skip: !process.env.DATABASE_URL && 'needs DATABASE_URL' }, async (t) => {
  const prev = process.env.ALLOW_PRIVATE_SCAN_TARGETS
  process.env.ALLOW_PRIVATE_SCAN_TARGETS = 'true'
  t.after(() => { if (prev === undefined) delete process.env.ALLOW_PRIVATE_SCAN_TARGETS; else process.env.ALLOW_PRIVATE_SCAN_TARGETS = prev })
  const server = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<!doctype html><title>lab</title>') })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  t.after(() => server.close())
  const url = `http://127.0.0.1:${server.address().port}/`
  const store = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'contract-')), 'v.json')
  const byName = Object.fromEntries(scanTools(new LocalDomainVerifier({ storeFile: store })).map((tool) => [tool.name, tool]))
  for (const name of ['webapp_scan', 'seclayer_scan']) {
    const args = { url }
    const value = await byName[name].execute(args, EXEC)
    const out = JSON.parse(byName[name].output.render(args, value)[0].text)
    assert.equal(out.status, 'complete', `${name}: ${JSON.stringify(out).slice(0, 200)}`)
  }
})
