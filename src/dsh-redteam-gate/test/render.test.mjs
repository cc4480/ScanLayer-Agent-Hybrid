import { test } from 'node:test'
import assert from 'node:assert/strict'
import { nativeTools } from '../src/tools.mjs'
import { redteamTools } from '../src/redteam-tools.mjs'
import { renderText } from '../src/render.mjs'

const never = { isVerified: async () => false }
const everyTool = () => [...nativeTools, ...redteamTools(never)]

// The harness calls output.render(args, value) after execute(); a missing render makes the call fail
// ("output.render failed: userRender is not a function"). These tests run the real tool path, not just definitions.

test('every tool has an output.render function', () => {
  for (const tool of everyTool()) {
    assert.equal(typeof tool.output?.render, 'function', `${tool.name} has no output.render`)
  }
})

test('renderText returns a text block for strings and for JSON values', () => {
  assert.deepEqual(renderText({}, 'hello'), [{ type: 'text', text: 'hello' }])
  const [block] = renderText({}, { a: 1 })
  assert.equal(block.type, 'text')
  assert.match(block.text, /"a": 1/)
})

test('recon_passive: execute then render yields text (no network: the domain is refused before any lookup)', async () => {
  const tool = redteamTools(never).find((t) => t.name === 'recon_passive')
  const args = { domain: '8.8.8.8' }
  const value = await tool.execute(args, {})
  const blocks = tool.output.render(args, value)
  assert.equal(blocks[0].type, 'text')
  assert.match(blocks[0].text, /error/)
})

test('nmap: execute runs for real on loopback and render yields text', { timeout: 60000 }, async () => {
  const tool = nativeTools.find((t) => t.name === 'nmap')
  const args = { target: '127.0.0.1', flags: '-Pn -sT -p 1' }
  const value = await tool.execute(args, {})
  assert.equal(typeof value.exitCode, 'number')
  const blocks = tool.output.render(args, value)
  assert.equal(blocks[0].type, 'text')
  assert.ok(blocks[0].text.includes('"exitCode"'))
})
