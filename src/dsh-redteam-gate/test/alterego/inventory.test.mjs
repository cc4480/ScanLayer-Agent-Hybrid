import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { ALLOWLISTED_TOOLS, DEFERRED } from '../../src/engines/alterego/allowlist.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const INVENTORY = path.join(here, '..', '..', 'src', 'engines', 'alterego', 'inventory.md')

function rows() {
  const text = fs.readFileSync(INVENTORY, 'utf8')
  return text
    .split(/\r?\n/)
    .map((line) => line.match(/^\| (\d+) \| ([a-z_]+) \| (.*?) \| (.*?) \| (.*?) \| (.*?) \|$/))
    .filter(Boolean)
    .map((m) => ({ n: Number(m[1]), name: m[2], purpose: m[3], risk: m[4], tier: m[5], status: m[6] }))
}

test('inventory lists 109 tools numbered 1..109 with unique names', () => {
  const r = rows()
  assert.equal(r.length, 109)
  assert.deepEqual(r.map((x) => x.n), Array.from({ length: 109 }, (_, i) => i + 1))
  assert.equal(new Set(r.map((x) => x.name)).size, 109)
})

test('every allowlisted tool is marked ALLOWLISTED with risk read only', () => {
  const byName = new Map(rows().map((x) => [x.name, x]))
  for (const name of ALLOWLISTED_TOOLS) {
    const row = byName.get(name)
    assert.ok(row, `${name} missing from inventory`)
    assert.equal(row.status, 'ALLOWLISTED')
    assert.equal(row.risk, 'read', `${name} must be risk read`)
  }
  assert.equal(rows().filter((x) => x.status === 'ALLOWLISTED').length, ALLOWLISTED_TOOLS.length)
})

test('every deferred entry in allowlist.mjs appears in the inventory as DEFERRED', () => {
  const byName = new Map(rows().map((x) => [x.name, x]))
  for (const name of Object.keys(DEFERRED)) {
    const row = byName.get(name)
    assert.ok(row, `${name} missing from inventory`)
    assert.match(row.status, /^DEFERRED/)
  }
})

test('no exec-risk tool is allowlisted', () => {
  for (const x of rows()) {
    if (x.status !== 'ALLOWLISTED') continue
    assert.doesNotMatch(x.risk, /exec|write|network|input-control/, `${x.name} has non-read risk`)
  }
})
