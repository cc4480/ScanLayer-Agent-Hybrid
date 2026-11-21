import { test } from 'node:test'
import assert from 'node:assert/strict'
import { READ_ONLY_ALLOWLIST, ALLOWLISTED_TOOLS, DEFERRED, validateArgs } from '../../src/engines/alterego/allowlist.mjs'
import { createAlterEgoBridge } from '../../src/engines/alterego/bridge.mjs'

// Canned envelopes: one realistic result shape per allowlisted tool.
const CANNED = {
  screenshot: { png_base64: 'iVBORw0KGgo=', width: 1920, height: 1080 },
  list_windows: { offset: 0, total: 1, windows: [{ hwnd: 1, pid: 2, title: 'Notepad' }] },
  active_window: { hwnd: 1, title: 'Notepad', pid: 2, process: 'notepad.exe' },
  system_info: { system: 'Windows', release: '11', hostname: 'host', user: 'u', cpu_percent: 3, mem_percent: 40 },
  list_processes: { processes: [{ pid: 4, exe: 'System' }] },
  list_dir: { path: 'C:\\Users\\u', items: [{ name: 'a.txt', dir: false, size: 3 }] },
  read_file: { path: 'C:\\Users\\u\\a.txt', content: 'abc' },
  read_file_range: { path: 'C:\\Users\\u\\a.txt', start_line: 1, end_line: 1, lines: ['abc'] },
  search_files: { matches: [{ file: 'a.txt', line: 1, text: 'abc' }] },
  search_filenames: { matches: ['a.txt'] },
}

// Valid arguments per tool (tools with required arguments cannot be called with {}).
const VALID_ARGS = {
  read_file: { path: 'C:\\Users\\u\\a.txt' },
  read_file_range: { path: 'C:\\Users\\u\\a.txt', start_line: 1 },
  search_files: { pattern: 'abc', path: 'C:\\Users\\u' },
  search_filenames: { pattern: '*.txt', path: 'C:\\Users\\u' },
}

function fakeInvoke(calls, overrides = {}) {
  return async (tool, args) => {
    calls.push({ tool, args })
    if (overrides[tool]) return overrides[tool]
    return { ok: true, result: CANNED[tool] }
  }
}

test('allowlist has exactly the ten read-only tools', () => {
  assert.deepEqual([...ALLOWLISTED_TOOLS].sort(), Object.keys(CANNED).sort())
})

const REFUSED = [
  'shell_exec', 'shell_pwsh', 'exec', 'exec_background', 'batch', 'submit_job', 'macro_replay',
  'kill_process', 'process', 'power', 'write_file', 'edit_file', 'delete_file', 'move_file',
  'type_text', 'hotkey', 'mouse_click', 'browser_eval', 'cdp_evaluate', 'web_fetch',
  'clipboard_set', 'record_audio', 'Screenshot', 'SHELL_EXEC', 'list_windows ', 'nonexistent',
  '__proto__', 'constructor', 'toString', '',
]

for (const name of REFUSED) {
  test(`unlisted tool is refused without invoking the bridge: ${JSON.stringify(name)}`, async () => {
    const calls = []
    const bridge = createAlterEgoBridge({ invoke: fakeInvoke(calls) })
    const out = await bridge.call(name, {})
    assert.equal(out.ok, false)
    assert.equal(out.refused, true)
    assert.match(out.error, /not allowlisted/)
    assert.equal(calls.length, 0, 'invoke must not run for an unlisted tool')
  })
}

test('deferred tools are never allowlisted', () => {
  for (const name of Object.keys(DEFERRED)) {
    assert.equal(READ_ONLY_ALLOWLIST[name], undefined, `${name} must not be allowlisted`)
  }
})

test('shell and exec tools are in the deferred list with an EXEC reason', () => {
  for (const name of ['shell_exec', 'shell_pwsh', 'exec', 'exec_background', 'batch', 'submit_job']) {
    assert.match(DEFERRED[name], /EXEC/, `${name} must be flagged EXEC`)
  }
})

for (const name of ALLOWLISTED_TOOLS) {
  test(`allowed tool returns a result object: ${name}`, async () => {
    const calls = []
    const bridge = createAlterEgoBridge({ invoke: fakeInvoke(calls) })
    const out = await bridge.call(name, VALID_ARGS[name] ?? {})
    assert.equal(out.ok, true, JSON.stringify(out))
    assert.equal(out.tool, name)
    assert.equal(typeof out.result, 'object')
    assert.deepEqual(out.result, CANNED[name])
    assert.equal(calls.length, 1)
    assert.equal(calls[0].tool, name)
  })
}

test('bridge-reported error payload becomes ok:false', async () => {
  const bridge = createAlterEgoBridge({
    invoke: fakeInvoke([], { read_file: { ok: true, result: { error: 'path outside profile' } } }),
  })
  const out = await bridge.call('read_file', { path: 'C:\\Windows\\win.ini' })
  assert.equal(out.ok, false)
  assert.equal(out.refused, false)
  assert.equal(out.error, 'path outside profile')
})

test('adapter refusal envelope is surfaced as refused', async () => {
  const bridge = createAlterEgoBridge({
    invoke: fakeInvoke([], { list_dir: { ok: false, refused: true, error: 'tool not allowlisted: list_dir' } }),
  })
  const out = await bridge.call('list_dir', {})
  assert.equal(out.ok, false)
  assert.equal(out.refused, true)
})

test('transport failure becomes ok:false and does not throw', async () => {
  const bridge = createAlterEgoBridge({
    invoke: async () => { throw new Error('cannot start python') },
  })
  const out = await bridge.call('system_info', {})
  assert.equal(out.ok, false)
  assert.equal(out.error, 'cannot start python')
})

test('invalid arguments are rejected before the bridge runs', async () => {
  const calls = []
  const bridge = createAlterEgoBridge({ invoke: fakeInvoke(calls) })
  const cases = [
    ['read_file', {}],                                  // missing path
    ['read_file', { path: 'a', extra: 1 }],              // unknown key
    ['read_file', { path: 5 }],                          // wrong type
    ['read_file_range', { path: 'a', start_line: 0 }],   // below minimum
    ['list_windows', { limit: 1.5 }],                    // not an integer
    ['screenshot', { region: { x: 0, y: 0, width: 1 } }], // region missing height
    ['system_info', ['x']],                              // args not an object
  ]
  for (const [name, args] of cases) {
    const out = await bridge.call(name, args)
    assert.equal(out.ok, false, `${name} ${JSON.stringify(args)} should fail`)
    assert.equal(out.refused, false)
  }
  assert.equal(calls.length, 0)
})

test('validateArgs accepts well-formed arguments', () => {
  assert.equal(validateArgs('read_file_range', { path: 'a', start_line: 1 }).ok, true)
  assert.equal(validateArgs('screenshot', { scale: 0.5, region: { x: 0, y: 0, width: 10, height: 10 } }).ok, true)
  assert.equal(validateArgs('system_info', undefined).ok, true)
})

test('native tool descriptors are read-risk, prefixed, and carry a JSON schema', () => {
  const bridge = createAlterEgoBridge({ invoke: fakeInvoke([]) })
  assert.equal(bridge.tools.length, 10)
  for (const t of bridge.tools) {
    assert.equal(t.risk, 'read')
    assert.equal(t.source, 'alterego')
    assert.ok(t.name.startsWith('alterego_'))
    assert.equal(t.parameters.type, 'object')
    assert.equal(typeof t.execute, 'function')
  }
})
