import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { ADAPTER_PATH, invokePcAgent, createAlterEgoBridge } from '../../src/engines/alterego/bridge.mjs'
import { ALLOWLISTED_TOOLS } from '../../src/engines/alterego/allowlist.mjs'

// End-to-end through adapter.py, using a STUB pc-agent folder. The real AlterEgo bridge is never touched.
const PYTHON = process.env.ALTEREGO_PYTHON || 'python'
const probe = spawnSync(PYTHON, ['-c', 'import sys; print(sys.version_info[0])'], { encoding: 'utf8' })
const havePython = probe.status === 0 && probe.stdout.trim() === '3'
const skip = havePython ? false : `python not runnable as "${PYTHON}"`

const STUB = `
def screenshot(region=None, scale=1.0):
    return {"png_base64": "iVBORw0KGgo=", "scale": scale}
def list_windows(offset=0, limit=0):
    return {"offset": offset, "total": 1, "windows": [{"hwnd": 1, "pid": 2, "title": "stub"}]}
def active_window():
    return {"hwnd": 1, "title": "stub", "pid": 2, "process": "stub.exe"}
def system_info():
    return {"system": "stub", "hostname": "stub-host"}
def list_processes():
    return {"processes": [{"pid": 4, "exe": "System"}]}
def list_dir(path="", offset=0, limit=0):
    return {"path": path, "items": []}
def read_file(path):
    if path.endswith("denied.txt"):
        return {"error": "path outside profile"}
    return {"path": path, "content": "hello"}
def read_file_range(path, start_line, end_line=0):
    return {"path": path, "start_line": start_line, "lines": ["hello"]}
def search_files(pattern, path, file_pattern="*", max_results=50, context=0, case_insensitive=False, output_mode="matches", offset=0):
    return {"matches": []}
def search_filenames(pattern, path, max_results=50, sort_by="name", offset=0):
    return {"matches": []}
def shell_exec(command, timeout_s=60, cwd=""):
    return {"ran": command}
def _register():
    fns = [screenshot, list_windows, active_window, system_info, list_processes,
           list_dir, read_file, read_file_range, search_files, search_filenames, shell_exec]
    return fns
ALL_TOOLS = _register()
`

let stubDir
before(() => {
  if (skip) return
  stubDir = fs.mkdtempSync(path.join(os.tmpdir(), 'alterego-stub-'))
  fs.writeFileSync(path.join(stubDir, 'tool_wrappers.py'), STUB, 'utf8')
})
after(() => {
  if (stubDir) fs.rmSync(stubDir, { recursive: true, force: true })
})

const envFor = (dir) => ({ ...process.env, ALTEREGO_PC_AGENT_DIR: dir, ALTEREGO_PYTHON: PYTHON })

test('adapter ALLOWED set is exactly the catalog tools marked registered', { skip }, async () => {
  // ALLOWED is loaded from catalog.json at import time, so ask the adapter itself.
  const { execFileSync } = await import('node:child_process')
  const script = 'import importlib.util,json,sys\n'
    + 'spec=importlib.util.spec_from_file_location("a", sys.argv[1])\n'
    + 'm=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n'
    + 'print(json.dumps(sorted(m.ALLOWED)))'
  const allowed = JSON.parse(execFileSync(PYTHON, ['-c', script, ADAPTER_PATH], { encoding: 'utf8' }))
  const catalog = JSON.parse(fs.readFileSync(path.join(path.dirname(ADAPTER_PATH), 'catalog.json'), 'utf8'))
  const registered = catalog.tools.filter((t) => t.registered).map((t) => t.name).sort()
  assert.deepEqual(allowed, registered)
  assert.ok(!allowed.includes('macro_replay'), 'macro_replay must never be allowed')
})

test('adapter refuses a tool that is not in the catalog', { skip }, async () => {
  const res = await invokePcAgent('not_a_real_tool', {}, { env: envFor(stubDir) })
  assert.equal(res.ok, false)
  assert.equal(res.refused, true)
  assert.match(res.error, /not allowlisted/)
})

test('adapter refuses macro_replay, which the app does not register', { skip }, async () => {
  const res = await invokePcAgent('macro_replay', { name: 'x' }, { env: envFor(stubDir) })
  assert.equal(res.ok, false)
  assert.equal(res.refused, true)
})

test('bridge refuses shell_exec without spawning python', { skip }, async () => {
  let spawned = 0
  const bridge = createAlterEgoBridge({
    invoke: async (...a) => { spawned++; return invokePcAgent(...a, { env: envFor(stubDir) }) },
  })
  const out = await bridge.call('shell_exec', { command: 'whoami' })
  assert.equal(out.refused, true)
  assert.equal(spawned, 0)
})

for (const name of ALLOWLISTED_TOOLS) {
  test(`end-to-end result shape through adapter: ${name}`, { skip }, async () => {
    const bridge = createAlterEgoBridge({
      invoke: (tool, args) => invokePcAgent(tool, args, { env: envFor(stubDir) }),
    })
    const args = {
      screenshot: {},
      list_windows: {},
      active_window: {},
      system_info: {},
      list_processes: {},
      list_dir: { path: 'C:\\stub' },
      read_file: { path: 'C:\\stub\\ok.txt' },
      read_file_range: { path: 'C:\\stub\\ok.txt', start_line: 1 },
      search_files: { pattern: 'x', path: 'C:\\stub' },
      search_filenames: { pattern: '*.txt', path: 'C:\\stub' },
    }[name]
    const out = await bridge.call(name, args)
    assert.equal(out.ok, true, JSON.stringify(out))
    assert.equal(out.tool, name)
    assert.equal(typeof out.result, 'object')
  })
}

test('wrapper error payload maps to ok:false end-to-end', { skip }, async () => {
  const bridge = createAlterEgoBridge({
    invoke: (tool, args) => invokePcAgent(tool, args, { env: envFor(stubDir) }),
  })
  const out = await bridge.call('read_file', { path: 'C:\\stub\\denied.txt' })
  assert.equal(out.ok, false)
  assert.equal(out.error, 'path outside profile')
})

test('missing pc-agent folder returns an error envelope, not a crash', { skip }, async () => {
  const res = await invokePcAgent('system_info', {}, { env: envFor(path.join(os.tmpdir(), 'no-such-alterego-dir')) })
  assert.equal(res.ok, false)
  assert.equal(res.refused, false)
  assert.match(res.error, /tool_wrappers\.py/)
})
