// Lab-host configuration for the ported probes.
//
// Two guards apply to one probe request and they disagree about loopback unless configured:
//   - src/scope.mjs allows loopback outright (LAB_HOSTS), because it is the documented lab exception.
//   - the probes' own SSRF guard (engines/seclayer-network/server/ssrf.ts, isBlockedIp) blocks 127.0.0.1
//     unless the host is listed in SCAN_DEV_ALLOW_HOSTS.
// Without the allowlist seclayer_probe refuses every loopback target with
//   "Refusing to scan internal or reserved address \"127.0.0.1\"."
// apply({ labHosts }) closes that gap from configuration instead of an ambient shell variable.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { apply, Config } from '../src/plugin.mjs'
import { assertTargetIsScannable } from '../src/engines/seclayer-network/server/ssrf.ts'

/** A ctx that records registrations but does nothing else. */
function fakeCtx() {
  const registered = []
  const hooks = []
  return {
    registered,
    hooks,
    ctx: {
      tools: { register: (tool) => registered.push(tool.name) },
      on: (event) => hooks.push(event),
    },
  }
}

/** Run `fn` with SCAN_DEV_ALLOW_HOSTS forced to `value`, restoring it afterwards. */
async function withAllowlist(value, fn) {
  const previous = process.env.SCAN_DEV_ALLOW_HOSTS
  if (value === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS
  else process.env.SCAN_DEV_ALLOW_HOSTS = value
  try {
    return await fn()
  } finally {
    if (previous === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS
    else process.env.SCAN_DEV_ALLOW_HOSTS = previous
  }
}

const scannable = async (url) => {
  try {
    await assertTargetIsScannable(new URL(url))
    return true
  } catch {
    return false
  }
}

test('Config is a Standard Schema that defaults labHosts to empty', () => {
  // The harness validates through '~standard'; the labHosts setting is read from its validated value.
  const std = Config['~standard']
  assert.ok(std && typeof std.validate === 'function', 'Config must implement the Standard Schema validate')
  assert.deepEqual(std.validate({}).value.labHosts, [])
  assert.deepEqual(std.validate({ labHosts: ['127.0.0.1', 'lab.local:8080'] }).value.labHosts, ['127.0.0.1', 'lab.local:8080'])
})

test('without labHosts the loopback refusal is unchanged (fail closed)', async () => {
  await withAllowlist(undefined, async () => {
    const { ctx } = fakeCtx()
    apply(ctx, {})
    assert.equal(process.env.SCAN_DEV_ALLOW_HOSTS, undefined, 'apply must not invent an allowlist')
    assert.equal(await scannable('http://127.0.0.1:9/'), false, 'loopback must stay refused when unconfigured')
  })
})

test('labHosts makes loopback scannable for the probes', async () => {
  await withAllowlist(undefined, async () => {
    const { ctx } = fakeCtx()
    apply(ctx, { labHosts: ['127.0.0.1'] })
    assert.equal(await scannable('http://127.0.0.1:9/'), true)
  })
})

test('labHosts does not open private, link-local or metadata ranges', async () => {
  await withAllowlist(undefined, async () => {
    const { ctx } = fakeCtx()
    apply(ctx, { labHosts: ['127.0.0.1'] })
    for (const url of ['http://10.0.0.5/', 'http://192.168.1.1/', 'http://169.254.169.254/', 'http://172.16.0.1/']) {
      assert.equal(await scannable(url), false, `${url} must remain refused`)
    }
  })
})

test('lab host entries are normalized and malformed entries are dropped', async () => {
  await withAllowlist(undefined, async () => {
    const { ctx } = fakeCtx()
    apply(ctx, { labHosts: ['127.0.0.1', 'LOCALHOST', '  http://bad/path  ', 'with space', '10.0.0.5:8080'] })
    assert.equal(process.env.SCAN_DEV_ALLOW_HOSTS, '127.0.0.1,localhost,10.0.0.5:8080')
  })
})

test('duplicate lab hosts are collapsed', async () => {
  await withAllowlist(undefined, async () => {
    const { ctx } = fakeCtx()
    apply(ctx, { labHosts: ['127.0.0.1', '127.0.0.1', '127.0.0.1:4100', '127.0.0.1:4100'] })
    assert.equal(process.env.SCAN_DEV_ALLOW_HOSTS, '127.0.0.1,127.0.0.1:4100')
  })
})

import { CATALOG as AE_CATALOG_LAB } from '../src/engines/alterego/registry.mjs'
const alterEgoCount = () => AE_CATALOG_LAB.tools.filter((t) => t.registered).length

test('a non-array labHosts value is ignored rather than trusted', async () => {
  await withAllowlist(undefined, async () => {
    const { ctx } = fakeCtx()
    apply(ctx, { labHosts: '127.0.0.1' })
    assert.equal(process.env.SCAN_DEV_ALLOW_HOSTS, undefined)
    assert.equal(await scannable('http://127.0.0.1:9/'), false)
  })
})

test('lab host entries cannot smuggle a scheme, path or credentials', async () => {
  await withAllowlist(undefined, async () => {
    const { ctx } = fakeCtx()
    apply(ctx, { labHosts: ['https://127.0.0.1', '127.0.0.1/../etc', 'user@127.0.0.1', '127.0.0.1:99999'] })
    assert.equal(process.env.SCAN_DEV_ALLOW_HOSTS, undefined, 'every malformed entry must be dropped')
  })
})

test('apply still registers all thirteen harness tools and the pre-execute hook', () => {
  const { ctx, registered, hooks } = fakeCtx()
  apply(ctx, { labHosts: ['127.0.0.1'] })
  const names = registered.map((t) => t.name ?? t)
  assert.equal(names.filter((n) => !String(n).startsWith('ae_')).length, 13)
  assert.equal(names.filter((n) => String(n).startsWith('ae_')).length, alterEgoCount())
  assert.deepEqual(hooks, ['tools/pre-execute'])
})

test('an out-of-band SCAN_DEV_ALLOW_HOSTS is left alone when the bundle declares nothing', async () => {
  await withAllowlist('127.0.0.1', async () => {
    const { ctx } = fakeCtx()
    apply(ctx, { labHosts: [] })
    assert.equal(process.env.SCAN_DEV_ALLOW_HOSTS, '127.0.0.1', 'apply must not clobber an operator-set value')
  })
})
