import { test, expect } from 'vitest'
import { productionLockdown, runScoped } from '../../src/engines/secscan-network/adapter.mjs'

test('production with a lab opt-out set is refused', () => {
  expect(() => productionLockdown({ NODE_ENV: 'production', SCAN_DEV_ALLOW_HOSTS: '127.0.0.1:8080' })).toThrow(/production lockdown/)
  expect(() => productionLockdown({ NODE_ENV: 'production', ALLOW_PRIVATE_SCAN_TARGETS: 'true' })).toThrow(/ALLOW_PRIVATE_SCAN_TARGETS/)
})

test('production with no opt-out set is allowed', () => {
  expect(() => productionLockdown({ NODE_ENV: 'production' })).not.toThrow()
  expect(() => productionLockdown({ NODE_ENV: 'production', SCAN_DEV_ALLOW_HOSTS: '   ' })).not.toThrow()
})

test('outside production the lab opt-out is not blocked here', () => {
  expect(() => productionLockdown({ SCAN_DEV_ALLOW_HOSTS: '127.0.0.1:8080' })).not.toThrow()
  expect(() => productionLockdown({ NODE_ENV: 'development', SCAN_DEV_ALLOW_HOSTS: '127.0.0.1:8080' })).not.toThrow()
})

test('runScoped refuses to run in production with a lab opt-out set, before any request', async () => {
  const saved = { NODE_ENV: process.env.NODE_ENV, SCAN_DEV_ALLOW_HOSTS: process.env.SCAN_DEV_ALLOW_HOSTS }
  process.env.NODE_ENV = 'production'
  process.env.SCAN_DEV_ALLOW_HOSTS = '127.0.0.1:8080'
  let ran = false
  try {
    await expect(runScoped({ isVerified: async () => true }, async () => { ran = true })).rejects.toThrow(/production lockdown/)
    expect(ran).toBe(false)
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]
      else process.env[k] = v
    }
  }
})
