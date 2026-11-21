import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { LocalDomainVerifier, normalizeDomain } from '../src/verifier.mjs'

async function freshStore() {
  const dir = await mkdtemp(join(tmpdir(), 'rt-verify-'))
  return join(dir, 'verified-domains.json')
}

test('normalizeDomain takes URLs and bare domains to lowercase hosts', () => {
  assert.equal(normalizeDomain('HTTPS://Example.COM./path'), 'example.com')
  assert.equal(normalizeDomain('example.com'), 'example.com')
  assert.equal(normalizeDomain('   '), null)
})

test('start then matching TXT record verifies the domain', async () => {
  const storeFile = await freshStore()
  let published = []
  const v = new LocalDomainVerifier({ storeFile, resolveTxt: async () => published })
  const c = await v.start('example.com')
  assert.equal(c.recordName, '_secscan-challenge.example.com')
  published = [[c.token]]
  const r = await v.check('example.com')
  assert.equal(r.verified, true)
  assert.equal(await v.isVerified('https://example.com/x'), true)
})

test('a TXT record with the wrong token does not verify', async () => {
  const storeFile = await freshStore()
  const v = new LocalDomainVerifier({ storeFile, resolveTxt: async () => [['secscan-verify-wrong']] })
  await v.start('example.com')
  const r = await v.check('example.com')
  assert.equal(r.verified, false)
  assert.equal(await v.isVerified('example.com'), false)
})

test('no TXT record does not verify', async () => {
  const storeFile = await freshStore()
  const v = new LocalDomainVerifier({ storeFile, resolveTxt: async () => [] })
  await v.start('example.com')
  assert.equal((await v.check('example.com')).verified, false)
})

test('DNS failure fails closed', async () => {
  const storeFile = await freshStore()
  let token
  const v = new LocalDomainVerifier({
    storeFile,
    resolveTxt: async () => { throw new Error('ENOTFOUND') },
  })
  token = (await v.start('example.com')).token
  const r = await v.check('example.com')
  assert.equal(r.verified, false)
  assert.match(r.reason, /ENOTFOUND/)
  assert.ok(token)
})

test('check without a challenge is denied', async () => {
  const storeFile = await freshStore()
  const v = new LocalDomainVerifier({ storeFile, resolveTxt: async () => [['anything']] })
  assert.equal((await v.check('example.com')).verified, false)
})

test('a corrupt store fails closed for isVerified', async () => {
  const storeFile = await freshStore()
  await writeFile(storeFile, '{not json', 'utf8')
  const v = new LocalDomainVerifier({ storeFile, resolveTxt: async () => [] })
  assert.equal(await v.isVerified('example.com'), false)
})

test('an unverified domain stays unverified', async () => {
  const storeFile = await freshStore()
  const v = new LocalDomainVerifier({ storeFile, resolveTxt: async () => [] })
  assert.equal(await v.isVerified('nobody.example'), false)
})
