import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { sealSecret, sealForStorage, openSecret, isSealed, isEncryptionConfigured, maskKey, hashToken } from './dbCrypto.js';

const KEY = crypto.randomBytes(32).toString('base64');

function withKey<T>(key: string | undefined, fn: () => T): T {
  const prev = process.env.ENCRYPTION_KEY;
  if (key === undefined) delete process.env.ENCRYPTION_KEY;
  else process.env.ENCRYPTION_KEY = key;
  try { return fn(); } finally {
    if (prev === undefined) delete process.env.ENCRYPTION_KEY;
    else process.env.ENCRYPTION_KEY = prev;
  }
}

test('sealSecret round-trips through openSecret', () => {
  withKey(KEY, () => {
    const raw = 'sk-abcdef0123456789abcdef0123456789';
    const sealed = sealSecret(raw);
    assert.ok(isSealed(sealed), 'carries the version prefix');
    assert.ok(!sealed.includes(raw), 'plaintext does not survive in the stored value');
    assert.equal(openSecret(sealed), raw);
  });
});

test('each seal is unique — a fresh IV per call, so equal keys do not look equal at rest', () => {
  withKey(KEY, () => {
    assert.notEqual(sealSecret('sk-same-value-000000'), sealSecret('sk-same-value-000000'));
  });
});

test('legacy plaintext rows still open, so existing users are not broken', () => {
  withKey(KEY, () => {
    assert.equal(openSecret('sk-written-before-sealing-existed'), 'sk-written-before-sealing-existed');
  });
});

test('a tampered sealed value returns null rather than garbage', () => {
  withKey(KEY, () => {
    const sealed = sealSecret('sk-abcdef0123456789');
    const parts = sealed.split('.');
    parts[parts.length - 1] = Buffer.from('tampered').toString('base64');
    assert.equal(openSecret(parts.join('.')), null);
  });
});

test('a value sealed under a different key returns null, never a wrong secret', () => {
  const sealed = withKey(KEY, () => sealSecret('sk-abcdef0123456789'));
  withKey(crypto.randomBytes(32).toString('base64'), () => {
    assert.equal(openSecret(sealed), null);
  });
});

test('null and empty pass straight through', () => {
  withKey(KEY, () => {
    assert.equal(openSecret(null), null);
    assert.equal(openSecret(''), null);
  });
});

test('sealSecret refuses to run without ENCRYPTION_KEY rather than storing plaintext', () => {
  withKey(undefined, () => {
    assert.equal(isEncryptionConfigured(), false);
    assert.throws(() => sealSecret('sk-abc'), /ENCRYPTION_KEY is not set/);
  });
});

test('a wrong-length ENCRYPTION_KEY fails loudly at seal time', () => {
  withKey(Buffer.from('too short').toString('base64'), () => {
    assert.throws(() => sealSecret('sk-abc'), /exactly 32 bytes/);
  });
});

test('maskKey and hashToken are unchanged by the new helpers', () => {
  assert.equal(maskKey('sk-abcdefghijklmnopqrstuvwxyz'), 'sk-abcdefghi…wxyz');
  assert.equal(hashToken('x'), crypto.createHash('sha256').update('x').digest('hex'));
});

test('sealForStorage seals when a key is configured and passes through nothing for an empty value', () => {
  withKey(KEY, () => {
    const sealed = sealForStorage('Bearer abc.def.ghi')!;
    assert.ok(isSealed(sealed));
    assert.equal(openSecret(sealed), 'Bearer abc.def.ghi');
    assert.equal(sealForStorage(undefined), null);
    assert.equal(sealForStorage(''), null);
  });
});

test('sealForStorage refuses to store a credential in cleartext in production, and allows it elsewhere', () => {
  const prev = process.env.NODE_ENV;
  try {
    process.env.NODE_ENV = 'production';
    withKey(undefined, () => assert.throws(() => sealForStorage('Bearer x'), /ENCRYPTION_KEY/));
    process.env.NODE_ENV = 'test';
    withKey(undefined, () => assert.equal(sealForStorage('Bearer x'), 'Bearer x'));
  } finally {
    if (prev === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = prev;
  }
});
