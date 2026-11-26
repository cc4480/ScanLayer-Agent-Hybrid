import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.DB_PATH = ':memory:';
const { toClientScan } = await import('./scans.js');

test('a scan sent to a client never carries the stored credential, only that one exists', () => {
  const out = toClientScan({ id: 'scan_1', url: 'https://a.test', authHeader: 'Bearer secret' });
  assert.equal('authHeader' in out, false);
  assert.equal(JSON.stringify(out).includes('secret'), false);
  assert.equal(out.hasAuthHeader, true);
  assert.equal(toClientScan({ id: 'scan_2', url: 'https://b.test' }).hasAuthHeader, false);
});
