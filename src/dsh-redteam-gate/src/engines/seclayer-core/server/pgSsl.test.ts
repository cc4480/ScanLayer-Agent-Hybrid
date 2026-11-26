import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pgSsl } from './pgSsl.js';

test('a local database gets no TLS', () => {
  assert.equal(pgSsl('postgres://u:p@localhost:5432/db', {}), undefined);
  assert.equal(pgSsl('postgres://u:p@127.0.0.1/db', { PG_SSL_CA: 'x' }), undefined);
});

test('a remote database is encrypted without verification until a CA is set', () => {
  assert.deepEqual(pgSsl('postgres://u:p@db.example.com/db', {}), { rejectUnauthorized: false });
});

test('PG_SSL_CA turns certificate verification on, with \\n escapes expanded', () => {
  const ssl = pgSsl('postgres://u:p@db.example.com/db', { PG_SSL_CA: '-----BEGIN CERTIFICATE-----\\nabc\\n-----END CERTIFICATE-----' });
  assert.equal(ssl?.rejectUnauthorized, true);
  assert.equal(ssl?.ca, '-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----');
});

test('an empty PG_SSL_CA changes nothing', () => {
  assert.deepEqual(pgSsl('postgres://u:p@db.example.com/db', { PG_SSL_CA: '  ' }), { rejectUnauthorized: false });
});
