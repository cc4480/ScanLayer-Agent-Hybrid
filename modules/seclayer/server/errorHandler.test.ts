import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { jsonErrorHandler } from './errorHandler.js';

async function serve() {
  const app = express();
  app.use(express.json({ limit: '1kb' }));
  app.post('/echo', (req, res) => res.json({ ok: true, got: req.body }));
  app.get('/boom', () => { throw new Error('database password is hunter2'); });
  app.use(jsonErrorHandler);
  const srv = http.createServer(app);
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  return { base, close: () => new Promise((r) => srv.close(r)) };
}

const post = (base: string, body: string) =>
  fetch(`${base}/echo`, { method: 'POST', headers: { 'content-type': 'application/json' }, body });

test('malformed JSON is a 400 and the parser message is not echoed', async () => {
  const s = await serve();
  try {
    const res = await post(s.base, '{"url": "https://a.test", oops');
    assert.equal(res.status, 400);
    const body = await res.json() as { message: string };
    assert.equal(body.message, 'The request body is not valid JSON.');
    assert.ok(!body.message.includes('oops'));
  } finally { await s.close(); }
});

test('an oversized body is a 413', async () => {
  const s = await serve();
  try {
    const res = await post(s.base, JSON.stringify({ pad: 'x'.repeat(5000) }));
    assert.equal(res.status, 413);
  } finally { await s.close(); }
});

test('a real failure is still an opaque 500 that does not leak the cause', async () => {
  const s = await serve();
  const prev = console.error;
  console.error = () => {};
  try {
    const res = await fetch(`${s.base}/boom`);
    assert.equal(res.status, 500);
    const text = await res.text();
    assert.ok(!text.includes('hunter2'));
  } finally { console.error = prev; await s.close(); }
});

test('a valid request is untouched', async () => {
  const s = await serve();
  try {
    const res = await post(s.base, '{"a":1}');
    assert.equal(res.status, 200);
  } finally { await s.close(); }
});
