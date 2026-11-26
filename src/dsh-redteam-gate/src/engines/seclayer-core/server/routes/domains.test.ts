import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'node:net';

process.env.DB_PATH = ':memory:';
const { db } = await import('../db.js');
const { registerDomainRoutes, MAX_DOMAIN_VERIFICATIONS_PER_USER } = await import('./domains.js');

async function withDomainApp(fn: (base: string, userId: string) => Promise<void>) {
  const user = (await db.getOrCreateUser(`domains-route-${Date.now()}-${Math.random()}@test.io`));
  const app = express();
  app.use(express.json());
  registerDomainRoutes(app, {
    requireAuth: (req, _res, next) => { (req as any).userId = user.id; next(); },
    getUserId: (req) => (req as any).userId,
    processScanJob: () => {},
    processNmapScanJob: () => {},
    nmapAvailable: false,
    cookieOptions: { httpOnly: true },
    sessionCookie: 'sl_session',
  });
  const server = app.listen(0);
  await new Promise<void>((resolve) => server.once('listening', () => resolve()));
  try {
    await fn(`http://127.0.0.1:${(server.address() as AddressInfo).port}`, user.id);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

const start = (base: string, url: string) =>
  fetch(`${base}/api/domains/verify/start`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) });

test('a user cannot hold more than the maximum number of pending or verified domains', async () => {
  await withDomainApp(async (base, userId) => {
    for (let i = 0; i < MAX_DOMAIN_VERIFICATIONS_PER_USER; i++) {
      await db.startDomainVerification(userId, `seed-${i}.example.com`, `tok-${i}`);
    }
    const refused = await start(base, 'https://one-too-many.example.com');
    assert.equal(refused.status, 400);
    assert.match((await refused.json()).message, /at most/);
    assert.equal((await db.listDomainVerifications(userId)).length, MAX_DOMAIN_VERIFICATIONS_PER_USER);

    // A domain already on the list is still returned, not refused.
    const existing = await start(base, 'https://seed-0.example.com');
    assert.equal(existing.status, 200);
  });
});

test('verification requests are rate limited per user', async () => {
  await withDomainApp(async (base) => {
    const statuses: number[] = [];
    for (let i = 0; i < 24; i++) statuses.push((await start(base, `https://rl-${i}.example.com`)).status);
    assert.ok(statuses.includes(429), 'the 21st request inside a minute is refused');
    assert.equal(statuses.filter((s) => s === 429).length, 4);
  });
});
