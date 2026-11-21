import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gatedFetch } from '../../src/engines/secscan-adapters/gate-adapter.mjs';

// Gate that verifies nothing: only loopback is admitted by the policy.
const denyAllGate = { isVerified: async () => false };

function spyFetch() {
  const calls = [];
  const fn = async (url, opts) => {
    calls.push({ url, opts });
    return { url, status: 200, headers: {}, setCookies: [], body: '' };
  };
  return { fn, calls };
}

test('a non-lab host (victim.example.org) is refused and the injected fetch is never called', async () => {
  const spy = spyFetch();
  const gated = gatedFetch({ gate: denyAllGate, fetchFn: spy.fn });
  await assert.rejects(
    () => gated('https://victim.example.org/'),
    (err) => err.code === 'SCOPE_DENIED' && /victim\.example\.org/.test(err.message),
  );
  assert.equal(spy.calls.length, 0, 'fetch spy must be called zero times for a refused host');
});

test('a host verified by SecScan is admitted and the injected fetch is called once', async () => {
  const spy = spyFetch();
  const gate = { isVerified: async (d) => d === 'verified.example.org' };
  const gated = gatedFetch({ gate, fetchFn: spy.fn });
  const res = await gated('https://verified.example.org/');
  assert.equal(res.status, 200);
  assert.equal(spy.calls.length, 1);
});

test('loopback lab host is admitted without verification', async () => {
  const spy = spyFetch();
  const gated = gatedFetch({ gate: denyAllGate, fetchFn: spy.fn });
  await gated('http://127.0.0.1:8080/');
  assert.equal(spy.calls.length, 1);
});

test('a raw non-loopback IP is refused even when the gate says verified', async () => {
  const spy = spyFetch();
  const gated = gatedFetch({ gate: { isVerified: async () => true }, fetchFn: spy.fn });
  await assert.rejects(() => gated('http://203.0.113.7/'), (err) => err.code === 'SCOPE_DENIED');
  assert.equal(spy.calls.length, 0);
});

test('a gate that throws fails closed (zero requests)', async () => {
  const spy = spyFetch();
  const gated = gatedFetch({ gate: { isVerified: async () => { throw new Error('db down'); } }, fetchFn: spy.fn });
  await assert.rejects(() => gated('https://victim.example.org/'), (err) => err.code === 'SCOPE_DENIED');
  assert.equal(spy.calls.length, 0);
});

test('gatedFetch refuses to build without a gate or a fetch function', () => {
  assert.throws(() => gatedFetch({ gate: null, fetchFn: spyFetch().fn }), TypeError);
  assert.throws(() => gatedFetch({ gate: denyAllGate, fetchFn: 'nope' }), TypeError);
});
