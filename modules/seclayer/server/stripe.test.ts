import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CREDIT_PACKS, isStripeConfigured, createCheckoutSession, parseWebhookEvent } from './stripe.js';

test('credit packs are well-formed and priced', () => {
  for (const id of ['single', 'pack5', 'pack20'] as const) {
    const p = CREDIT_PACKS[id];
    assert.equal(p.id, id);
    assert.ok(p.credits > 0);
    assert.ok(p.amountCents > 0);
  }
  assert.equal(CREDIT_PACKS.pack5.credits, 5);
});

test('Stripe is reported unconfigured without a secret key', () => {
  const prev = process.env.STRIPE_SECRET_KEY;
  delete process.env.STRIPE_SECRET_KEY;
  assert.equal(isStripeConfigured(), false);
  if (prev) process.env.STRIPE_SECRET_KEY = prev;
});

test('checkout creation fails fast when Stripe is not configured', async () => {
  const prev = process.env.STRIPE_SECRET_KEY;
  delete process.env.STRIPE_SECRET_KEY;
  await assert.rejects(createCheckoutSession('user_1', 'pack5', 'https://app.test'), /not configured/i);
  if (prev) process.env.STRIPE_SECRET_KEY = prev;
});

test('an invalid pack is rejected', async () => {
  process.env.STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || 'sk_test_dummy';
  await assert.rejects(createCheckoutSession('user_1', 'not-a-pack', 'https://app.test'), /invalid credit pack/i);
});

test('webhook parsing requires a configured signing secret', () => {
  const prev = process.env.STRIPE_WEBHOOK_SECRET;
  delete process.env.STRIPE_WEBHOOK_SECRET;
  assert.throws(() => parseWebhookEvent(Buffer.from('{}'), 'sig'), /webhook secret/i);
  if (prev) process.env.STRIPE_WEBHOOK_SECRET = prev;
});

import Stripe from 'stripe';
import { parseWebhookAction } from './stripe.js';

function signedEvent(type: string, object: Record<string, unknown>): { body: Buffer; sig: string } {
  process.env.STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || 'sk_test_unit';
  process.env.STRIPE_WEBHOOK_SECRET = 'whsec_unit_test_secret';
  const payload = JSON.stringify({ id: 'evt_1', object: 'event', type, data: { object } });
  const sig = new Stripe('sk_test_unit').webhooks.generateTestHeaderString({ payload, secret: 'whsec_unit_test_secret' });
  return { body: Buffer.from(payload), sig };
}
const paidSession = { id: 'cs_1', payment_status: 'paid', metadata: { userId: 'u1', credits: '5' } };

test('a paid checkout grants credits, whether it completes paid or becomes paid later', async () => {
  for (const type of ['checkout.session.completed', 'checkout.session.async_payment_succeeded']) {
    const { body, sig } = signedEvent(type, paidSession);
    assert.deepEqual(await parseWebhookAction(body, sig), { kind: 'grant', userId: 'u1', credits: 5, sessionId: 'cs_1' });
  }
  const unpaid = signedEvent('checkout.session.completed', { ...paidSession, payment_status: 'unpaid' });
  assert.equal(await parseWebhookAction(unpaid.body, unpaid.sig), null);
});

test('a full refund or a dispute reverses the session that took the payment; a partial refund does not', async () => {
  const lookup = async (pi: string) => (pi === 'pi_1' ? 'cs_1' : null);
  const full = signedEvent('charge.refunded', { id: 'ch_1', refunded: true, payment_intent: 'pi_1' });
  assert.deepEqual(await parseWebhookAction(full.body, full.sig, lookup), { kind: 'reverse', sessionId: 'cs_1', reason: 'refund' });
  const partial = signedEvent('charge.refunded', { id: 'ch_1', refunded: false, payment_intent: 'pi_1' });
  assert.equal(await parseWebhookAction(partial.body, partial.sig, lookup), null);
  const dispute = signedEvent('charge.dispute.created', { id: 'dp_1', payment_intent: 'pi_1' });
  assert.deepEqual(await parseWebhookAction(dispute.body, dispute.sig, lookup), { kind: 'reverse', sessionId: 'cs_1', reason: 'dispute' });
  const unknown = signedEvent('charge.refunded', { id: 'ch_2', refunded: true, payment_intent: 'pi_other' });
  assert.equal(await parseWebhookAction(unknown.body, unknown.sig, lookup), null);
});

test('a webhook with a bad signature is rejected', async () => {
  const { body } = signedEvent('checkout.session.completed', paidSession);
  await assert.rejects(() => parseWebhookAction(body, 't=1,v1=deadbeef'), /signature/i);
});
