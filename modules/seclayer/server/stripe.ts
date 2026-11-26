import Stripe from 'stripe';

// Real Stripe Checkout integration. Credits are NEVER granted on session
// creation — only when a signature-verified `checkout.session.completed`
// webhook is received. When STRIPE_SECRET_KEY is unset the feature is disabled
// (callers receive a clear "not configured" response) rather than mocked.

export interface CreditPack {
  id: 'single' | 'pack5' | 'pack20';
  name: string;
  credits: number;
  amountCents: number;
}

export const CREDIT_PACKS: Record<CreditPack['id'], CreditPack> = {
  single: { id: 'single', name: 'Single Scan Credit', credits: 1, amountCents: 2900 },
  pack5: { id: 'pack5', name: '5 Scan Credits', credits: 5, amountCents: 9900 },
  pack20: { id: 'pack20', name: '20 Scan Credits', credits: 20, amountCents: 29900 },
};

let client: Stripe | null = null;

export function isStripeConfigured(): boolean {
  return !!process.env.STRIPE_SECRET_KEY;
}

function getStripe(): Stripe {
  if (!process.env.STRIPE_SECRET_KEY) {
    throw new Error('Stripe is not configured (STRIPE_SECRET_KEY is missing).');
  }
  if (!client) {
    client = new Stripe(process.env.STRIPE_SECRET_KEY);
  }
  return client;
}

// Creates a Checkout Session for a credit pack and returns the hosted URL.
// userId + credits are embedded in metadata so the webhook can grant credits.
export async function createCheckoutSession(
  userId: string,
  packId: string,
  baseUrl: string,
): Promise<string> {
  const pack = CREDIT_PACKS[packId as CreditPack['id']];
  if (!pack) throw new Error('Invalid credit pack selected.');

  const session = await getStripe().checkout.sessions.create({
    mode: 'payment',
    line_items: [
      {
        quantity: 1,
        price_data: {
          currency: 'usd',
          unit_amount: pack.amountCents,
          product_data: { name: `Seclayer — ${pack.name}` },
        },
      },
    ],
    metadata: { userId, credits: String(pack.credits), packId: pack.id },
    success_url: `${baseUrl}/dashboard?checkout_success=true`,
    cancel_url: `${baseUrl}/dashboard?checkout_canceled=true`,
  });

  if (!session.url) throw new Error('Stripe did not return a checkout URL.');
  return session.url;
}

export interface CheckoutCompletion {
  userId: string;
  credits: number;
  sessionId: string;
}

function verifiedEvent(rawBody: Buffer, signature: string | undefined): Stripe.Event {
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) throw new Error('Stripe webhook secret (STRIPE_WEBHOOK_SECRET) is not configured.');
  if (!signature) throw new Error('Missing Stripe-Signature header.');
  return getStripe().webhooks.constructEvent(rawBody, signature, secret);
}

// A Checkout session that finished and is PAID. Card payments are paid when
// checkout.session.completed arrives; delayed methods (bank debits and the like, if they are ever
// enabled in the dashboard) complete unpaid and only become paid on async_payment_succeeded, so a
// grant has to listen for both or those customers pay and never get their credits.
const GRANT_EVENTS = new Set(['checkout.session.completed', 'checkout.session.async_payment_succeeded']);

function grantFromEvent(event: Stripe.Event): CheckoutCompletion | null {
  if (!GRANT_EVENTS.has(event.type)) return null;

  const session = event.data.object as Stripe.Checkout.Session;
  if (session.payment_status !== 'paid') return null;

  const userId = session.metadata?.userId;
  const credits = Number(session.metadata?.credits);
  if (!userId || !Number.isFinite(credits) || credits <= 0) return null;

  return { userId, credits, sessionId: session.id };
}

// Verifies a webhook payload and, for a completed & paid checkout, returns the
// credit grant to apply. Returns null for other event types. Throws on an
// invalid signature so the caller can respond 400.
export function parseWebhookEvent(rawBody: Buffer, signature: string | undefined): CheckoutCompletion | null {
  return grantFromEvent(verifiedEvent(rawBody, signature));
}

export type WebhookAction =
  | ({ kind: 'grant' } & CheckoutCompletion)
  | { kind: 'reverse'; sessionId: string; reason: 'refund' | 'dispute' };

// Finds the Checkout session that took a payment, so a refund or dispute on the payment can be
// traced back to the credits it bought.
export type SessionLookup = (paymentIntentId: string) => Promise<string | null>;

const lookupSessionByPaymentIntent: SessionLookup = async (paymentIntentId) => {
  const found = await getStripe().checkout.sessions.list({ payment_intent: paymentIntentId, limit: 1 });
  return found.data[0]?.id ?? null;
};

const paymentIntentId = (v: string | { id: string } | null | undefined): string | null =>
  typeof v === 'string' ? v : v?.id ?? null;

// Everything the webhook acts on: a paid checkout grants credits; a FULL refund or a dispute takes
// them back. A partial refund is deliberately left alone: there is no sensible fraction of a credit
// pack to reverse, and a person can settle that by hand. Throws on a bad signature (respond 400)
// and when the session lookup fails (respond 5xx so Stripe retries).
export async function parseWebhookAction(
  rawBody: Buffer,
  signature: string | undefined,
  lookup: SessionLookup = lookupSessionByPaymentIntent,
): Promise<WebhookAction | null> {
  const event = verifiedEvent(rawBody, signature);

  const grant = grantFromEvent(event);
  if (grant) return { kind: 'grant', ...grant };

  let pi: string | null = null;
  let reason: 'refund' | 'dispute';
  if (event.type === 'charge.refunded') {
    const charge = event.data.object as Stripe.Charge;
    if (!charge.refunded) return null;
    pi = paymentIntentId(charge.payment_intent);
    reason = 'refund';
  } else if (event.type === 'charge.dispute.created') {
    pi = paymentIntentId((event.data.object as Stripe.Dispute).payment_intent);
    reason = 'dispute';
  } else {
    return null;
  }
  if (!pi) return null;
  const sessionId = await lookup(pi);
  return sessionId ? { kind: 'reverse', sessionId, reason } : null;
}
