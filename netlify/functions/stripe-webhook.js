// Kept Voices Stripe webhook → keptvoices-api gift-token issuer
//
// Purpose: receive checkout.session.completed events from Stripe Checkout,
// verify signature, and forward to the FastAPI gift-token-issuer at
// keptvoices-api.ai-civ.com via X-Internal-Auth shared secret. The FastAPI
// side mints the gift token, fires the buyer's thank-you email, and stores
// the gift row (idempotent on stripe_session_id).
//
// Stripe expects 2xx within ~30s or it retries. We do best-effort forwarding;
// if FastAPI is down, we still 200 (Stripe replays via stripe_event_id and
// FastAPI dedupes via webhook_events table).
//
// Required env vars (Netlify site settings):
//   STRIPE_SECRET_KEY            — for stripe SDK init
//   STRIPE_WEBHOOK_SECRET_KV     — webhook signing secret for THIS endpoint
//                                  (separate from aiciv-inc's webhook secret)
//   KEPTVOICES_INTERNAL_SECRET   — shared with FastAPI systemd drop-in
//   KEPTVOICES_API_BASE          — defaults to https://keptvoices-api.ai-civ.com
//
// Subsystem contract: projects/keptvoices-api/FIRING_CONTRACT_gift_tokens.md

const https = require('https');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const KEPTVOICES_API_BASE = process.env.KEPTVOICES_API_BASE || 'https://keptvoices-api.ai-civ.com';
const PAYMENT_VERIFIED_PATH = '/api/keptvoices/internal/payment-verified';

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  const signature = event.headers['stripe-signature'] || event.headers['Stripe-Signature'];
  if (!signature) {
    console.error('kv-stripe-webhook: missing stripe-signature header');
    return { statusCode: 400, body: 'Missing stripe-signature header' };
  }

  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET_KV;
  if (!webhookSecret) {
    console.error('kv-stripe-webhook: STRIPE_WEBHOOK_SECRET_KV not configured');
    return { statusCode: 500, body: 'Webhook secret not configured' };
  }

  const internalSecret = process.env.KEPTVOICES_INTERNAL_SECRET;
  if (!internalSecret) {
    console.error('kv-stripe-webhook: KEPTVOICES_INTERNAL_SECRET not configured');
    return { statusCode: 500, body: 'Internal secret not configured' };
  }

  // Stripe signature verification needs raw bytes the webhook was signed against.
  const rawBody = event.isBase64Encoded
    ? Buffer.from(event.body, 'base64').toString('utf8')
    : event.body;

  let stripeEvent;
  try {
    stripeEvent = stripe.webhooks.constructEvent(rawBody, signature, webhookSecret);
  } catch (err) {
    console.error('kv-stripe-webhook: signature verification failed:', err.message);
    return { statusCode: 400, body: `Webhook signature verification failed: ${err.message}` };
  }

  console.log(`kv-stripe-webhook: received ${stripeEvent.type} (id=${stripeEvent.id})`);

  if (stripeEvent.type !== 'checkout.session.completed') {
    return {
      statusCode: 200,
      body: JSON.stringify({ received: true, ignored: stripeEvent.type }),
    };
  }

  const session = stripeEvent.data.object;
  const metadata = session.metadata || {};

  const buyerEmail = session.customer_email
    || (session.customer_details && session.customer_details.email)
    || null;
  const buyerName = (session.customer_details && session.customer_details.name) || null;

  if (!buyerEmail) {
    console.error('kv-stripe-webhook: missing buyer email on session', session.id);
    // Still 200 — Stripe retries don't help for missing customer data.
    return { statusCode: 200, body: JSON.stringify({ received: true, error: 'missing_buyer_email' }) };
  }

  // Resolve buyer-note audio: the upload endpoint returned a blob_id which the
  // browser placed in metadata. We construct the serve URL here so FastAPI
  // doesn't have to know about Netlify-side env conventions.
  let buyerNoteAudioUrl = null;
  if (metadata.kv_buyer_note_blob_id) {
    const blobId = String(metadata.kv_buyer_note_blob_id).trim();
    if (/^[0-9A-HJKMNPQRSTVWXYZ]{12}$/.test(blobId)) {
      buyerNoteAudioUrl = `${KEPTVOICES_API_BASE}/api/keptvoices/buyer-note/${blobId}`;
    } else {
      console.warn('kv-stripe-webhook: invalid blob_id format in metadata, ignoring:', blobId);
    }
  }

  const payload = {
    stripe_session_id: session.id,
    stripe_payment_intent: session.payment_intent || null,
    stripe_event_id: stripeEvent.id,
    buyer_email: buyerEmail,
    buyer_name: buyerName,
    buyer_note_text: metadata.kv_buyer_note_text || null,
    buyer_note_audio_url: buyerNoteAudioUrl,
    amount_cents: session.amount_total || 0,
    currency: (session.currency || 'usd').toLowerCase(),
    tier: metadata.kv_tier || 'founding_cohort',
    mothers_day_deal: metadata.kv_mothers_day_deal === 'true' || metadata.kv_mothers_day_deal === '1',
    upsell_copies: parseInt(metadata.kv_upsell_copies || '1', 10) || 1,
    referral_code: metadata.kv_referral_code || null,
    subject_hint: metadata.kv_subject_hint || null,
    onboarding_register: metadata.kv_onboarding_register || 'register_3_buyer_voice_first',
  };

  try {
    const target = parseBase(KEPTVOICES_API_BASE);
    const response = await postJson({
      hostname: target.hostname,
      port: target.port,
      protocol: target.protocol,
      path: PAYMENT_VERIFIED_PATH,
      headers: { 'X-Internal-Auth': internalSecret },
    }, payload);
    console.log(`kv-stripe-webhook: payment_verified ok session=${session.id} status=${response.status}`);
    return {
      statusCode: 200,
      body: JSON.stringify({ received: true, forwarded: true, session_id: session.id }),
    };
  } catch (err) {
    // Log loud but still 200 — FastAPI dedupe via stripe_event_id will catch on retry.
    console.error(`kv-stripe-webhook: forward failed session=${session.id}:`, err.message);
    return {
      statusCode: 200,
      body: JSON.stringify({ received: true, forwarded: false, error: err.message }),
    };
  }
};

function parseBase(url) {
  const u = new URL(url);
  const isHttps = u.protocol === 'https:';
  return {
    protocol: u.protocol,
    hostname: u.hostname,
    port: u.port ? parseInt(u.port, 10) : (isHttps ? 443 : 80),
  };
}

function postJson(options, payload) {
  const body = JSON.stringify(payload);
  const requestOptions = {
    hostname: options.hostname,
    port: options.port || 443,
    path: options.path,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
      ...(options.headers || {}),
    },
  };
  const transport = options.protocol === 'http:' ? require('http') : https;
  return new Promise((resolve, reject) => {
    const req = transport.request(requestOptions, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        if (res.statusCode >= 400) {
          reject(new Error(`HTTP ${res.statusCode}: ${data}`));
        } else {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(20000, () => {
      req.destroy(new Error('request_timeout_20s'));
    });
    req.write(body);
    req.end();
  });
}
