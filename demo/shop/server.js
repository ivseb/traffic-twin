// shop-api: a tiny invented e-commerce backend for the traffic-twin demo.
// Zero dependencies: node:http + global fetch. State is in memory.
//
//   POST /orders                      create an order, register a carrier shipment
//   GET  /orders/{id}                 read one of your orders
//   GET  /customers/{id}/orders       list your orders
//   GET  /orders/{id}/shipment        live shipment status from the carrier
//   GET  /__truth                     exact counts produced (not part of the API)
//   GET  /__health                    liveness

import http from 'node:http';
import { createHash, randomBytes } from 'node:crypto';

const PORT = Number(process.env.PORT ?? 3000);
const CARRIER = (process.env.CARRIER_BASE_URL ?? 'http://localhost:8080').replace(/\/$/, '');
const CARRIER_ATTEMPTS = 3;

// ---- simulated clock (mirror of demo/internal/simclock) --------------------
const TIME_SCALE = Number(process.env.TIME_SCALE || 60);
const SIM_EPOCH = Date.parse(process.env.SIM_EPOCH || '2026-10-19T06:00:00Z');
const CLOCK_ANCHOR = process.env.CLOCK_ANCHOR
  ? Number(process.env.CLOCK_ANCHOR) * 1000
  : new Date().setUTCHours(0, 0, 0, 0);
const simNow = () => new Date(SIM_EPOCH + (Date.now() - CLOCK_ANCHOR) * TIME_SCALE);
const isoSeconds = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');

// ---- seeded ids --------------------------------------------------------------
// mulberry32: tiny deterministic PRNG so ids are reproducible for a seed.
function mulberry32(a) {
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rand = mulberry32(Number(process.env.SEED || 42) ^ 0x5b0b);
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
function newOrderId() {
  let id;
  do {
    id = 'ORD-';
    for (let i = 0; i < 10; i++) id += ALPHABET[Math.floor(rand() * ALPHABET.length)];
  } while (orders.has(id));
  return id;
}

// ---- catalog and state -------------------------------------------------------
const CATALOG = {
  'SKU-MUG-001': 1290, 'SKU-TEA-014': 850, 'SKU-BAG-203': 3490, 'SKU-PEN-077': 499,
  'SKU-LMP-310': 5900, 'SKU-BKS-120': 1800, 'SKU-SCK-045': 990, 'SKU-PLT-388': 2450,
};
const COUPONS = { WELCOME10: 0.10, AUTUMN15: 0.15 };
const orders = new Map();          // id -> order
const ordersByCustomer = new Map(); // customerId -> [id]
const idempotency = new Map();     // customerId|key -> { hash, orderId }

// ---- exact counts --------------------------------------------------------------
const truth = { requests: {}, carrier_calls: {}, presence: {} };
const bump = (obj, k1, k2) => { (obj[k1] ??= {})[k2] = (obj[k1][k2] ?? 0) + 1; };
function countPresence(scope, obj, fields) {
  for (const f of fields) {
    const present = f.split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj) !== undefined;
    bump(truth.presence, scope, `${f}:${present ? 'present' : 'absent'}`);
  }
}

// ---- helpers ---------------------------------------------------------------------
class HttpError extends Error {
  constructor(status, code, message, extra = {}) { super(message); Object.assign(this, { status, code, extra }); }
}
const invalid = (field, message) => new HttpError(400, 'VALIDATION_ERROR', message, { field });

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > 64 * 1024) throw new HttpError(413, 'PAYLOAD_TOO_LARGE', 'body exceeds 64 KiB');
    chunks.push(c);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || 'null'); }
  catch { throw new HttpError(400, 'INVALID_JSON', 'request body is not valid JSON'); }
}

// Fake, unsigned JWT: header.payload.(empty). Only `sub` matters.
function authenticate(req) {
  const m = /^Bearer ([\w-]+)\.([\w-]+)\.[\w-]*$/.exec(req.headers.authorization ?? '');
  if (!m) throw new HttpError(401, 'UNAUTHENTICATED', 'missing or malformed bearer token');
  try {
    const claims = JSON.parse(Buffer.from(m[2], 'base64url').toString('utf8'));
    if (typeof claims.sub !== 'string' || !claims.sub) throw new Error('no sub');
    return claims.sub;
  } catch {
    throw new HttpError(401, 'UNAUTHENTICATED', 'token payload has no subject');
  }
}

// W3C trace context: keep the caller's trace id, new span for each hop.
function traceparent(req) {
  const m = /^00-([0-9a-f]{32})-[0-9a-f]{16}-([0-9a-f]{2})$/.exec(req.headers.traceparent ?? '');
  const traceId = m ? m[1] : randomBytes(16).toString('hex');
  return `00-${traceId}-${randomBytes(8).toString('hex')}-${m ? m[2] : '01'}`;
}

async function carrierFetch(op, path, init, req) {
  const res = await fetch(CARRIER + path, {
    ...init,
    headers: { 'content-type': 'application/json', traceparent: traceparent(req), ...(init.headers ?? {}) },
    signal: AbortSignal.timeout(5000),
  });
  bump(truth.carrier_calls, op, String(res.status));
  return { status: res.status, body: await res.json().catch(() => null) };
}

// ---- validation ------------------------------------------------------------------
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
function validateOrder(b) {
  if (b == null || typeof b !== 'object' || Array.isArray(b)) throw invalid('', 'body must be a JSON object');
  if (!Array.isArray(b.items) || b.items.length === 0) throw invalid('items', 'items must be a non-empty array');
  if (b.items.length > 20) throw invalid('items', 'at most 20 items per order');
  b.items.forEach((it, i) => {
    if (typeof it?.sku !== 'string') throw invalid(`items[${i}].sku`, 'sku is required');
    if (!(it.sku in CATALOG)) throw new HttpError(400, 'UNKNOWN_SKU', `unknown sku ${it.sku}`, { field: `items[${i}].sku` });
    if (!Number.isInteger(it.qty) || it.qty < 1 || it.qty > 10) throw invalid(`items[${i}].qty`, 'qty must be an integer between 1 and 10');
  });
  if (typeof b.email !== 'string' || !EMAIL.test(b.email)) throw invalid('email', 'a valid email is required');
  const a = b.shippingAddress;
  if (a == null || typeof a !== 'object') throw invalid('shippingAddress', 'shippingAddress is required');
  for (const f of ['fullName', 'line1', 'city', 'postcode', 'country']) {
    if (typeof a[f] !== 'string' || !a[f].trim()) throw invalid(`shippingAddress.${f}`, `${f} is required`);
  }
  if (!/^[A-Z]{2}$/.test(a.country)) throw invalid('shippingAddress.country', 'country must be ISO 3166-1 alpha-2');
  if (b.note !== undefined && (typeof b.note !== 'string' || b.note.length > 500)) throw invalid('note', 'note must be a string up to 500 chars');
  if (b.couponCode !== undefined && !(b.couponCode in COUPONS)) throw new HttpError(400, 'INVALID_COUPON', 'coupon not recognised', { field: 'couponCode' });
  if (b.giftWrap !== undefined && typeof b.giftWrap !== 'boolean') throw invalid('giftWrap', 'giftWrap must be a boolean');
}

// ---- handlers ----------------------------------------------------------------------
async function createOrder(req, res) {
  const customerId = authenticate(req);
  const body = await readJson(req);
  validateOrder(body);

  const key = req.headers['idempotency-key'];
  const hash = createHash('sha256').update(JSON.stringify(body)).digest('hex');
  const prior = key ? idempotency.get(`${customerId}|${key}`) : undefined;
  if (prior && prior.hash !== hash) {
    throw new HttpError(409, 'IDEMPOTENCY_KEY_REUSED', 'Idempotency-Key was already used with a different body');
  }
  if (prior) return send(res, 201, orderView(orders.get(prior.orderId)), { 'idempotent-replayed': 'true' });

  const id = newOrderId();
  const a = body.shippingAddress;
  const shipmentReq = {
    orderId: id,
    service: body.items.length > 3 ? 'EXPRESS' : 'STANDARD',
    parcels: Math.ceil(body.items.reduce((n, it) => n + it.qty, 0) / 4),
    recipient: { fullName: a.fullName, email: body.email, ...(body.phone ? { phone: body.phone } : {}) },
    address: { line1: a.line1, ...(a.line2 ? { line2: a.line2 } : {}), city: a.city, postcode: a.postcode, country: a.country },
  };
  // The carrier is flaky (1% 503). Retry: a 503 never creates a shipment, so retrying is safe.
  let shipment;
  for (let attempt = 1; attempt <= CARRIER_ATTEMPTS && !shipment; attempt++) {
    try {
      const r = await carrierFetch('POST /v1/shipments', '/v1/shipments', { method: 'POST', body: JSON.stringify(shipmentReq) }, req);
      if (r.status === 202) shipment = r.body;
      else if (r.status !== 503) throw new HttpError(502, 'CARRIER_REJECTED', `carrier answered ${r.status}`);
    } catch (e) {
      if (e instanceof HttpError) throw e;
    }
    if (!shipment) await new Promise((ok) => setTimeout(ok, 50 * attempt));
  }
  if (!shipment) throw new HttpError(503, 'CARRIER_UNAVAILABLE', 'shipping partner unavailable, order not placed', { retryable: true });

  const subtotal = body.items.reduce((n, it) => n + CATALOG[it.sku] * it.qty, 0);
  const discount = body.couponCode ? Math.round(subtotal * COUPONS[body.couponCode]) : undefined;
  const order = {
    id, customerId, status: 'CONFIRMED',
    items: body.items.map((it) => ({ sku: it.sku, qty: it.qty, unitPrice: CATALOG[it.sku] / 100 })),
    currency: 'EUR',
    subtotal: subtotal / 100,
    ...(discount !== undefined ? { couponCode: body.couponCode, discount: discount / 100 } : {}),
    total: (subtotal - (discount ?? 0)) / 100,
    email: body.email,
    ...(body.phone ? { phone: body.phone } : {}),
    shippingAddress: { ...a },
    ...(body.note !== undefined ? { note: body.note } : {}),
    ...(body.giftWrap !== undefined ? { giftWrap: body.giftWrap } : {}),
    shipmentId: shipment.shipmentId,
    createdAt: isoSeconds(simNow()),
  };
  orders.set(id, order);
  (ordersByCustomer.get(customerId) ?? ordersByCustomer.set(customerId, []).get(customerId)).push(id);
  if (key) idempotency.set(`${customerId}|${key}`, { hash, orderId: id });

  const view = orderView(order);
  countPresence('POST /orders 201', view, ['phone', 'note', 'couponCode', 'discount', 'giftWrap', 'shippingAddress.line2']);
  send(res, 201, view, { location: `/orders/${id}` });
}

const orderView = (o) => structuredClone(o);

function ownOrder(customerId, id) {
  const o = orders.get(id);
  // Someone else's order is reported as missing: do not leak existence.
  if (!o || o.customerId !== customerId) throw new HttpError(404, 'ORDER_NOT_FOUND', `order ${id} not found`);
  return o;
}

async function getOrder(req, res, { id }) {
  const customerId = authenticate(req);
  send(res, 200, orderView(ownOrder(customerId, id)));
}

async function listCustomerOrders(req, res, { id }) {
  const customerId = authenticate(req);
  if (id !== customerId) throw new HttpError(403, 'FORBIDDEN', 'you can only list your own orders');
  const items = (ordersByCustomer.get(id) ?? []).map((oid) => {
    const o = orders.get(oid);
    return { id: o.id, status: o.status, total: o.total, currency: o.currency, createdAt: o.createdAt };
  });
  send(res, 200, { customerId: id, count: items.length, items });
}

async function getShipment(req, res, { id }) {
  const customerId = authenticate(req);
  const o = ownOrder(customerId, id);
  let r;
  try {
    r = await carrierFetch('GET /v1/shipments', `/v1/shipments?orderId=${encodeURIComponent(o.id)}`, { method: 'GET' }, req);
  } catch {
    r = { status: 599 };
  }
  if (r.status !== 200) throw new HttpError(503, 'TRACKING_UNAVAILABLE', 'shipment tracking temporarily unavailable', { retryable: true });
  const s = r.body?.items?.[0];
  if (!s) throw new HttpError(404, 'SHIPMENT_NOT_FOUND', 'the carrier has not registered a shipment for this order yet');
  const view = {
    orderId: o.id, shipmentId: s.shipmentId, status: s.status, updatedAt: s.updatedAt,
    ...(s.eta ? { eta: s.eta } : {}),
    ...(s.cancelReason ? { cancelReason: s.cancelReason } : {}),
  };
  countPresence('GET /orders/{id}/shipment 200', view, ['eta', 'cancelReason']);
  send(res, 200, view);
}

// ---- routing -------------------------------------------------------------------------
const ROUTES = [
  ['POST', /^\/orders$/, 'POST /orders', createOrder],
  ['GET', /^\/orders\/(?<id>[^/]+)$/, 'GET /orders/{id}', getOrder],
  ['GET', /^\/orders\/(?<id>[^/]+)\/shipment$/, 'GET /orders/{id}/shipment', getShipment],
  ['GET', /^\/customers\/(?<id>[^/]+)\/orders$/, 'GET /customers/{id}/orders', listCustomerOrders],
];

const server = http.createServer(async (req, res) => {
  const path = new URL(req.url, 'http://shop.local').pathname;
  if (req.method === 'GET' && path === '/__health') return send(res, 200, { status: 'ok' });
  if (req.method === 'GET' && path === '/__truth') {
    return send(res, 200, { service: 'shop-api', note: 'exact counts, not estimates', sim_now: simNow(), ...truth });
  }
  const matches = ROUTES.filter(([, re]) => re.test(path));
  const route = matches.find(([m]) => m === req.method);
  const op = route?.[2] ?? `${req.method} ${path}`;
  try {
    if (!route) {
      if (matches.length) throw new HttpError(405, 'METHOD_NOT_ALLOWED', `${req.method} not allowed here`);
      throw new HttpError(404, 'NOT_FOUND', `no route for ${req.method} ${path}`);
    }
    await route[3](req, res, route[1].exec(path).groups ?? {});
  } catch (e) {
    if (!(e instanceof HttpError)) {
      console.error(e);
      e = new HttpError(500, 'INTERNAL', 'unexpected error');
    }
    send(res, e.status, { error: { code: e.code, message: e.message, ...e.extra } });
  } finally {
    if (route) bump(truth.requests, op, String(res.statusCode));
  }
});

server.keepAliveTimeout = 65_000;
server.listen(PORT, () => {
  console.log(`shop-api listening on :${PORT}, carrier=${CARRIER}, time_scale=${TIME_SCALE}, sim_now=${simNow().toISOString()}`);
});
