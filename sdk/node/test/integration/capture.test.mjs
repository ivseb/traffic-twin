// End to end: an app started with `node --import @traffic-twin/sdk/register`, a fake
// carrier and a fake tt-core (enrollment with CA pin, mTLS heartbeat, signed policy,
// OTLP intake). Asserts the sanitized events and that the app's traffic is unchanged.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { statSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { basePolicy, startFakeCore } from '../helpers/fake-core.mjs';
import { HMAC_KEY, ROOT, call, spawnApp, startCarrier, tempDir } from '../helpers/procs.mjs';
import { nodeToOut, parseJson, writeCanonical } from '../../dist/esm/sanitizer/json.js';

let core;
let carrier;
let app;
let state;

function policyFor(carrierUrl) {
  return basePolicy({
    services: [
      {
        name: 'carrier',
        match: { base: carrierUrl },
        ops: [
          {
            op: 'POST /v1/shipments',
            request: { body: [{ path: '$.orderId', action: { action: 'hmac', domain: 'order' } }] },
            response: { body: [{ path: '$.status', action: { action: 'keep' } }] },
          },
          { op: 'GET /v1/shipments', request: { query: { orderId: { action: 'hmac', domain: 'order' } } } },
        ],
      },
      {
        name: 'shop-api',
        match: { inbound: true, internal: false },
        ops: [
          {
            op: 'POST /orders',
            response: {
              body: [
                { path: '$.id', action: { action: 'hmac', domain: 'order' } },
                { path: '$.status', action: { action: 'keep' } },
                { path: '$.total', action: { action: 'bucket', kind: 'num', bounds: [0, 50, 100, 250] } },
              ],
            },
          },
        ],
      },
    ],
  });
}

before(async () => {
  carrier = await startCarrier();
  core = await startFakeCore({ policy: policyFor(carrier.url) });
  state = tempDir();
  app = await spawnApp(join(ROOT, 'test', 'fixtures', 'app.mjs'), {
    register: true,
    env: {
      TT_ENROLL_URL: core.url,
      TT_ENROLL_TOKEN: core.token,
      TT_HMAC_KEY: HMAC_KEY,
      TT_SERVICE_NAME: 'shop-api',
      TT_STATE_DIR: state.dir,
      TT_EXPORT_FLUSH_MS: '200',
      TT_HEARTBEAT_INTERVAL_MS: '500',
      TT_POLICY_POLL_INTERVAL_MS: '500',
      CARRIER_URL: carrier.url,
    },
  });
  const ok = await core.waitFor((s) => s.heartbeats.some((h) => h.state === 'capturing'));
  assert.ok(ok, 'source reached the capturing state: ' + app.stderr());
});

after(async () => {
  await app?.stop();
  await core?.close();
  await carrier?.close();
  state?.cleanup();
});

test('enrollment used a CSR and the token pin; state files are private', () => {
  assert.equal(core.state.enrollments.length, 1);
  const e = core.state.enrollments[0];
  assert.match(e.csr, /BEGIN CERTIFICATE REQUEST/);
  assert.equal(e.source.kind, 'sdk-node');
  assert.equal(e.source.service_name, 'shop-api');
  assert.deepEqual(e.source.hmac_kids, ['k1']);
  for (const f of readdirSync(state.dir)) {
    assert.equal(statSync(join(state.dir, f)).mode & 0o777, 0o600, f);
  }
  assert.equal(statSync(state.dir).mode & 0o777, 0o700);
});

test('inbound and outbound exchanges become sanitized, correlated events', async () => {
  const before = core.state.events.length;
  const tp = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
  const r = await call(app.port, {
    method: 'POST',
    path: '/orders?promo=AUTUMN10',
    headers: { 'content-type': 'application/json', cookie: 'sid=9f8e7d6c5b4a', traceparent: tp },
    body: JSON.stringify({ items: [{ sku: 'TSHIRT-RED-M', qty: 2 }], email: 'giulia.neri@example.com', note: '' }),
  });
  assert.equal(r.status, 201);
  assert.equal(JSON.parse(r.body).status, 'CREATED');
  assert.ok(await core.waitFor((s) => s.events.length >= before + 3), 'three events arrived');
  const evs = core.state.events.slice(before).map((x) => x.event);
  const inbound = evs.find((e) => e.dir === 'inbound');
  const outs = evs.filter((e) => e.dir === 'outbound');
  assert.ok(inbound);
  assert.equal(outs.length, 2, JSON.stringify(outs.map((o) => [o.service, o.op, o.sampled_by])));

  assert.equal(inbound.schema, 'tt.http.exchange/v1');
  assert.equal(inbound.service, 'shop-api');
  assert.equal(inbound.op, 'POST /orders');
  assert.equal(inbound.route_source, 'policy');
  assert.equal(inbound.sampled_by, 'trace', 'traceparent present: sampled by trace (12.3)');
  assert.equal(inbound.status, 201);
  assert.equal(inbound.trace_id, '4bf92f3577b34da6a3ce929d0e0e4736');
  assert.equal(inbound.parent_span_id, '00f067aa0ba902b7');
  assert.match(inbound.span_id, /^[0-9a-f]{16}$/);
  assert.equal(inbound.source.kind, 'sdk-node');
  assert.match(inbound.source.id, /^src-/);
  assert.equal(inbound.policy.id, 'p-shop');
  assert.match(inbound.policy.hash, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(inbound.req.body, { email: 'drop:str:email', items: [{ qty: 'drop:int', sku: 'drop:str:l32' }], note: 'drop:str:l8' });
  assert.deepEqual(inbound.req.query, { promo: ['drop:str:l8'] });
  assert.deepEqual(inbound.req.cookies, { sid: ['drop:str:l32'] });
  assert.deepEqual(inbound.req.headers['content-type'], ['keep:application/json']);
  assert.equal(inbound.req.size, 'l128');
  assert.match(inbound.resp.body.id, /^tk1:k1:[A-Za-z0-9_-]{22}$/);
  assert.equal(inbound.resp.body.status, 'keep:CREATED');
  assert.equal(inbound.resp.body.total, 'num:50-100');
  assert.equal(inbound.resp.body.email, 'drop:str:email');
  assert.deepEqual(inbound.resp.cookies, { cart: ['drop:str:l32'] });

  const post = outs.find((e) => e.op === 'POST /v1/shipments');
  const get = outs.find((e) => e.op === 'GET /v1/shipments');
  assert.ok(post && get);
  for (const o of [post, get]) {
    assert.equal(o.service, 'carrier');
    assert.equal(o.sampled_by, 'inherited');
    assert.equal(o.trace_id, inbound.trace_id, 'outbound shares the inbound trace');
    assert.equal(o.parent_span_id, inbound.span_id);
  }
  // fetch (undici): body seen through the body chunk channels.
  assert.equal(post.req.body.orderId, inbound.resp.body.id, 'same order id, same token');
  assert.equal(post.req.body.email, 'drop:str:email');
  assert.equal(post.resp.body.status, 'keep:BOOKED');
  assert.equal(post.resp.body.shipmentId, 'drop:str:l32');
  assert.deepEqual(post.req.headers.authorization, ['drop:str:l32']);
  // node:http client
  assert.deepEqual(get.req.query, { orderId: [inbound.resp.body.id] });
  assert.equal(get.status, 200);
  assert.deepEqual(get.resp.body, { items: [{ shipmentId: 'drop:str:l32', status: 'drop:str:l8' }] });
});

test('events are canonical, carry no input value, and the OTLP envelope follows event.md', () => {
  for (const s of core.state.eventStrings) {
    assert.equal(writeCanonical(nodeToOut(parseJson(Buffer.from(s)))), s, 'byte-exact canonical form');
    for (const secret of ['giulia', 'ORD-2026', 'TSHIRT', '9f8e7d6c5b4a', 'carrier-api-key', 'SHP-5521', 'AUTUMN10']) {
      assert.ok(!s.includes(secret), 'value leaked: ' + secret);
    }
  }
  const req = core.state.otlpRequests[0];
  const attrs = Object.fromEntries(req.resourceLogs[0].resource.attributes.map((a) => [a.key, a.value.stringValue]));
  assert.equal(attrs['service.name'], 'shop-api');
  assert.equal(attrs['tt.source.kind'], 'sdk-node');
  const lr = req.resourceLogs[0].scopeLogs[0].logRecords[0];
  assert.equal(lr.eventName, 'tt.http.exchange');
  assert.equal(lr.severityNumber, 9);
  assert.match(lr.timeUnixNano, /^[0-9]+$/);
});

test('the app traffic is unchanged: no traceparent or baggage injected toward the carrier', () => {
  assert.ok(carrier.seen.length >= 2);
  for (const s of carrier.seen) {
    assert.equal(s.headers.traceparent, undefined);
    assert.equal(s.headers.baggage, undefined);
  }
});

test('heartbeat reports counters and overhead, never values', async () => {
  assert.ok(await core.waitFor((s) => s.heartbeats.at(-1).counters.events_sent >= 3));
  const hb = core.state.heartbeats.at(-1);
  assert.equal(hb.state, 'capturing');
  assert.ok(hb.counters.exchanges_seen >= 3);
  assert.equal(hb.counters.sanitizer_errors, 0);
  assert.ok(hb.overhead_us.p50 >= 0);
  assert.equal(hb.policy.id, 'p-shop');
  assert.ok(!JSON.stringify(hb).includes('giulia'));
});

test('kill switch stops capture; turning it off resumes it', async () => {
  core.state.kill = true;
  assert.ok(await core.waitFor((s) => s.heartbeats.at(-1).state === 'killed'));
  const n = core.state.events.length;
  const r = await call(app.port, { method: 'POST', path: '/orders', headers: { 'content-type': 'application/json' }, body: '{"email":"a@b.example"}' });
  assert.equal(r.status, 201, 'the app keeps working');
  await new Promise((res) => setTimeout(res, 800));
  assert.equal(core.state.events.length, n, 'no events while killed');
  core.state.kill = false;
  assert.ok(await core.waitFor((s) => s.heartbeats.at(-1).state === 'capturing'));
});

test('a policy replay below min_issued_seq is rejected (fail-closed)', async () => {
  core.state.minIssuedSeq = 5;
  assert.ok(await core.waitFor((s) => s.heartbeats.at(-1).state === 'policy_rejected'));
  const fresh = policyFor(carrier.url);
  fresh.issued_seq = 6;
  fresh.version = 2;
  core.setPolicy(fresh);
  assert.ok(await core.waitFor((s) => s.heartbeats.at(-1).state === 'capturing' && s.heartbeats.at(-1).policy?.issued_seq === 6));
});

// Usability test 4: at every policy change tt-core moves min_issued_seq to the new policy in the
// same heartbeat that announces it; the source must switch without reporting an error.
test('a normal policy change produces no error and no policy_rejected state', async () => {
  const from = core.state.heartbeats.length;
  const since = new Date().toISOString();
  for (const seq of [7, 8, 9]) {
    const next = policyFor(carrier.url);
    next.issued_seq = seq;
    next.version = seq;
    core.setPolicy(next);
    core.state.minIssuedSeq = seq;
    assert.ok(await core.waitFor((s) => s.heartbeats.at(-1).state === 'capturing' && s.heartbeats.at(-1).policy?.issued_seq === seq), 'switched to ' + seq);
  }
  const hbs = core.state.heartbeats.slice(from);
  assert.ok(!hbs.some((h) => h.state === 'policy_rejected'), 'states: ' + hbs.map((h) => h.state).join(','));
  const errs = (hbs.at(-1).last_errors ?? []).filter((e) => e.at >= since).map((e) => e.code);
  for (const bad of ['policy_below_min_issued_seq', 'policy_rejected']) assert.ok(!errs.includes(bad), 'errors: ' + errs.join(','));
});
