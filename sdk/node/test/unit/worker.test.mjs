import { test } from 'node:test';
import assert from 'node:assert/strict';
import { basePolicy } from '../helpers/fake-core.mjs';
import { HMAC_KEY } from '../helpers/procs.mjs';
import { Sanitizer } from '../../dist/esm/sanitizer/sanitizer.js';
import { Policy, parseKeyRing, selectKey } from '../../dist/esm/sanitizer/policy.js';
import { nodeToPlain, parseJson } from '../../dist/esm/sanitizer/json.js';
import { sanitizeToRecord } from '../../dist/esm/export/pipeline.js';
import { otlpBody } from '../../dist/esm/export/event.js';
import { SanitizerPool } from '../../dist/esm/worker/pool.js';
import { BodyTap } from '../../dist/esm/capture/body.js';

function sanitizer() {
  const body = basePolicy({ services: [{ name: 'shop-api', match: { inbound: true, internal: false }, ops: [{ op: 'POST /orders', response: { body: [{ path: '$.id', action: { action: 'hmac', domain: 'order' } }, { path: '$.status', action: { action: 'keep' } }] } }] }] });
  const bytes = Buffer.from(JSON.stringify(body));
  const p = new Policy(nodeToPlain(parseJson(bytes), true));
  p.hash = 'sha256:' + '0'.repeat(64);
  p.bodyBytes = bytes;
  return new Sanitizer(p, selectKey(parseKeyRing(HMAC_KEY), p));
}

function job(i, san) {
  const ownBuf = (s) => Buffer.from(Uint8Array.from(Buffer.from(s)).buffer);
  return {
    san,
    job: {
      gen: 0,
      decision: { sampled: true, by: 'random' },
      meta: { dir: 'inbound', tsMs: 1792404000412 + i, latencyMs: 3, status: 201, traceId: '4bf92f3577b34da6a3ce929d0e0e4736', spanId: '00f067aa0ba902b7' },
      wire: {
        dir: 'inbound', service_name: 'shop-api', method: 'POST', target: '/orders?promo=AUTUMN10',
        req_headers: ['Host', '127.0.0.1:8080', 'Content-Type', 'application/json', 'Cookie', 'sid=9f8e7d6c5b4a'],
        req_body: ownBuf('{"email":"giulia.neri@example.com","n":' + i + '}'), req_body_total: 40, req_body_consumed: true, status: 201,
        resp_headers: 'HTTP/1.1 201 Created\r\nContent-Type: application/json; charset=utf-8\r\nSet-Cookie: cart=c-9f8e7d6c5b4a; Path=/\r\n\r\n',
        resp_body: ownBuf('{"id":"ORD-2026-000' + i + '","status":"CREATED"}'), resp_body_total: 45,
      },
    },
  };
}

const unobserved = (r) => r.replace(/"observedTimeUnixNano":"[0-9]+"/, '"observedTimeUnixNano":"0"');

test('a worker thread produces the same bytes as the inline pipeline', async () => {
  const san = sanitizer();
  const items = Array.from({ length: 40 }, (_, i) => job(i, san));
  const inline = items.map((x) => sanitizeToRecord(san, x.job.wire, x.job.decision, x.job.meta, 'src-1', Date.now()).record);
  assert.ok(inline.every((r) => typeof r === 'string' && r.includes('tkn') === false));

  const got = await new Promise((resolve, reject) => {
    const pool = new SanitizerPool({
      size: 1,
      onOut: (b) => { pool.terminate(); resolve(b); },
      onLost: () => reject(new Error('worker lost')),
    });
    pool.warm();
    const t = setInterval(() => {
      if (!pool.usable) return;
      clearInterval(t);
      assert.ok(pool.canHandle(san));
      assert.ok(pool.post(items.map((x) => ({ san, job: structuredClone(x.job, { transfer: [] }) })), 1000, 'src-1'));
    }, 10);
    setTimeout(() => reject(new Error('timeout')), 10_000).unref();
  });
  assert.equal(got.stale, false);
  assert.deepEqual(got.errs, []);
  assert.deepEqual(got.recs.map(unobserved), inline.map(unobserved));
});

test('batch results of a discarded epoch are not delivered', async () => {
  const san = sanitizer();
  const b = await new Promise((resolve, reject) => {
    const pool = new SanitizerPool({ size: 1, onOut: (x) => { pool.terminate(); resolve(x); }, onLost: () => reject(new Error('lost')) });
    pool.warm();
    const t = setInterval(() => {
      if (!pool.usable) return;
      clearInterval(t);
      pool.post([job(1, san)], 10, 'src-1');
      pool.discard();
    }, 10);
    setTimeout(() => reject(new Error('timeout')), 10_000).unref();
  });
  assert.equal(b.stale, true);
  assert.deepEqual(b.recs, []);
});

test('policies without their signed bytes stay on the main thread', () => {
  const san = sanitizer();
  san.policy.bodyBytes = undefined;
  const pool = new SanitizerPool({ size: 1, onOut: () => {}, onLost: () => {} });
  assert.equal(pool.canHandle(san), false);
});

test('prebuilt OTLP records give the same body as the batch encoder', () => {
  const e = { json: '{"a":"x\\"y"}', tsMs: 1792404000412, policyHash: 'sha256:x', traceId: '4bf92f3577b34da6a3ce929d0e0e4736', spanId: '00f067aa0ba902b7' };
  const res = { serviceName: 's', sourceId: 'src-1' };
  const body = JSON.parse(otlpBody([e, { ...e, traceId: 'nothex' }], res, 1792404000700));
  const recs = body.resourceLogs[0].scopeLogs[0].logRecords;
  assert.equal(recs[0].observedTimeUnixNano, '1792404000700000000');
  assert.equal(recs[0].traceId, e.traceId);
  assert.equal(recs[1].traceId, undefined);
  assert.equal(recs[1].body.stringValue, e.json);
  assert.deepEqual(body.resourceLogs[0].scopeLogs[0].scope.name, 'traffic-twin');
});

test('body tap keeps the first limit bytes in standalone buffers', () => {
  const tap = new BodyTap(10);
  tap.add(Buffer.from('abcd'));
  tap.add('efgh');
  tap.add(new Uint8Array([105, 106, 107, 108]));
  tap.add(Buffer.from('zzz'));
  assert.equal(tap.total, 15);
  const b = tap.bytes();
  assert.equal(b.toString(), 'abcdefghij');
  assert.equal(b.buffer.byteLength, b.length);
});
