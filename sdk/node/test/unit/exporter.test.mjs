import { test } from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { Exporter } from '../../dist/esm/export/exporter.js';
import { buildEvent, otlpBody } from '../../dist/esm/export/event.js';
import { SDK_VERSION } from '../../dist/esm/version.js';
import { generateCsr } from '../../dist/esm/fleet/asn1.js';
import { startFakeCore } from '../helpers/fake-core.mjs';

function counters() {
  return { events_sent: 0, events_dropped_queue: 0, events_rejected: 0, send_errors: 0 };
}

test('bounded queue drops the oldest events and counts them', () => {
  const c = counters();
  const ex = new Exporter({ url: 'https://127.0.0.1:1/v1/logs', agent: new https.Agent(), resource: { serviceName: 's', sourceId: 'src-1' }, counters: c, onError: () => {}, maxEvents: 3, flushMs: 60_000 });
  for (let i = 0; i < 5; i++) ex.enqueue({ json: '{"i":' + i + '}', tsMs: 0, policyHash: 'sha256:x' });
  assert.equal(ex.size.events, 3);
  assert.equal(c.events_dropped_queue, 2);
  ex.clear();
  assert.equal(ex.size.events, 0);
  assert.equal(c.events_dropped_queue, 5);
  ex.stop();
});

test('retries 503 with backoff over mTLS, then delivers', async () => {
  const core = await startFakeCore();
  try {
    const sourceId = 'src-test1';
    const { csrPem, keyPem } = generateCsr(sourceId);
    const agent = new https.Agent({ cert: core.pki.issueFromCsr(csrPem, sourceId), key: keyPem, ca: core.pki.caPem });
    const c = counters();
    const ex = new Exporter({ url: core.url + '/v1/logs', agent, resource: { serviceName: 'shop-api', sourceId }, counters: c, onError: () => {}, baseBackoffMs: 20, flushMs: 60_000 });
    core.state.failLogs = 2;
    ex.enqueue({ json: '{"a":1}', tsMs: Date.now(), policyHash: 'sha256:x', traceId: '4bf92f3577b34da6a3ce929d0e0e4736' });
    await ex.flush();
    assert.equal(c.events_sent, 1);
    assert.equal(c.send_errors, 2);
    assert.deepEqual(core.state.eventStrings, ['{"a":1}']);
    ex.stop();
    agent.destroy();
  } finally {
    await core.close();
  }
});

test('event assembly adds source fields and stays canonical', () => {
  const out = new Map([['service', 'shop-api'], ['op', 'GET /'], ['route_source', 'raw'], ['sampled_by', 'random'], ['req', new Map([['path', '/']])], ['resp', new Map([['size', 'l8']])]]);
  const s = buildEvent(out, { policyId: 'p-shop', policyVersion: 3, policyHash: 'sha256:' + 'a'.repeat(64), sourceId: 'src-1', dir: 'inbound', tsMs: Date.UTC(2026, 9, 19, 10, 0, 0, 412), latencyMs: 12.9, status: 200, traceId: '4bf92f3577b34da6a3ce929d0e0e4736', spanId: '00f067aa0ba902b7' });
  assert.equal(s, '{"dir":"inbound","latency_ms":12,"op":"GET /","policy":{"hash":"sha256:' + 'a'.repeat(64) + '","id":"p-shop","version":3},"req":{"path":"/"},"resp":{"size":"l8"},"route_source":"raw","sampled_by":"random","schema":"tt.http.exchange/v1","service":"shop-api","source":{"id":"src-1","kind":"sdk-node","version":"' + SDK_VERSION + '"},"span_id":"00f067aa0ba902b7","status":200,"trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","ts":"2026-10-19T10:00:00.412Z"}');
  const withErr = buildEvent(out, { policyId: 'p', policyVersion: 1, policyHash: 'sha256:x', sourceId: 'src-1', dir: 'outbound', tsMs: 0, latencyMs: 0, netError: 'timeout' });
  assert.ok(!withErr.includes('"resp"') && withErr.includes('"net_error":"timeout"'));
  const body = JSON.parse(otlpBody([{ json: s, tsMs: 1792404000412, policyHash: 'sha256:x' }], { serviceName: 'shop-api', sourceId: 'src-1' }, 1792404000700));
  assert.equal(body.resourceLogs[0].scopeLogs[0].logRecords[0].timeUnixNano, '1792404000412000000');
  assert.equal(body.resourceLogs[0].scopeLogs[0].logRecords[0].body.stringValue, s);
});
