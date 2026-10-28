// ARCHITECTURE 3.2: an app with @opentelemetry/sdk-node keeps exporting exactly the same
// spans when the traffic-twin SDK is loaded, and the SDK reads (never replaces) its context.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { startFakeCore, basePolicy } from '../helpers/fake-core.mjs';
import { HMAC_KEY, ROOT, call, spawnApp, tempDir } from '../helpers/procs.mjs';

const APP = join(ROOT, 'test', 'fixtures', 'otel-app.cjs');
const OTEL_ENV = { OTEL_METRICS_EXPORTER: 'none', OTEL_LOGS_EXPORTER: 'none', OTEL_SDK_DISABLED: 'false' };

async function exercise(app) {
  for (let i = 0; i < 3; i++) {
    const r = await call(app.port, { path: '/work' });
    assert.equal(r.status, 200);
    const j = JSON.parse(r.body);
    assert.equal(j.a.traceparent, 'present', 'OpenTelemetry still propagates its own context');
  }
  await new Promise((r) => setTimeout(r, 200));
  return JSON.parse((await call(app.port, { path: '/spans' })).body);
}

function shape(spans) {
  const index = new Map(spans.map((s, i) => [s.spanId, i]));
  return spans
    .map((s) => ({ name: s.name, kind: s.kind, status: s.status, attributes: s.attributes, parent: index.has(s.parentSpanId) ? spans[index.get(s.parentSpanId)].name + '/' + spans[index.get(s.parentSpanId)].kind : null }))
    .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
}

test('OpenTelemetry spans are unchanged with the SDK loaded, and events reuse the OTel trace', async () => {
  const plain = await spawnApp(APP, { env: OTEL_ENV });
  let without;
  try {
    without = await exercise(plain);
  } finally {
    await plain.stop();
  }

  const core = await startFakeCore({ policy: basePolicy() });
  const st = tempDir();
  const withSdk = await spawnApp(APP, {
    nodeArgs: ['--require', join(ROOT, 'dist', 'cjs', 'register.js')],
    env: {
      ...OTEL_ENV,
      TT_ENROLL_URL: core.url,
      TT_ENROLL_TOKEN: core.token,
      TT_HMAC_KEY: HMAC_KEY,
      TT_SERVICE_NAME: 'shop-api',
      TT_STATE_DIR: st.dir,
      TT_EXPORT_FLUSH_MS: '200',
    },
  });
  let withTt;
  try {
    assert.ok(await core.waitFor((s) => s.policyFetches > 0 && s.heartbeats.length > 0), 'enrolled');
    await new Promise((r) => setTimeout(r, 300));
    withTt = await exercise(withSdk);
    // All the events of the exercise (>= 15, see below) before stopping the app,
    // not just the first ones: the export is batched every 200 ms.
    assert.ok(await core.waitFor((s) => s.events.length >= 15), 'events exported');
  } finally {
    await withSdk.stop();
    await core.close();
    st.cleanup();
  }

  assert.equal(withTt.provider, without.provider, 'the app keeps its own tracer provider');
  assert.ok(without.spans.length >= 9, 'the app exports spans: ' + without.spans.length);
  assert.equal(withTt.spans.length, without.spans.length, 'same number of spans');
  assert.deepEqual(shape(withTt.spans), shape(without.spans), 'same span names, kinds, attributes and structure');

  // The SDK read the active OpenTelemetry context: events share the app's trace ids.
  const traces = new Set(withTt.spans.map((s) => s.traceId));
  const evs = core.state.events.map((e) => e.event);
  const inbound = evs.filter((e) => e.dir === 'inbound' && e.op.startsWith('GET /'));
  assert.ok(inbound.length >= 3);
  // Per /work: inbound /work, two outbound calls, two downstream inbound requests. Only the
  // final GET /spans may carry a trace whose server span was not finished when listed.
  const matched = evs.filter((e) => traces.has(e.trace_id));
  assert.ok(matched.length >= 15, `events on OpenTelemetry traces: ${matched.length}/${evs.length}`);
  assert.ok(evs.length - matched.length <= 1, `events off OpenTelemetry traces: ${evs.length - matched.length}`);
});
