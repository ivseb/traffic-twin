// Overhead benchmark (threat model G10, M12): the same app with the SDK off and on. Each
// POST /orders is one inbound exchange plus two outbound calls (fetch and node:http) to a
// local carrier; with the SDK on, all three are captured, sanitized and exported over mTLS
// to a fake tt-core running in this process. No external load tool.
//
//   node bench/overhead.mjs [--seconds 8] [--concurrency 16] [--rounds 2]
//                           [--rate-bp 10000] [--steady-rps 300] [--threads N] [--endpoint orders|health]
//                           [--io-ms 2] [--profile <dir>]
//
// Two measurements per mode:
//   steady:     open loop at a fixed request rate, below saturation: latency added per request;
//   saturation: closed loop with N concurrent clients: maximum throughput (CPU cost).

import http from 'node:http';
import { join } from 'node:path';
import { basePolicy, startFakeCore } from '../test/helpers/fake-core.mjs';
import { HMAC_KEY, ROOT, spawnApp, startCarrier, tempDir } from '../test/helpers/procs.mjs';

const arg = (name, d) => {
  const i = process.argv.indexOf('--' + name);
  return i > 0 ? Number(process.argv[i + 1]) : d;
};
const SECONDS = arg('seconds', 8);
const CONC = arg('concurrency', 16);
const ROUNDS = arg('rounds', 5);
const RATE_BP = arg('rate-bp', 10000);
const STEADY_RPS = arg('steady-rps', 300);
const THREADS = process.argv.includes('--threads') ? String(arg('threads', 0)) : undefined; // sanitizer worker threads (default: SDK default)
const ENDPOINT = process.argv.includes('--endpoint') ? process.argv[process.argv.indexOf('--endpoint') + 1] : 'orders'; // orders | health
const IO_MS = arg('io-ms', 0); // orders only: the handler waits this long (async I/O) before answering
const PROFILE = process.argv.includes('--profile') ? process.argv[process.argv.indexOf('--profile') + 1] : '';
const APP = join(ROOT, 'test', 'fixtures', 'app.mjs');
const BODY = JSON.stringify({ items: [{ sku: 'TSHIRT-RED-M', qty: 2 }, { sku: 'MUG-BLUE', qty: 1 }], email: 'giulia.neri@example.com', note: 'leave at the door' });

function once(agent, port) {
  return new Promise((resolve, reject) => {
    const t0 = process.hrtime.bigint();
    const health = ENDPOINT === 'health';
    const req = http.request({ host: '127.0.0.1', port, method: health ? 'GET' : 'POST', path: health ? '/health' : '/orders', agent, headers: health ? {} : { 'content-type': 'application/json', 'content-length': Buffer.byteLength(BODY) } }, (res) => {
      res.resume();
      res.on('end', () => resolve(Number(process.hrtime.bigint() - t0) / 1e6));
    });
    req.on('error', reject);
    req.end(health ? undefined : BODY);
  });
}

function cpu(port) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: '/__cpu' }, (res) => {
      let b = '';
      res.on('data', (c) => (b += c));
      res.on('end', () => resolve(JSON.parse(b)));
    }).on('error', reject);
  });
}

function stats(lat, seconds) {
  lat.sort((a, b) => a - b);
  const q = (f) => lat[Math.min(lat.length - 1, Math.floor(f * lat.length))];
  return { n: lat.length, rps: lat.length / seconds, p50: q(0.5), p99: q(0.99) };
}

async function saturation(port, seconds) {
  const agent = new http.Agent({ keepAlive: true, maxSockets: CONC });
  const lat = [];
  const end = Date.now() + seconds * 1000;
  await Promise.all(Array.from({ length: CONC }, async () => {
    while (Date.now() < end) lat.push(await once(agent, port));
  }));
  agent.destroy();
  return stats(lat, seconds);
}

async function steady(port, seconds, rps) {
  const agent = new http.Agent({ keepAlive: true, maxSockets: 64 });
  const lat = [];
  const pending = [];
  const t0 = performance.now();
  const total = Math.floor(seconds * rps);
  for (let i = 0; i < total; i++) {
    const due = t0 + (i * 1000) / rps;
    const wait = due - performance.now();
    if (wait > 1) await new Promise((r) => setTimeout(r, wait));
    pending.push(once(agent, port).then((ms) => lat.push(ms)));
  }
  await Promise.all(pending);
  agent.destroy();
  return stats(lat, seconds);
}

// Off-path cost: sanitize + assemble one inbound exchange like the app's (single thread, in process).
{
  const { Sanitizer } = await import('../dist/esm/sanitizer/sanitizer.js');
  const { Policy, parseKeyRing, selectKey } = await import('../dist/esm/sanitizer/policy.js');
  const { nodeToPlain, parseJson } = await import('../dist/esm/sanitizer/json.js');
  const { buildEvent, serializedParts } = await import('../dist/esm/export/event.js');
  const body = basePolicy({ services: [{ name: 'shop-api', match: { inbound: true, internal: false }, ops: [{ op: 'POST /orders', response: { body: [{ path: '$.id', action: { action: 'hmac', domain: 'order' } }, { path: '$.status', action: { action: 'keep' } }] } }] }] });
  const p = new Policy(nodeToPlain(parseJson(Buffer.from(JSON.stringify(body))), true));
  p.hash = 'sha256:' + '0'.repeat(64);
  const san = new Sanitizer(p, selectKey(parseKeyRing(HMAC_KEY), p));
  const ex = {
    dir: 'inbound', service_name: 'shop-api', method: 'POST', raw_path: Buffer.from('/orders'), raw_query: Buffer.from('promo=AUTUMN10'),
    req_headers: [['Host', Buffer.from('127.0.0.1:8080')], ['Content-Type', Buffer.from('application/json')], ['Cookie', Buffer.from('sid=9f8e7d6c5b4a')], ['User-Agent', Buffer.from('bench/1.0')]],
    req_body: Buffer.from(BODY), status: 201,
    resp_headers: [['Content-Type', Buffer.from('application/json; charset=utf-8')], ['Content-Length', Buffer.from('90')]],
    resp_body: Buffer.from('{"id":"ORD-2026-000184","status":"CREATED","total":73.4,"email":"giulia.neri@example.com"}'),
  };
  const run = () => {
    const r = san.run(ex, Date.now(), { sampled: true, by: 'random' });
    return buildEvent(serializedParts(r.parts), { policyId: 'p-shop', policyVersion: 1, policyHash: p.hash, sourceId: 'src-1', dir: 'inbound', tsMs: Date.now(), latencyMs: 3, status: 201 });
  };
  for (let i = 0; i < 3000; i++) run();
  const n = 20000;
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < n; i++) run();
  console.log(`sanitize + event assembly, one inbound exchange: ${(Number(process.hrtime.bigint() - t0) / 1000 / n).toFixed(1)} us (off the request path)`);
}

const carrier = await startCarrier();
const policy = basePolicy({
  sampling: { rate_bp: RATE_BP, trust_baggage: false, propagate_to: [] },
  services: [
    { name: 'carrier', match: { base: carrier.url }, ops: [{ op: 'POST /v1/shipments', request: { body: [{ path: '$.orderId', action: { action: 'hmac', domain: 'order' } }] } }] },
    { name: 'shop-api', match: { inbound: true, internal: false }, ops: [{ op: 'POST /orders', response: { body: [{ path: '$.id', action: { action: 'hmac', domain: 'order' } }, { path: '$.status', action: { action: 'keep' } }] } }] },
  ],
});
const core = await startFakeCore({ policy });
const state = tempDir();
const results = { off: { steady: [], sat: [] }, on: { steady: [], sat: [] } };

for (let round = 0; round < ROUNDS; round++) {
  for (const mode of ['off', 'on']) {
    const app = await spawnApp(APP, {
      register: mode === 'on',
      nodeArgs: PROFILE && mode === 'on' ? ['--cpu-prof', '--cpu-prof-dir', PROFILE] : [],
      env: {
        CARRIER_URL: carrier.url,
        ...(IO_MS > 0 ? { ORDER_IO_MS: String(IO_MS) } : {}),
        ...(mode === 'on' ? {
          TT_ENROLL_URL: core.url, TT_ENROLL_TOKEN: core.token, TT_HMAC_KEY: HMAC_KEY, TT_SERVICE_NAME: 'shop-api', TT_STATE_DIR: state.dir, ...(THREADS !== undefined ? { TT_SANITIZER_THREADS: THREADS } : {}),
        } : {}),
      },
    });
    if (mode === 'on') {
      const before = core.state.heartbeats.length;
      await core.waitFor((s) => s.heartbeats.length > before && s.policyFetches > 0, 10_000);
      await new Promise((r) => setTimeout(r, 300));
    }
    await saturation(app.port, 2); // warm-up (JIT)
    const cpu0 = await cpu(app.port);
    const s = await steady(app.port, SECONDS, STEADY_RPS);
    await new Promise((r) => setTimeout(r, 1500)); // let asynchronous sanitization and export finish
    const cpu1 = await cpu(app.port);
    s.cpuPerReq = (cpu1.main - cpu0.main) / s.n; // request thread only
    s.cpuAllPerReq = (cpu1.us - cpu0.us) / s.n; // all threads (sanitizer workers included)
    const sc0 = await cpu(app.port);
    const c = await saturation(app.port, SECONDS);
    const sc1 = await cpu(app.port);
    c.cpuPerReq = (sc1.main - sc0.main) / c.n;
    c.cpuAllPerReq = (sc1.us - sc0.us) / c.n;
    results[mode].steady.push(s);
    results[mode].sat.push(c);
    console.log(`round ${round + 1} ${mode.padEnd(3)}: steady ${STEADY_RPS} req/s cpu main ${s.cpuPerReq.toFixed(0)} / all ${s.cpuAllPerReq.toFixed(0)} us/req p50 ${s.p50.toFixed(3)} ms p99 ${s.p99.toFixed(3)} ms | saturation ${c.rps.toFixed(0)} req/s cpu main ${c.cpuPerReq.toFixed(0)} / all ${c.cpuAllPerReq.toFixed(0)} us/req p50 ${c.p50.toFixed(3)} ms`);
    await app.stop();
  }
}

const med = (xs) => { const a = [...xs].sort((x, y) => x - y); const h = a.length >> 1; return a.length % 2 ? a[h] : (a[h - 1] + a[h]) / 2; };
const rng = (xs) => `${Math.min(...xs).toFixed(0)}..${Math.max(...xs).toFixed(0)}`;
const col = (mode, kind, k) => results[mode][kind].map((x) => x[k]);
// Per-round paired deltas (off and on of the same round ran back to back), then median and range.
const dCpu = results.on.steady.map((x, i) => ((x.cpuPerReq - results.off.steady[i].cpuPerReq) / results.off.steady[i].cpuPerReq) * 100);
const dCpuAll = results.on.steady.map((x, i) => ((x.cpuAllPerReq - results.off.steady[i].cpuAllPerReq) / results.off.steady[i].cpuAllPerReq) * 100);
const dSatCpu = results.on.sat.map((x, i) => ((x.cpuPerReq - results.off.sat[i].cpuPerReq) / results.off.sat[i].cpuPerReq) * 100);
const dSatCpuAll = results.on.sat.map((x, i) => ((x.cpuAllPerReq - results.off.sat[i].cpuAllPerReq) / results.off.sat[i].cpuAllPerReq) * 100);
const dP50 = results.on.steady.map((x, i) => x.p50 - results.off.steady[i].p50);
const dP99 = results.on.steady.map((x, i) => x.p99 - results.off.steady[i].p99);
const dThr = results.on.sat.map((x, i) => ((x.rps - results.off.sat[i].rps) / results.off.sat[i].rps) * 100);
console.log(`\nsummary (median [min..max] of ${ROUNDS} rounds; sampling ${RATE_BP / 100}%; 3 exchanges per request; node ${process.versions.node}):`);
console.log(`  steady ${STEADY_RPS} req/s p50 off ${med(col('off', 'steady', 'p50')).toFixed(3)} ms, on ${med(col('on', 'steady', 'p50')).toFixed(3)} ms; p99 off ${med(col('off', 'steady', 'p99')).toFixed(3)} ms, on ${med(col('on', 'steady', 'p99')).toFixed(3)} ms`);
console.log(`  -> p50 added ${med(dP50).toFixed(3)} ms [${Math.min(...dP50).toFixed(3)}..${Math.max(...dP50).toFixed(3)}], p99 added ${med(dP99).toFixed(3)} ms`);
console.log(`  app CPU per request (all threads): off ${med(col('off', 'steady', 'cpuAllPerReq')).toFixed(0)} us, on ${med(col('on', 'steady', 'cpuAllPerReq')).toFixed(0)} us; delta ${med(dCpuAll).toFixed(1)}% [${Math.min(...dCpuAll).toFixed(1)}..${Math.max(...dCpuAll).toFixed(1)}]`);
console.log(`  app CPU per request (request thread): off ${med(col('off', 'steady', 'cpuPerReq')).toFixed(0)} us [${rng(col('off', 'steady', 'cpuPerReq'))}], on ${med(col('on', 'steady', 'cpuPerReq')).toFixed(0)} us [${rng(col('on', 'steady', 'cpuPerReq'))}]; delta ${med(dCpu).toFixed(1)}% [${Math.min(...dCpu).toFixed(1)}..${Math.max(...dCpu).toFixed(1)}]`);
console.log(`  CPU per request under load (request thread): off ${med(col('off', 'sat', 'cpuPerReq')).toFixed(0)} us, on ${med(col('on', 'sat', 'cpuPerReq')).toFixed(0)} us; delta ${med(dSatCpu).toFixed(1)}% [${Math.min(...dSatCpu).toFixed(1)}..${Math.max(...dSatCpu).toFixed(1)}]; all threads delta ${med(dSatCpuAll).toFixed(1)}%`);
console.log(`  saturation (concurrency ${CONC}) off: ${med(col('off', 'sat', 'rps')).toFixed(0)} req/s [${rng(col('off', 'sat', 'rps'))}], on: ${med(col('on', 'sat', 'rps')).toFixed(0)} req/s [${rng(col('on', 'sat', 'rps'))}]`);
console.log(`  -> throughput delta ${med(dThr).toFixed(1)}% [${Math.min(...dThr).toFixed(1)}..${Math.max(...dThr).toFixed(1)}]`);
const hb = core.state.heartbeats.at(-1);
console.log(`  events received by the fake intake: ${core.state.events.length}; dropped by the SDK: ${hb?.counters.events_dropped_queue ?? 0}`);

await core.close();
await carrier.close();
state.cleanup();
