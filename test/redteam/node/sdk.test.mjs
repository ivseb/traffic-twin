// Red team round 2: the Node SDK (sdk/node) against a fake, sometimes malicious, tt-core.
// Invented data only; every canary is random per run.
//
// Run (from the repository root):
//   (cd sdk/node && npm ci && npm run build) && node --test --test-concurrency=1 test/redteam/node/sdk.test.mjs
//
// Tests named "regression" cover findings that are now fixed; the others are guards.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import http from 'node:http';
import { mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, sign } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { basePolicy, createPki, envelope, newSigner, startEvilCore, SIGNING_KID } from './evil-core.mjs';
import { startCarrier } from '../../../sdk/node/test/helpers/procs.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const APP = join(here, 'fixtures', 'app.mjs');
const HMAC_KEY = 'k1:' + randomBytes(32).toString('base64url');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function tempDir(prefix = 'tt-rt-node-') {
  const d = mkdtempSync(join(tmpdir(), prefix));
  return { dir: d, cleanup: () => rmSync(d, { recursive: true, force: true }) };
}

function spawnApp(env, { cwd } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [APP], {
      cwd: cwd ?? here,
      env: { PATH: process.env.PATH, HOME: env.HOME ?? process.env.HOME, TT_HEARTBEAT_INTERVAL_MS: '300', TT_POLICY_POLL_INTERVAL_MS: '300', TT_EXPORT_FLUSH_MS: '100', ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    let err = '';
    const timer = setTimeout(() => reject(new Error('app did not start: ' + err)), 15_000);
    child.stderr.on('data', (d) => (err += d));
    child.stdout.on('data', (d) => {
      out += d;
      const line = out.split('\n').find((l) => l.startsWith('{"port"'));
      if (line && !child.port) {
        child.port = JSON.parse(line).port;
        clearTimeout(timer);
        resolve({
          port: child.port, stderr: () => err, stdout: () => out,
          stop: () => new Promise((r) => {
            if (child.exitCode !== null) return r();
            child.once('exit', () => r());
            child.kill('SIGTERM');
            setTimeout(() => child.kill('SIGKILL'), 3000).unref();
          }),
        });
      }
    });
    child.once('exit', (code) => {
      clearTimeout(timer);
      if (!child.port) reject(new Error(`app exited ${code}: ${err}`));
    });
  });
}

function call(port, { method = 'GET', path = '/', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

async function status(port) {
  return JSON.parse((await call(port, { path: '/__rt/status' })).body.toString('utf8'));
}

async function until(pred, ms = 10_000) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    if (await pred()) return true;
    await sleep(50);
  }
  return false;
}

function baseEnv(core, st, extra = {}) {
  return { TT_ENROLL_URL: core.url, TT_ENROLL_TOKEN: core.token, TT_HMAC_KEY: HMAC_KEY, TT_SERVICE_NAME: 'shop-api', TT_STATE_DIR: st.dir, ...extra };
}

const capturing = (core) => core.waitFor((s) => s.heartbeats.at(-1)?.state === 'capturing', 15_000);
const lastCodes = (core) => (core.state.heartbeats.at(-1)?.last_errors ?? []).map((e) => e.code);

// ---------------------------------------------------------------------------------------

test('guard: debug mode (TT_DEBUG=1) never writes payload values to stdout/stderr, heartbeats or events', async () => {
  const c = 'rtcanary' + randomBytes(8).toString('hex');
  // Names (keys, cookie/query/header names) go out literally when they respect the name rule
  // (threat model 7, sanitizer.md 9.3): the name canary is one the rule must hide (6+ digits).
  const cn = 'n' + String(100000000 + Math.floor(Math.random() * 899999999));
  let first = true;
  const core = await startEvilCore({
    hooks: {
      logs(req, res) {
        if (!first) return false;
        first = false; // one failed export to exercise the error/debug path
        res.writeHead(503, { 'retry-after': '0' });
        res.end();
        return true;
      },
    },
  });
  const carrier = await startCarrier();
  const st = tempDir();
  const app = await spawnApp(baseEnv(core, st, { TT_DEBUG: '1', CARRIER_URL: carrier.url }));
  try {
    assert.ok(await capturing(core), 'capturing');
    const h = { 'x-rt-canary': c, authorization: 'Bearer ' + c, cookie: `a=${c}; ${cn}=1`, ['x-' + cn]: c, 'user-agent': c, referer: 'https://x.example/' + c };
    const deep = '['.repeat(4000) + JSON.stringify(c) + ']'.repeat(4000);
    const reqs = [
      { method: 'GET', path: `/x/${c}/y?q=${c}&${cn}=1&${c}` },
      { method: 'POST', path: '/orders', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: c, [cn]: [c, { c }] }) },
      { method: 'POST', path: '/orders', headers: { 'content-type': 'application/json' }, body: '{"broken": "' + c + '",,' },
      { method: 'POST', path: '/orders', headers: { 'content-type': 'application/json' }, body: deep },
      { method: 'POST', path: '/orders', headers: { 'content-type': 'application/json' }, body: Buffer.concat([Buffer.from('{"a":"'), Buffer.from([0xff, 0xfe]), Buffer.from(c + '"}')]) },
      { method: 'POST', path: '/orders', headers: { 'content-type': 'application/json', 'content-encoding': 'gzip' }, body: Buffer.from('not-gzip-' + c) },
      { method: 'POST', path: '/orders', headers: { 'content-type': 'application/json', 'content-encoding': 'gzip' }, body: gzipSync(JSON.stringify({ v: c })) },
      { method: 'POST', path: '/orders', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: `${cn}=${c}&e=${c}` },
      { method: 'POST', path: '/orders', headers: { 'content-type': 'text/plain' }, body: c.repeat(200_000) },
      { method: 'POST', path: '/out', headers: { 'content-type': 'application/json' }, body: '{}' },
    ];
    for (const r of reqs) await call(app.port, { ...r, headers: { ...h, ...(r.headers ?? {}) } });
    assert.ok(await core.waitFor((s) => s.events.length >= reqs.length, 15_000), `events: ${core.state.events.length}`);
    await sleep(700); // a few more heartbeats with last_errors
    const all = [app.stderr(), app.stdout(), JSON.stringify(core.state.heartbeats), core.state.eventStrings.join('\n')].join('\n');
    assert.ok(app.stderr().includes('[traffic-twin]'), 'debug output is on');
    const where = { stderr: app.stderr(), stdout: app.stdout(), heartbeats: JSON.stringify(core.state.heartbeats), events: core.state.eventStrings.join('\n') };
    const leaks = Object.entries(where).filter(([, v]) => v.toLowerCase().includes(c) || v.includes(cn)).map(([k, v]) => {
      const i = Math.max(v.toLowerCase().indexOf(c), v.indexOf(cn));
      return k + ': ...' + v.slice(Math.max(0, i - 300), i + 60) + '...';
    });
    assert.deepEqual(leaks, [], 'canary leaked');
    void all;
  } finally {
    await app.stop();
    await core.close();
    await carrier.close();
    st.cleanup();
  }
});

test('guard: state directory 0700 and every state file 0600 (explicit dir pre-created 0755, and default ~/.traffic-twin)', async () => {
  const core = await startEvilCore();
  const st = tempDir();
  const home = tempDir('tt-rt-home-');
  chmodSync(st.dir, 0o755);
  const app = await spawnApp(baseEnv(core, st));
  const env2 = { ...baseEnv(core, st), HOME: home.dir };
  delete env2.TT_STATE_DIR;
  const app2 = await spawnApp(env2);
  try {
    assert.ok(await core.waitFor((s) => s.heartbeats.filter((h) => h.state === 'capturing').length >= 2, 15_000));
    core.state.kill = true;
    assert.ok(await core.waitFor((s) => s.heartbeats.at(-1).state === 'killed'));
    const check = (dir) => {
      assert.equal(statSync(dir).mode & 0o777, 0o700, dir);
      const files = readdirSync(dir);
      for (const f of ['client.key', 'enrollment.json', 'policy.envelope.json', 'state.json']) assert.ok(files.includes(f), f + ' in ' + files);
      for (const f of files) assert.equal(statSync(join(dir, f)).mode & 0o777, 0o600, f);
    };
    check(st.dir);
    const root = join(home.dir, '.traffic-twin');
    assert.equal(statSync(root).mode & 0o077, 0, '~/.traffic-twin not accessible to others');
    for (const d of readdirSync(root)) check(join(root, d));
  } finally {
    await app.stop();
    await app2.stop();
    await core.close();
    st.cleanup();
    home.cleanup();
  }
});

test('guard: restart with a cached policy while tt-core is down never captures', async () => {
  const core = await startEvilCore();
  const st = tempDir();
  const env = baseEnv(core, st);
  let app = await spawnApp(env);
  try {
    assert.ok(await capturing(core));
  } finally {
    await app.stop();
  }
  await core.close();
  app = await spawnApp(env);
  try {
    for (let i = 0; i < 5; i++) await call(app.port, { method: 'POST', path: '/orders', body: '{}', headers: { 'content-type': 'application/json' } });
    await sleep(1500);
    const s = await status(app.port);
    assert.notEqual(s.status.state, 'capturing');
    assert.equal(s.status.counters.exchanges_sampled, 0);
  } finally {
    await app.stop();
    st.cleanup();
  }
});

test('guard: HMAC key missing or shorter than 32 bytes means no capture', async () => {
  for (const key of ['k1:' + randomBytes(31).toString('base64url'), '']) {
    const core = await startEvilCore();
    const st = tempDir();
    const app = await spawnApp(baseEnv(core, st, { TT_HMAC_KEY: key }));
    try {
      assert.ok(await core.waitFor((s) => s.heartbeats.length >= 2));
      assert.equal(core.state.heartbeats.at(-1).state, 'key_missing');
      await call(app.port, { method: 'POST', path: '/orders', body: '{}', headers: { 'content-type': 'application/json' } });
      await sleep(400);
      assert.equal(core.state.events.length, 0);
    } finally {
      await app.stop();
      await core.close();
      st.cleanup();
    }
  }
});

test('guard: an H1 policy (keep on authorization) planted in the cache is refused at start-up (policy_unsafe)', async () => {
  let only304 = false;
  const core = await startEvilCore({ hooks: { policy(req, res) { if (!only304) return false; res.writeHead(304); res.end(); return true; } } });
  const st = tempDir();
  const env = baseEnv(core, st);
  let app = await spawnApp(env);
  try {
    assert.ok(await capturing(core));
  } finally {
    await app.stop();
  }
  const unsafe = basePolicy({ issued_seq: 2, version: 2 });
  unsafe.global.request.headers.authorization = { action: 'keep' };
  writeFileSync(join(st.dir, 'policy.envelope.json'), JSON.stringify(envelope(unsafe, core.signer)), { mode: 0o600 });
  only304 = true;
  const n = core.state.heartbeats.length;
  app = await spawnApp(env);
  try {
    assert.ok(await core.waitFor((s) => s.heartbeats.length >= n + 2));
    const hbs = core.state.heartbeats.slice(n);
    assert.ok(hbs.every((h) => h.state !== 'capturing' && h.policy?.issued_seq !== 2), JSON.stringify(hbs.map((h) => [h.state, h.policy])));
    assert.ok(lastCodes(core).includes('policy_unsafe'), lastCodes(core).join(','));
  } finally {
    await app.stop();
    await core.close();
    st.cleanup();
  }
});

test('guard: malicious policies from tt-core: bad signature, issued_seq downgrade, forged key endorsement, 20 MiB policy', async () => {
  let hbExtra = {};
  let huge = false;
  const core = await startEvilCore({
    hooks: {
      heartbeat: () => hbExtra,
      policy(req, res) {
        if (!huge) return false;
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end('{"format":"tt.policy.compiled/v1","pad":"' + 'A'.repeat(20 << 20) + '"}');
        return true;
      },
    },
  });
  const st = tempDir();
  const app = await spawnApp(baseEnv(core, st));
  const seqNow = () => core.state.heartbeats.at(-1)?.policy?.issued_seq;
  const settle = async () => {
    const n = core.state.heartbeats.length;
    await core.waitFor((s) => s.heartbeats.length >= n + 3);
  };
  try {
    assert.ok(await capturing(core));
    // seq 3 accepted.
    core.setPolicy(basePolicy({ issued_seq: 3, version: 3 }));
    assert.ok(await core.waitFor(() => seqNow() === 3));
    // a. tampered signature on seq 4.
    const bad = envelope(basePolicy({ issued_seq: 4, version: 4 }), core.signer);
    const sig = Buffer.from(bad.signature.sig, 'base64url');
    sig[5] ^= 1;
    bad.signature.sig = sig.toString('base64url');
    core.state.envelope = bad;
    await settle();
    assert.equal(seqNow(), 3, 'bad signature accepted');
    // b. a correctly signed but older policy (downgrade).
    core.setPolicy(basePolicy({ issued_seq: 2, version: 2 }));
    await settle();
    assert.equal(seqNow(), 3, 'issued_seq downgrade accepted');
    // c. a new signing key with a forged endorsement, then a policy signed with it.
    const evil = newSigner();
    const raw = Buffer.from(evil.pub, 'base64url');
    const forged = sign(null, Buffer.concat([Buffer.from('tt-fleet-key/v1\0evil-1\0', 'latin1'), raw]), evil.privateKey);
    hbExtra = { add_signing_keys: [{ kid: 'evil-1', alg: 'Ed25519', public_key: evil.pub, endorsed_by: SIGNING_KID, endorsement: forged.toString('base64url') }] };
    await settle();
    core.setPolicy(basePolicy({ issued_seq: 5, version: 5 }), evil, 'evil-1');
    await settle();
    assert.equal(seqNow(), 3, 'policy signed with a forged-endorsed key accepted');
    assert.ok(core.state.heartbeats.some((h) => (h.last_errors ?? []).some((e) => e.code === 'signing_key_endorsement_invalid')));
    // d. an oversized answer.
    hbExtra = {};
    huge = true;
    await settle();
    assert.equal(seqNow(), 3);
    assert.equal(core.state.heartbeats.at(-1).state, 'capturing');
  } finally {
    await app.stop();
    await core.close();
    st.cleanup();
  }
});

test('guard: the kill switch cannot be lifted by a server outside the pinned CA (same address, other CA)', async () => {
  const core = await startEvilCore();
  const st = tempDir();
  const app = await spawnApp(baseEnv(core, st));
  try {
    assert.ok(await capturing(core));
    core.state.kill = true;
    assert.ok(await core.waitFor((s) => s.heartbeats.at(-1).state === 'killed'));
    const other = createPki();
    core.server.setSecureContext({ key: other.serverKeyPem, cert: other.serverCertChainPem, ca: other.caPem });
    core.server.closeAllConnections?.();
    core.state.kill = false;
    const n = core.state.heartbeats.length;
    await sleep(2000);
    assert.ok(core.state.heartbeats.length <= n + 1, 'heartbeats reached a server outside the pinned CA');
    assert.equal((await status(app.port)).status.state, 'killed');
  } finally {
    await app.stop();
    await core.close();
    st.cleanup();
  }
});

test('guard: no outbound connection or DNS lookup other than the configured tt-core', async () => {
  const core = await startEvilCore();
  const st = tempDir();
  const app = await spawnApp(baseEnv(core, st));
  try {
    assert.ok(await capturing(core));
    for (let i = 0; i < 3; i++) await call(app.port, { method: 'POST', path: '/orders', body: '{"a":1}', headers: { 'content-type': 'application/json' } });
    assert.ok(await core.waitFor((s) => s.events.length >= 3));
    const s = await status(app.port);
    const others = s.connects.filter((c) => c !== `127.0.0.1:${core.port}`);
    assert.deepEqual(others, [], 'unexpected connections');
    assert.deepEqual(s.lookups.filter((h) => h !== '127.0.0.1'), [], 'unexpected DNS lookups');
  } finally {
    await app.stop();
    await core.close();
    st.cleanup();
  }
});

test('guard: no OpenTelemetry global registration (fake @opentelemetry/api records every access)', async () => {
  const cwd = tempDir('tt-rt-otel-');
  const mod = join(cwd.dir, 'node_modules', '@opentelemetry', 'api');
  mkdirSync(mod, { recursive: true });
  writeFileSync(join(mod, 'package.json'), '{"name":"@opentelemetry/api","version":"1.9.0","main":"index.js"}');
  writeFileSync(join(mod, 'index.js'), `
    const acc = (globalThis.__rtOtelAccess = []);
    const wrap = (name, obj) => new Proxy(obj, { get(t, p) { if (typeof p === 'string') acc.push(name + '.' + p); return t[p]; } });
    const fn = (name) => (...a) => { acc.push('call:' + name); return undefined; };
    const trace = wrap('trace', { getSpanContext: fn('trace.getSpanContext'), setGlobalTracerProvider: fn('trace.setGlobalTracerProvider'), getTracer: fn('trace.getTracer'), setSpan: fn('trace.setSpan') });
    const context = wrap('context', { active: fn('context.active'), setGlobalContextManager: fn('context.setGlobalContextManager'), with: fn('context.with') });
    const propagation = wrap('propagation', { setGlobalPropagator: fn('propagation.setGlobalPropagator'), inject: fn('propagation.inject'), extract: fn('propagation.extract') });
    module.exports = wrap('api', { trace, context, propagation, isSpanContextValid: fn('isSpanContextValid'), diag: wrap('diag', {}), metrics: wrap('metrics', {}) });
  `);
  const core = await startEvilCore();
  const st = tempDir();
  const app = await spawnApp(baseEnv(core, st), { cwd: cwd.dir });
  try {
    assert.ok(await capturing(core));
    await call(app.port, { method: 'POST', path: '/orders', body: '{}', headers: { 'content-type': 'application/json' } });
    const s = await status(app.port);
    assert.ok(Array.isArray(s.otel) && s.otel.length > 0, 'the fake API was loaded');
    const allowed = new Set(['api.trace', 'api.context', 'api.default', 'api.isSpanContextValid', 'api.__esModule', 'api.then',
      'trace.getSpanContext', 'context.active', 'call:trace.getSpanContext', 'call:context.active', 'call:isSpanContextValid']);
    assert.deepEqual([...new Set(s.otel)].filter((a) => !allowed.has(a)), []);
  } finally {
    await app.stop();
    await core.close();
    st.cleanup();
    cwd.cleanup();
  }
});

// --- findings --------------------------------------------------------------------------

test('regression (was FINDING, medium): the kill switch stops a batch already taken by the exporter, retries included', async () => {
  let posts = 0;
  let killedAt = 0;
  const core = await startEvilCore({
    hooks: {
      logs(req, res, state) {
        posts++;
        if (posts === 1) {
          state.kill = true; // the operator pulls the kill switch while the intake is busy
          res.writeHead(503, { 'retry-after': '2' });
          res.end();
          return true;
        }
        return false;
      },
      heartbeat(state, hb) {
        if (hb.state === 'killed' && !killedAt) killedAt = Date.now();
        return {};
      },
    },
  });
  const st = tempDir();
  const app = await spawnApp(baseEnv(core, st));
  try {
    assert.ok(await capturing(core));
    await call(app.port, { method: 'POST', path: '/orders', body: '{"a":1}', headers: { 'content-type': 'application/json' } });
    assert.ok(await core.waitFor(() => killedAt > 0, 5000), 'source reported killed');
    await sleep(4000); // past Retry-After
    assert.equal(core.state.events.length, 0, `${core.state.events.length} event(s) delivered after the source reported "killed"`);
  } finally {
    await app.stop();
    await core.close();
    st.cleanup();
  }
});

test('regression (was FINDING, low): a policy answer larger than the 8 MiB cap is aborted, not read forever', async () => {
  let aborted = false;
  let stream = false;
  const core = await startEvilCore({
    hooks: {
      policy(req, res) {
        if (!stream) return false;
        stream = false;
        res.writeHead(200, { 'content-type': 'application/json' });
        res.write('{"pad":"');
        const chunk = 'A'.repeat(64 << 10);
        const t0 = Date.now();
        const iv = setInterval(() => {
          if (Date.now() - t0 > 8000) {
            clearInterval(iv);
            res.end('"}');
            return;
          }
          res.write(chunk);
        }, 5);
        res.on('close', () => {
          aborted = !res.writableEnded;
          clearInterval(iv);
        });
        return true;
      },
    },
  });
  const st = tempDir();
  const app = await spawnApp(baseEnv(core, st));
  try {
    assert.ok(await capturing(core));
    stream = true;
    core.setPolicy(basePolicy({ issued_seq: 2, version: 2 })); // new hash: the source fetches
    // 64 KiB every 5 ms reaches the 8 MiB cap in about 1 s; give it 5 s to hang up.
    assert.ok(await until(() => aborted, 6000), 'the SDK kept reading past maxResponseBytes instead of aborting');
  } finally {
    await app.stop();
    await core.close();
    st.cleanup();
  }
});
