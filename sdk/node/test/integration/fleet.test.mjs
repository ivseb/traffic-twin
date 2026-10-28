// Fleet behaviour: baggage propagation rules (D-M8), fail-closed start, persisted kill switch,
// server-generated key enrollment, policy signing key rotation and revocation.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { SIGNING_KID, basePolicy, endorsedKey, newSigner, startFakeCore } from '../helpers/fake-core.mjs';
import { HMAC_KEY, ROOT, call, spawnApp, startCarrier, tempDir } from '../helpers/procs.mjs';

const APP = join(ROOT, 'test', 'fixtures', 'app.mjs');

async function startInternal() {
  const seen = [];
  const server = http.createServer((req, res) => {
    seen.push(req.headers);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"stock":3}');
  });
  await new Promise((r) => server.listen(0, r));
  return { port: server.address().port, seen, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }) };
}

test('tt.s baggage goes only to propagate_to hosts, never to a policy base', async () => {
  const carrier = await startCarrier();
  const internal = await startInternal();
  const policy = basePolicy({
    sampling: { rate_bp: 10000, trust_baggage: false, propagate_to: [`localhost:${internal.port}`] },
    services: [{ name: 'carrier', match: { base: carrier.url }, ops: [] }],
  });
  const core = await startFakeCore({ policy });
  const st = tempDir();
  const app = await spawnApp(APP, {
    register: true,
    env: {
      TT_ENROLL_URL: core.url, TT_ENROLL_TOKEN: core.token, TT_HMAC_KEY: HMAC_KEY, TT_SERVICE_NAME: 'shop-api',
      TT_STATE_DIR: st.dir, TT_ENROLL_CSR: '0', TT_EXPORT_FLUSH_MS: '200',
      CARRIER_URL: carrier.url, INTERNAL_URL: `http://localhost:${internal.port}`,
    },
  });
  try {
    assert.ok(await core.waitFor((s) => s.policyFetches > 0), 'policy fetched');
    await new Promise((r) => setTimeout(r, 300));
    const r = await call(app.port, { method: 'POST', path: '/orders', headers: { 'content-type': 'application/json' }, body: '{"email":"a@b.example"}' });
    assert.equal(r.status, 201);
    assert.equal(internal.seen.length, 2);
    // fetch: the app's own baggage member is kept, tt.s is added; node:http: tt.s only.
    assert.match(String(internal.seen[0].baggage), /tenant=acme/);
    assert.match(String(internal.seen[0].baggage), /tt\.s=1/);
    assert.equal(internal.seen[1].baggage, 'tt.s=1');
    for (const s of carrier.seen) assert.equal(s.headers.baggage, undefined, 'never toward an external base');
    // Server-generated key flow: the key was stored 0600 and never sent back.
    assert.equal(core.state.enrollments[0].csr, undefined);
    assert.match(readFileSync(join(st.dir, 'client.key'), 'utf8'), /PRIVATE KEY/);
  } finally {
    await app.stop();
    await core.close();
    await carrier.close();
    await internal.close();
    st.cleanup();
  }
});

test('without an HMAC key the SDK says key_missing (never no_policy) and explains where the key comes from', async () => {
  const core = await startFakeCore();
  const st = tempDir();
  const app = await spawnApp(APP, {
    register: true,
    env: { TT_ENROLL_URL: core.url, TT_ENROLL_TOKEN: core.token, TT_SERVICE_NAME: 'shop-api', TT_STATE_DIR: st.dir, TT_ENROLL_CSR: '0' },
  });
  try {
    assert.ok(await core.waitFor((s) => s.heartbeats.length > 0), 'heartbeat sent');
    assert.equal(core.state.heartbeats[0].state, 'key_missing');
    const r = await call(app.port, { method: 'POST', path: '/orders', headers: { 'content-type': 'application/json' }, body: '{"email":"a@b.example"}' });
    assert.equal(r.status, 201, 'the application is not affected');
    const err = app.stderr();
    assert.match(err, /key_missing: neither TT_HMAC_KEY_FILE nor TT_HMAC_KEY is set/);
    assert.match(err, /same kid as the policy/);
    assert.equal(err.split('key_missing').length - 1, 1, 'said once');
  } finally {
    await app.stop();
    await core.close();
    st.cleanup();
  }
});

test('without a reachable tt-core the app works and nothing is captured', async () => {
  const st = tempDir();
  const app = await spawnApp(APP, {
    register: true,
    env: { TT_ENROLL_URL: 'https://127.0.0.1:1', TT_ENROLL_TOKEN: 'tte_' + 'a'.repeat(32) + '.' + 'b'.repeat(43), TT_HMAC_KEY: HMAC_KEY, TT_SERVICE_NAME: 'shop-api', TT_STATE_DIR: st.dir },
  });
  try {
    const r = await call(app.port, { method: 'POST', path: '/orders', headers: { 'content-type': 'application/json' }, body: '{"email":"a@b.example"}' });
    assert.equal(r.status, 201);
    assert.equal(app.stderr(), '');
  } finally {
    await app.stop();
    st.cleanup();
  }
});

test('the kill switch is persisted with the policy cache', async () => {
  const core = await startFakeCore();
  const st = tempDir();
  const env = {
    TT_ENROLL_URL: core.url, TT_ENROLL_TOKEN: core.token, TT_HMAC_KEY: HMAC_KEY, TT_SERVICE_NAME: 'shop-api',
    TT_STATE_DIR: st.dir, TT_HEARTBEAT_INTERVAL_MS: '300',
  };
  const app = await spawnApp(APP, { register: true, env });
  try {
    assert.ok(await core.waitFor((s) => s.heartbeats.at(-1)?.state === 'capturing'));
    core.state.kill = true;
    assert.ok(await core.waitFor((s) => s.heartbeats.at(-1).state === 'killed'));
    assert.equal(JSON.parse(readFileSync(join(st.dir, 'state.json'), 'utf8')).kill, true);
    assert.ok(readFileSync(join(st.dir, 'policy.envelope.json'), 'utf8').includes('tt.policy.compiled/v1'));
  } finally {
    await app.stop();
  }
  // Restart: reuses the enrollment (no second enroll) and stays killed until told otherwise.
  const again = await spawnApp(APP, { register: true, env });
  try {
    const n = core.state.heartbeats.length;
    assert.ok(await core.waitFor((s) => s.heartbeats.length > n));
    assert.equal(core.state.heartbeats[n].state, 'killed');
    assert.equal(core.state.enrollments.length, 1);
    core.state.kill = false;
    assert.ok(await core.waitFor((s) => s.heartbeats.at(-1).state === 'capturing'));
  } finally {
    await again.stop();
    await core.close();
    st.cleanup();
  }
});

const fleetEnv = (core, st) => ({
  TT_ENROLL_URL: core.url, TT_ENROLL_TOKEN: core.token, TT_HMAC_KEY: HMAC_KEY, TT_SERVICE_NAME: 'shop-api',
  TT_STATE_DIR: st.dir, TT_HEARTBEAT_INTERVAL_MS: '150', TT_POLICY_POLL_INTERVAL_MS: '150',
});
const lastHb = (core) => core.state.heartbeats.at(-1);
async function heartbeats(core, n) {
  const k = core.state.heartbeats.length;
  assert.ok(await core.waitFor((s) => s.heartbeats.length >= k + n), 'heartbeats stopped');
}
const keyErrors = (hb) => (hb.last_errors ?? []).map((e) => e.code).filter((c) => c.startsWith('signing_key'));

test('a key endorsed by a kid revoked in the same heartbeat is not pinned', async () => {
  const core = await startFakeCore();
  const st = tempDir();
  const app = await spawnApp(APP, { register: true, env: fleetEnv(core, st) });
  try {
    assert.ok(await core.waitFor((s) => s.heartbeats.at(-1)?.state === 'capturing'));
    assert.deepEqual(lastHb(core).signing_kids, [SIGNING_KID]);
    const evil = newSigner();
    core.state.heartbeatExtra = {
      revoke_signing_keys: [SIGNING_KID],
      add_signing_keys: [endorsedKey(core.signer, SIGNING_KID, 'policy-evil-1', evil)],
    };
    await heartbeats(core, 3);
    core.setPolicy(basePolicy({ issued_seq: 9, version: 9 }), evil, 'policy-evil-1');
    await heartbeats(core, 5);
    const hb = lastHb(core);
    assert.deepEqual(hb.signing_kids, []);
    assert.notEqual(hb.policy?.issued_seq, 9, 'policy signed by a key endorsed with a just-revoked kid accepted');
    assert.notEqual(hb.state, 'capturing');
    const saved = JSON.parse(readFileSync(join(st.dir, 'state.json'), 'utf8'));
    assert.deepEqual(saved.revoked_kids, [SIGNING_KID]);
    assert.ok(!(saved.added_keys ?? []).some((k) => k.kid === 'policy-evil-1'));
  } finally {
    await app.stop();
    await core.close();
    st.cleanup();
  }
});

test('endorsed rotation, then revocation of the old key; survives a restart; repeats are silent', async () => {
  const core = await startFakeCore();
  const st = tempDir();
  const env = fleetEnv(core, st);
  let app = await spawnApp(APP, { register: true, env });
  try {
    assert.ok(await core.waitFor((s) => s.heartbeats.at(-1)?.state === 'capturing'));
    const k2 = newSigner();
    const k3 = newSigner();
    // k3 is endorsed by k2, which is pinned earlier in the same list.
    const adds = [endorsedKey(core.signer, SIGNING_KID, 'policy-test-2', k2), endorsedKey(k2, 'policy-test-2', 'policy-test-3', k3)];
    core.state.heartbeatExtra = { add_signing_keys: adds };
    assert.ok(await core.waitFor((s) => s.heartbeats.at(-1).signing_kids?.length === 3), 'rotated keys not reported');
    assert.deepEqual(lastHb(core).signing_kids, [SIGNING_KID, 'policy-test-2', 'policy-test-3']);
    core.setPolicy(basePolicy({ issued_seq: 5, version: 5 }), k2, 'policy-test-2');
    assert.ok(await core.waitFor((s) => s.heartbeats.at(-1).policy?.issued_seq === 5), 'policy signed by the new key not accepted');

    // The same keys at every heartbeat: no error, no rewrite of state.json.
    const m0 = statSync(join(st.dir, 'state.json')).mtimeMs;
    await heartbeats(core, 4);
    assert.deepEqual(keyErrors(lastHb(core)), []);
    assert.equal(statSync(join(st.dir, 'state.json')).mtimeMs, m0, 'state.json rewritten for keys already pinned');

    core.state.heartbeatExtra = { add_signing_keys: adds, revoke_signing_keys: [SIGNING_KID] };
    assert.ok(await core.waitFor((s) => s.heartbeats.at(-1).signing_kids?.length === 2), 'revocation not reported');
    await heartbeats(core, 3);
    const hb = lastHb(core);
    assert.deepEqual(hb.signing_kids, ['policy-test-2', 'policy-test-3']);
    assert.equal(hb.state, 'capturing');
    assert.equal(hb.policy?.issued_seq, 5);
    assert.deepEqual(keyErrors(hb), []);

    // A kid already pinned with another key is refused.
    core.state.heartbeatExtra = { add_signing_keys: [...adds, endorsedKey(k2, 'policy-test-2', 'policy-test-3', newSigner())], revoke_signing_keys: [SIGNING_KID] };
    assert.ok(await core.waitFor((s) => keyErrors(s.heartbeats.at(-1)).includes('signing_key_conflict')), 'conflicting key not noted');
    await app.stop();

    core.state.heartbeatExtra = {};
    app = await spawnApp(APP, { register: true, env });
    const n = core.state.heartbeats.length;
    assert.ok(await core.waitFor((s) => s.heartbeats.length > n && s.heartbeats.at(-1).state === 'capturing'), 'not capturing after restart');
    assert.deepEqual(lastHb(core).signing_kids, ['policy-test-2', 'policy-test-3']);
    assert.equal(lastHb(core).policy?.issued_seq, 5);
    core.setPolicy(basePolicy({ issued_seq: 6, version: 6 })); // signed by the revoked enrollment key
    await heartbeats(core, 5);
    assert.equal(lastHb(core).policy?.issued_seq, 5, 'policy signed by a revoked key accepted after restart');
    core.setPolicy(basePolicy({ issued_seq: 7, version: 7 }), k3, 'policy-test-3');
    assert.ok(await core.waitFor((s) => s.heartbeats.at(-1).policy?.issued_seq === 7), 'rotated key lost after restart');
  } finally {
    await app.stop();
    await core.close();
    st.cleanup();
  }
});
