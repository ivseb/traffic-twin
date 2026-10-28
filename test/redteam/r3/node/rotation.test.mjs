// Red team round 3: policy signing key rotation and revocation in the Node SDK, against the
// round-2 fake tt-core (test/redteam/node/evil-core.mjs). Invented data only.
//
// Run (from the repository root):
//   (cd sdk/node && npm ci && npm run build) && node --test --test-concurrency=1 test/redteam/r3/node/rotation.test.mjs
//
// "FINDING" tests fail while the bug exists; "guard" and "fixed" tests pass.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import http from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, sign } from 'node:crypto';
import { basePolicy, newSigner, startEvilCore, SIGNING_KID } from '../../node/evil-core.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const APP = join(here, '..', '..', 'node', 'fixtures', 'app.mjs');
const HMAC_KEY = 'k1:' + randomBytes(32).toString('base64url');

function tempDir() {
  const d = mkdtempSync(join(tmpdir(), 'tt-rt3-node-'));
  return { dir: d, cleanup: () => rmSync(d, { recursive: true, force: true }) };
}

function spawnApp(env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [APP], {
      cwd: join(here, '..', '..', 'node'),
      env: { PATH: process.env.PATH, HOME: process.env.HOME, TT_HEARTBEAT_INTERVAL_MS: '200', TT_POLICY_POLL_INTERVAL_MS: '200', TT_EXPORT_FLUSH_MS: '100', ...env },
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
          port: child.port,
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

const env = (core, st) => ({ TT_ENROLL_URL: core.url, TT_ENROLL_TOKEN: core.token, TT_HMAC_KEY: HMAC_KEY, TT_SERVICE_NAME: 'shop-api', TT_STATE_DIR: st.dir });
const seqNow = (core) => core.state.heartbeats.at(-1)?.policy?.issued_seq;
const stateNow = (core) => core.state.heartbeats.at(-1)?.state;
async function settle(core, n = 4) {
  const k = core.state.heartbeats.length;
  await core.waitFor((s) => s.heartbeats.length >= k + n);
}

function endorse(endorser, kid, pubB64) {
  const raw = Buffer.from(pubB64, 'base64url');
  return sign(null, Buffer.concat([Buffer.from('tt-fleet-key/v1\0' + kid + '\0', 'latin1'), raw]), endorser.privateKey).toString('base64url');
}

test('guard: endorsed rotation, then revocation of the old key; survives a restart', async () => {
  let hb = {};
  const core = await startEvilCore({ hooks: { heartbeat: () => hb } });
  const st = tempDir();
  let app = await spawnApp(env(core, st));
  try {
    assert.ok(await core.waitFor((s) => s.heartbeats.at(-1)?.state === 'capturing', 15_000));
    const k2 = newSigner();
    hb = { add_signing_keys: [{ kid: 'policy-rt3-2', alg: 'Ed25519', public_key: k2.pub, endorsed_by: SIGNING_KID, endorsement: endorse(core.signer, 'policy-rt3-2', k2.pub) }] };
    await settle(core);
    core.setPolicy(basePolicy({ issued_seq: 5, version: 5 }), k2, 'policy-rt3-2');
    assert.ok(await core.waitFor(() => seqNow(core) === 5), 'policy signed by the endorsed new key not accepted');
    hb = { ...hb, revoke_signing_keys: [SIGNING_KID] };
    await settle(core);
    assert.equal(stateNow(core), 'capturing');
    core.setPolicy(basePolicy({ issued_seq: 6, version: 6 })); // old, revoked key
    await settle(core);
    assert.equal(seqNow(core), 5, 'policy signed by a revoked key accepted');
    await app.stop();
    hb = {};
    app = await spawnApp(env(core, st));
    await settle(core, 6);
    assert.equal(seqNow(core), 5, 'after restart: revoked key trusted again or rotated key lost');
    core.setPolicy(basePolicy({ issued_seq: 7, version: 7 }), k2, 'policy-rt3-2');
    assert.ok(await core.waitFor(() => seqNow(core) === 7), 'after restart the rotated key is no longer trusted');
  } finally {
    await app.stop();
    await core.close();
    st.cleanup();
  }
});

test('guard: revoking the kid of the active policy stops capture', async () => {
  let hb = {};
  const core = await startEvilCore({ hooks: { heartbeat: () => hb } });
  const st = tempDir();
  const app = await spawnApp(env(core, st));
  try {
    assert.ok(await core.waitFor((s) => s.heartbeats.at(-1)?.state === 'capturing', 15_000));
    hb = { revoke_signing_keys: [SIGNING_KID] };
    assert.ok(await core.waitFor((s) => s.heartbeats.at(-1)?.state !== 'capturing'), 'still capturing with a revoked key');
  } finally {
    await app.stop();
    await core.close();
    st.cleanup();
  }
});

// RT3-KEY-3 (low, fixed): the Node SDK applied add_signing_keys BEFORE revoke_signing_keys, so a key
// endorsed by a kid revoked in the very same heartbeat is pinned (the Go sourceclient revokes
// first and refuses it). Whoever holds the compromised old key gets a fresh trusted key out of
// the revocation message itself. Now revocations are applied first; kept as a regression.
test('fixed RT3-KEY-3: a key endorsed by a kid revoked in the same heartbeat is not pinned', async () => {
  let hb = {};
  const core = await startEvilCore({ hooks: { heartbeat: () => hb } });
  const st = tempDir();
  const app = await spawnApp(env(core, st));
  try {
    assert.ok(await core.waitFor((s) => s.heartbeats.at(-1)?.state === 'capturing', 15_000));
    const evil = newSigner();
    hb = {
      revoke_signing_keys: [SIGNING_KID],
      add_signing_keys: [{ kid: 'evil-rt3', alg: 'Ed25519', public_key: evil.pub, endorsed_by: SIGNING_KID, endorsement: endorse(core.signer, 'evil-rt3', evil.pub) }],
    };
    await settle(core);
    core.setPolicy(basePolicy({ issued_seq: 9, version: 9 }), evil, 'evil-rt3');
    await settle(core, 6);
    assert.notEqual(seqNow(core), 9, 'policy signed by a key endorsed with a just-revoked kid was accepted');
  } finally {
    await app.stop();
    await core.close();
    st.cleanup();
  }
});

void http;
