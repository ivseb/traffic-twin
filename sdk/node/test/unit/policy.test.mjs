import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import {
  Policy, Refused, checkAcceptance, ed25519PublicKey, parseKeyRing, selectKey, verifyEnvelope,
} from '../../dist/esm/sanitizer/policy.js';
import { nodeToPlain, parseJson } from '../../dist/esm/sanitizer/json.js';
import { basePolicy, canonicalBytes } from '../helpers/fake-core.mjs';
import { generateCsr, pemBlocks } from '../../dist/esm/fleet/asn1.js';
import { tokenPin } from '../../dist/esm/fleet/client.js';
import { createPki } from '../helpers/pki.mjs';

const plain = (o) => nodeToPlain(parseJson(Buffer.from(JSON.stringify(o))), true);

function signed(body, { prefix = true, kid = 'pk1' } = {}) {
  const k = generateKeyPairSync('ed25519');
  const bytes = canonicalBytes(body);
  const msg = prefix ? Buffer.concat([Buffer.from('tt.policy.body/v1\0'), bytes]) : bytes;
  const env = {
    format: 'tt.policy.compiled/v1',
    policy_id: body.policy_id,
    version: body.version,
    issued_seq: body.issued_seq,
    hash: 'sha256:' + createHash('sha256').update(bytes).digest('hex'),
    body_b64: bytes.toString('base64url'),
    signature: { alg: 'Ed25519', kid, sig: sign(null, msg, k.privateKey).toString('base64url') },
  };
  const keys = new Map([[kid, ed25519PublicKey(k.publicKey.export({ format: 'jwk' }).x)]]);
  return { env, keys };
}

const code = (fn) => {
  try {
    fn();
    return 'accepted';
  } catch (e) {
    if (e instanceof Refused) return e.code;
    throw e;
  }
};

test('a signed envelope verifies; tampering, unknown kids and the unprefixed signature do not', () => {
  const { env, keys } = signed(basePolicy());
  const v = verifyEnvelope(plain(env), keys, true);
  assert.equal(v.hash, env.hash);
  assert.equal(code(() => verifyEnvelope(plain({ ...env, version: 2 }), keys, true)), 'policy_rejected');
  assert.equal(code(() => verifyEnvelope(plain({ ...env, hash: 'sha256:' + '0'.repeat(64) }), keys, true)), 'policy_rejected');
  assert.equal(code(() => verifyEnvelope(plain(env), new Map(), true)), 'policy_rejected');
  assert.equal(code(() => verifyEnvelope(plain({ ...env, extra: 1 }), keys, true)), 'policy_rejected');
  const raw = signed(basePolicy(), { prefix: false });
  assert.equal(code(() => verifyEnvelope(plain(raw.env), raw.keys, true)), 'policy_rejected');
});

test('the body schema is enforced at the source (policy.md 4.1)', () => {
  const bad = [
    { ...basePolicy(), unknown_field: true },
    basePolicy({ hmac: { kid: 'k1', accept_kids: [], epoch: '2026-10' }, services: [{ name: 'x', match: { inbound: true, internal: false }, ops: [{ op: 'GET /a', response: { body: [{ path: '$.a', action: { action: 'hmac', domain: 'subject' } }] } }] }] }),
    basePolicy({ segments: { auto_words: true, allow: [], hosts_allow: [] } }),
    basePolicy({ services: [{ name: 'x', match: { inbound: true, internal: false }, ops: [{ op: 'get /a' }] }] }),
  ];
  for (const b of bad) {
    const { env, keys } = signed(b);
    assert.equal(code(() => verifyEnvelope(plain(env), keys, true)), 'policy_rejected');
  }
});

test('acceptance: group, expiry, issued_seq ordering (policy.md 4.3-4.5)', () => {
  const p = new Policy(plain(basePolicy({ issued_seq: 7 })));
  const ok = { group: 'shop', now: Date.now(), lastIssuedSeq: 6, minIssuedSeq: 0 };
  assert.equal(code(() => checkAcceptance(p, ok)), 'accepted');
  assert.equal(code(() => checkAcceptance(p, { ...ok, group: 'other' })), 'policy_rejected');
  assert.equal(code(() => checkAcceptance(p, { ...ok, now: Date.now() + 40 * 86400_000 })), 'expired_policy');
  assert.equal(code(() => checkAcceptance(p, { ...ok, lastIssuedSeq: 7 })), 'policy_rejected');
  assert.equal(code(() => checkAcceptance(p, { ...ok, lastIssuedSeq: 7, allowEqualSeq: true })), 'accepted');
  assert.equal(code(() => checkAcceptance(p, { ...ok, minIssuedSeq: 8 })), 'policy_rejected');
});

test('HMAC key lines (7.1) and key choice with accept_kids', () => {
  const k32 = Buffer.alloc(32, 7).toString('base64url');
  assert.equal(parseKeyRing(`k1:${k32}\r\n\nk2:${k32}\n`).order.join(), 'k1,k2');
  for (const bad of [undefined, '', 'k1', `K1:${k32}`, `k1:${k32}=`, `k1:${Buffer.alloc(31).toString('base64url')}`, ` k1:${k32}`, `k1:${k32}\nbad`]) {
    assert.equal(code(() => parseKeyRing(bad)), 'key_missing', String(bad));
  }
  const p = new Policy(plain(basePolicy({ hmac: { kid: 'k9', accept_kids: ['k3', 'k2'], epoch: '2026-10' } })));
  assert.equal(selectKey(parseKeyRing(`k1:${k32}\nk2:${k32}`), p).kid, 'k2');
  assert.equal(code(() => selectKey(parseKeyRing(`k1:${k32}`), p)), 'key_mismatch');
});

test('CSR generation and the enrollment token pin', () => {
  const { csrPem, keyPem } = generateCsr('shop-api');
  assert.equal(pemBlocks(csrPem, 'CERTIFICATE REQUEST').length, 1);
  assert.match(keyPem, /BEGIN PRIVATE KEY/);
  const pki = createPki();
  assert.match(pki.issueFromCsr(csrPem, 'src-1'), /BEGIN CERTIFICATE/);
  assert.equal(tokenPin('tte_' + 'a'.repeat(32) + '.' + 'b'.repeat(43)), 'b'.repeat(43));
  assert.equal(tokenPin('tte_short.' + 'b'.repeat(43)), null);
});
