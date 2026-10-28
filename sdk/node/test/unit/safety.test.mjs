// v1.3 source-side safety subset (docs/spec/hardening.md 2.1): H1, H2, H3.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import { Refused, UNSAFE_DETAIL, ed25519PublicKey, verifyEnvelope } from '../../dist/esm/sanitizer/policy.js';
import { nodeToPlain, parseJson } from '../../dist/esm/sanitizer/json.js';
import { basePolicy, canonicalBytes } from '../helpers/fake-core.mjs';

const plain = (o) => nodeToPlain(parseJson(Buffer.from(JSON.stringify(o))), true);

function verifier(body) {
  const k = generateKeyPairSync('ed25519');
  const bytes = canonicalBytes(body);
  const env = {
    format: 'tt.policy.compiled/v1',
    policy_id: body.policy_id,
    version: body.version,
    issued_seq: body.issued_seq,
    hash: 'sha256:' + createHash('sha256').update(bytes).digest('hex'),
    body_b64: bytes.toString('base64url'),
    signature: {
      alg: 'Ed25519',
      kid: 'pk1',
      sig: sign(null, Buffer.concat([Buffer.from('tt.policy.body/v1\0'), bytes]), k.privateKey).toString('base64url'),
    },
  };
  const keys = new Map([['pk1', ed25519PublicKey(k.publicKey.export({ format: 'jwk' }).x)]]);
  return () => verifyEnvelope(plain(env), keys, true);
}

function outcome(body) {
  try {
    verifier(body)();
    return 'accepted';
  } catch (e) {
    if (e instanceof Refused) return e.detail.startsWith(UNSAFE_DETAIL) ? 'unsafe' : e.code;
    throw e;
  }
}

const created = Date.parse(basePolicy().created_at);
const at = (ms) => new Date(created + ms).toISOString().replace(/\.000Z$/, 'Z');
const WEEK = 7 * 86400_000;
const svc = { name: 'shop-api', match: { inbound: true, internal: false }, ops: [] };

test('H1: keep or hmac on a credential header is unsafe wherever it appears', () => {
  for (const h of ['authorization', 'cookie', 'set-cookie', 'proxy-authorization']) {
    for (const action of [{ action: 'keep' }, { action: 'hmac', domain: 'tok' }]) {
      const rule = { headers: { [h]: action } };
      const what = `${h} ${action.action}`;
      assert.equal(outcome(basePolicy({ global: { request: rule } })), 'unsafe', 'global request ' + what);
      assert.equal(outcome(basePolicy({ global: { response: rule } })), 'unsafe', 'global response ' + what);
      assert.equal(outcome(basePolicy({ global: { errors: rule } })), 'unsafe', 'global errors ' + what);
      assert.equal(outcome(basePolicy({ services: [{ ...svc, errors: rule }] })), 'unsafe', 'service errors ' + what);
      assert.equal(outcome(basePolicy({ services: [{ ...svc, ops: [{ op: 'GET /a', request: rule }] }] })), 'unsafe', 'op request ' + what);
      assert.equal(outcome(basePolicy({ services: [{ ...svc, ops: [{ op: 'GET /a', response: rule }] }] })), 'unsafe', 'op response ' + what);
    }
  }
  assert.equal(outcome(basePolicy({ global: { request: { headers: { authorization: { action: 'drop' } } } } })), 'accepted');
});

test('H2: keep or hmac on a global .* rule is unsafe; service and operation rules and drop are fine', () => {
  const g = (action, path = '$.a.*') => basePolicy({ global: { response: { body: [{ path, action }] } } });
  assert.equal(outcome(g({ action: 'keep' })), 'unsafe');
  assert.equal(outcome(g({ action: 'hmac', domain: 'tok' }, '$.items[*].*')), 'unsafe');
  assert.equal(outcome(g({ action: 'drop' })), 'accepted');
  const rule = [{ path: '$.*', action: { action: 'keep' } }];
  assert.equal(outcome(basePolicy({ services: [{ ...svc, request: { body: rule } }] })), 'accepted');
  assert.equal(outcome(basePolicy({ services: [{ ...svc, ops: [{ op: 'GET /a', response: { body: rule } }] }] })), 'accepted');
});

test('H3: discovery and auto_words may not expire after created_at + 7 days', () => {
  const win = (field, ms) => field === 'discovery'
    ? basePolicy({ discovery: { enabled: true, expires_at: at(ms) } })
    : basePolicy({ segments: { auto_words: true, auto_words_expires_at: at(ms), allow: [], hosts_allow: [] } });
  for (const f of ['discovery', 'auto_words']) {
    assert.equal(outcome(win(f, WEEK)), 'accepted', f + ' at exactly 7 days');
    assert.equal(outcome(win(f, WEEK + 1000)), 'unsafe', f + ' at 7 days + 1 s');
  }
  assert.equal(outcome(basePolicy({ discovery: { enabled: false, expires_at: at(30 * 86400_000) } })), 'accepted');
});
