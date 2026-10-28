import { test } from 'node:test';
import assert from 'node:assert/strict';
import { basePolicy } from '../helpers/fake-core.mjs';
import { HMAC_KEY } from '../helpers/procs.mjs';
import { Sanitizer } from '../../dist/esm/sanitizer/sanitizer.js';
import { Policy, parseKeyRing, selectKey } from '../../dist/esm/sanitizer/policy.js';
import { nodeToPlain, parseJson } from '../../dist/esm/sanitizer/json.js';

function san(over, opts = {}) {
  const p = new Policy(nodeToPlain(parseJson(Buffer.from(JSON.stringify(basePolicy(over)))), true));
  p.hash = 'sha256:' + '0'.repeat(64);
  return new Sanitizer(p, selectKey(parseKeyRing(HMAC_KEY), p), opts);
}
const pairs = (raw) => { const o = []; for (let i = 0; i < raw.length; i += 2) o.push([raw[i], Buffer.from(raw[i + 1], 'latin1')]); return o; };
const jwt = (sub) => 'eyJhbGciOiJIUzI1NiJ9.' + Buffer.from(JSON.stringify({ sub })).toString('base64url') + '.c2ln';

// decideRaw must agree with decide() on the same headers (or defer with null).
test('decideRaw gives the same decision as decide() for header, cookie and JWT subjects', () => {
  const cases = [
    [{ from: 'header', name: 'X-Customer-Id' }, (i) => ['X-Customer-ID', 'cust-' + i]],
    [{ from: 'cookie', name: 'sid' }, (i) => ['Cookie', `theme=dark; sid=s-${i}; lang=it`]],
    [{ from: 'header', name: 'authorization', jwt_claim: 'sub' }, (i) => ['Authorization', 'Bearer ' + jwt('u' + i)]],
  ];
  for (const [subject, hdr] of cases) {
    const s = san({ identity: { subject }, sampling: { rate_bp: 3000, trust_baggage: false, propagate_to: [] } });
    let yes = 0;
    for (let i = 0; i < 400; i++) {
      const raw = ['Host', 'x', ...hdr(i), 'Accept', '*/*'];
      const a = s.decide({ dir: 'inbound', service_name: 'shop-api', req_headers: pairs(raw) });
      const b = s.decideRaw('shop-api', raw, undefined);
      const c = s.decideRaw('shop-api', raw, undefined); // from the cache
      assert.deepEqual(b, a);
      assert.deepEqual(c, a);
      if (a.sampled) yes++;
    }
    assert.ok(yes > 40 && yes < 220, `rate roughly 30%: ${yes}`);
    // no subject header at all: falls back to random like decide()
    assert.equal(s.decideRaw('shop-api', ['Host', 'x'], undefined).by, 'random');
    // a repeated subject header is left to decide()
    assert.equal(s.decideRaw('shop-api', [...hdr(1), ...hdr(2)], undefined), null);
  }
});

test('decideRaw: trace id, random and baggage', () => {
  const s = san({ sampling: { rate_bp: 10000, trust_baggage: false, propagate_to: [] } });
  const tid = '4bf92f3577b34da6a3ce929d0e0e4736';
  assert.deepEqual(s.decideRaw('shop-api', ['Host', 'x'], tid), s.decide({ dir: 'inbound', service_name: 'shop-api', req_headers: [], trace_id: tid }));
  assert.deepEqual(s.decideRaw('shop-api', [], undefined), { sampled: true, by: 'random' });
  assert.deepEqual(san({ sampling: { rate_bp: 0, trust_baggage: false, propagate_to: [] } }).decideRaw('shop-api', [], undefined), { sampled: false, by: 'random' });
  const t = san({ sampling: { rate_bp: 0, trust_baggage: true, propagate_to: [] }, services: [{ name: 'shop-api', match: { inbound: true, internal: true }, ops: [] }] });
  assert.equal(t.decideRaw('shop-api', ['baggage', 'tt.s=1'], undefined), null);
  assert.deepEqual(t.decide({ dir: 'inbound', service_name: 'shop-api', req_headers: pairs(['baggage', 'tt.s=1']) }), { sampled: true, by: 'baggage' });
});
