// Cost of the inbound sampling decision for a JWT-subject policy: decide() on header pairs vs decideRaw().
const { basePolicy } = await import('../test/helpers/fake-core.mjs');
const { HMAC_KEY } = await import('../test/helpers/procs.mjs');
const { Sanitizer } = await import('../dist/esm/sanitizer/sanitizer.js');
const { Policy, parseKeyRing, selectKey } = await import('../dist/esm/sanitizer/policy.js');
const { nodeToPlain, parseJson } = await import('../dist/esm/sanitizer/json.js');
const { rawPairs } = await import('../dist/esm/capture/common.js');
const jwt = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.' + Buffer.from('{"sub":"CUS-000777"}').toString('base64url') + '.';
const p = new Policy(nodeToPlain(parseJson(Buffer.from(JSON.stringify(basePolicy({ identity: { subject: { from: 'header', name: 'authorization', jwt_claim: 'sub' } }, sampling: { rate_bp: 0, trust_baggage: false, propagate_to: [] } })))), true));
p.hash = 'sha256:' + '0'.repeat(64);
const san = new Sanitizer(p, selectKey(parseKeyRing(HMAC_KEY), p));
const raw = ['Host', 'localhost:3100', 'User-Agent', 'oha', 'Accept', '*/*', 'Authorization', 'Bearer ' + jwt];
const names = new Set(['cookie', 'baggage', 'authorization']);
const old = () => san.decide({ dir: 'inbound', service_name: 'shop-api', req_headers: rawPairs(raw, names) });
const fast = san.decideRaw ? () => san.decideRaw('shop-api', raw, undefined) : null;
for (const [n, f] of [['decide(rawPairs)', old], ['decideRaw', fast]]) {
  if (!f) continue;
  for (let i = 0; i < 20000; i++) f();
  const t = process.hrtime.bigint();
  for (let i = 0; i < 300000; i++) f();
  console.log(n, (Number(process.hrtime.bigint() - t) / 300000 / 1000).toFixed(2), 'us', JSON.stringify(f()));
}
