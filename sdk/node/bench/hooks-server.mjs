// Server half of bench/hooks.mjs: a bare node:http server with the SDK capture hooks
// installed on a stub host (no Fleet, no export), to measure the hook path alone.
//   HOOKS=none|all   RATE_BP=<basis points>   OUT=0|1 (the handler makes 2 outbound calls)

import http from 'node:http';
import { basePolicy } from '../test/helpers/fake-core.mjs';
import { HMAC_KEY } from '../test/helpers/procs.mjs';

const HOOKS = process.env.HOOKS ?? 'none';
const RATE_BP = Number(process.env.RATE_BP ?? 0);
const OUT = process.env.OUT === '1';
const SUBJECT = process.env.SUBJECT ?? 'none'; // none | header | cookie | jwt
let submitted = 0;

if (HOOKS === 'all') {
  const { Sanitizer } = await import('../dist/esm/sanitizer/sanitizer.js');
  const { Policy, parseKeyRing, selectKey } = await import('../dist/esm/sanitizer/policy.js');
  const { nodeToPlain, parseJson } = await import('../dist/esm/sanitizer/json.js');
  const { installInbound } = await import('../dist/esm/capture/inbound.js');
  const { installOutboundHttp } = await import('../dist/esm/capture/outbound-http.js');
  const { installOutboundUndici } = await import('../dist/esm/capture/outbound-undici.js');
  const identity = SUBJECT === 'header' ? { subject: { from: 'header', name: 'x-customer-id' } }
    : SUBJECT === 'cookie' ? { subject: { from: 'cookie', name: 'sid' } }
    : SUBJECT === 'jwt' ? { subject: { from: 'header', name: 'authorization', jwt_claim: 'sub' } } : undefined;
  const body = basePolicy({ ...(identity ? { identity } : {}), sampling: { rate_bp: RATE_BP, trust_baggage: false, propagate_to: [] }, services: [{ name: 'shop-api', match: { inbound: true, internal: false }, ops: [] }] });
  const p = new Policy(nodeToPlain(parseJson(Buffer.from(JSON.stringify(body))), true));
  p.hash = 'sha256:' + '0'.repeat(64);
  const san = new Sanitizer(p, selectKey(parseKeyRing(HMAC_KEY), p));
  const names = new Set(['cookie', 'baggage']);
  // Same shape and cost as the Agent's hot-path methods.
  const overhead = new Float64Array(1024);
  let n = 0;
  const seen = { seen: 0, sampled: 0 };
  const host = {
    active: () => san,
    serviceName: () => 'shop-api',
    decisionHeaders: () => names,
    mayPropagate: () => false,
    submit: () => { submitted++; },
    noteSeen: () => { seen.seen++; },
    noteSampled: () => { seen.sampled++; },
    noteOverhead: (ns) => { overhead[n++ % 1024] = ns; },
    noteError: () => {},
  };
  installInbound(host);
  installOutboundHttp(host);
  installOutboundUndici(host);
}

const sink = http.createServer((req, res) => { res.end('{"ok":true}'); });
await new Promise((r) => sink.listen(0, '127.0.0.1', r));
const sinkUrl = `http://127.0.0.1:${sink.address().port}`;
const agent = new http.Agent({ keepAlive: true });

const server = http.createServer(async (req, res) => {
  if (OUT) {
    await (await fetch(sinkUrl + '/a')).text();
    await new Promise((resolve) => http.get(sinkUrl + '/b', { agent }, (r) => { r.resume(); r.on('end', resolve); }));
  }
  res.writeHead(200, { 'content-type': 'text/plain', 'content-length': '2' });
  res.end('ok');
});
server.keepAliveTimeout = 30_000;
server.listen(0, '127.0.0.1', () => process.send?.({ port: server.address().port }));
process.on('message', (m) => {
  if (m === 'cpu') {
    const u = process.cpuUsage();
    const t = process.threadCpuUsage();
    process.send({ main: t.user + t.system, all: u.user + u.system, submitted });
  } else if (m === 'stop') process.exit(0);
});
