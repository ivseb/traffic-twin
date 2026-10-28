// Micro-bench of the capture hook path alone (no Fleet, no export): CPU time of the
// request thread per request, with the hooks off and on, for requests that are NOT sampled
// (rate 0) and for sampled ones. The fixed per-request cost at 0 % is what every request
// pays whatever the sampling rate.
//
//   node bench/hooks.mjs [--seconds 3] [--rounds 7] [--concurrency 16] [--out 1] [--subject none|header|cookie|jwt]
//
// A trivial GET (~70 us of server work) is the worst case for the relative cost; --out 1
// makes the handler call a local sink with fetch and node:http (2 more captured exchanges).

import { fork } from 'node:child_process';
import net from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const arg = (name, d) => {
  const i = process.argv.indexOf('--' + name);
  return i > 0 ? Number(process.argv[i + 1]) : d;
};
const SECONDS = arg('seconds', 3);
const ROUNDS = arg('rounds', 7);
const CONC = arg('concurrency', 16);
const OUT = arg('out', 0);
const SUBJECT = process.argv.includes('--subject') ? process.argv[process.argv.indexOf('--subject') + 1] : 'none'; // none | header | cookie | jwt
const SERVER = join(dirname(fileURLToPath(import.meta.url)), 'hooks-server.mjs');
// 600 distinct customers, like the demo; the subject (if the policy has one) is a header, a cookie or a JWT.
const jwt = (i) => 'eyJhbGciOiJIUzI1NiJ9.' + Buffer.from(JSON.stringify({ sub: 'cust-' + (100000 + i), iat: 1792000000, exp: 1793000000, scope: 'shop' })).toString('base64url') + '.c2lnbmF0dXJlLW5vdC1yZWFs';
const REQS = Array.from({ length: 600 }, (_, i) => {
  const extra = SUBJECT === 'header' ? `x-customer-id: cust-${100000 + i}\r\n`
    : SUBJECT === 'cookie' ? `Cookie: theme=dark; sid=sess-${100000 + i}; lang=it\r\n`
    : SUBJECT === 'jwt' ? `Authorization: Bearer ${jwt(i)}\r\n` : '';
  return Buffer.from(`GET /customers/${i}/orders?x=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: bench\r\nAccept: */*\r\n${extra}\r\n`);
});
let next = 0;


function ask(child, msg) {
  return new Promise((resolve) => {
    const h = (m) => { if (m && m.main !== undefined) { child.off('message', h); resolve(m); } };
    child.on('message', h);
    child.send(msg);
  });
}

function drive(port, ms) {
  return new Promise((resolve) => {
    let count = 0;
    let open = CONC;
    const end = Date.now() + ms;
    for (let i = 0; i < CONC; i++) {
      const s = net.connect(port, '127.0.0.1');
      s.setNoDelay(true);
      s.on('connect', () => s.write(REQS[next++ % 600]));
      s.on('data', (d) => {
        if (d[d.length - 1] !== 0x6b /* 'k' of "ok" */) return;
        count++;
        if (Date.now() < end) s.write(REQS[next++ % 600]);
        else s.end();
      });
      s.on('close', () => { if (--open === 0) resolve(count); });
      s.on('error', () => {});
    }
  });
}

async function variant(hooks, rateBp) {
  const child = fork(SERVER, [], { env: { PATH: process.env.PATH, HOOKS: hooks, RATE_BP: String(rateBp), OUT: String(OUT), SUBJECT }, stdio: ['ignore', 'inherit', 'inherit', 'ipc'] });
  const { port } = await new Promise((r) => child.once('message', r));
  await drive(port, 1500); // warm-up
  const c0 = await ask(child, 'cpu');
  const n = await drive(port, SECONDS * 1000);
  const c1 = await ask(child, 'cpu');
  child.send('stop');
  return { n, rps: n / SECONDS, us: (c1.main - c0.main) / n, usAll: (c1.all - c0.all) / n, submitted: c1.submitted - c0.submitted };
}

const med = (xs) => { const a = [...xs].sort((x, y) => x - y); const h = a.length >> 1; return a.length % 2 ? a[h] : (a[h - 1] + a[h]) / 2; };
const cases = [['off', 'none', 0], ['hooks, not sampled (0 %)', 'all', 0], ['hooks, 5 %', 'all', 500], ['hooks, 100 %', 'all', 10000]];
const res = cases.map(() => []);
for (let r = 0; r < ROUNDS; r++) {
  for (let i = 0; i < cases.length; i++) res[i].push(await variant(cases[i][1], cases[i][2]));
}
console.log(`hook path, subject ${SUBJECT}, ${OUT ? '1 inbound + 2 outbound exchanges' : '1 inbound exchange'} per request, ${CONC} connections, median [min..max] of ${ROUNDS} rounds x ${SECONDS}s, node ${process.versions.node}`);
for (let i = 0; i < cases.length; i++) {
  const us = res[i].map((x) => x.us);
  const d = res[i].map((x, k) => x.us - res[0][k].us);
  console.log(`  ${cases[i][0].padEnd(26)} ${med(us).toFixed(1).padStart(6)} us/req [${Math.min(...us).toFixed(1)}..${Math.max(...us).toFixed(1)}]  ${med(res[i].map((x) => x.rps)).toFixed(0).padStart(6)} req/s  captured ${(med(res[i].map((x) => x.submitted / x.n)) * 100).toFixed(1)}%` + (i > 0 ? `  delta ${med(d).toFixed(1)} us [${Math.min(...d).toFixed(1)}..${Math.max(...d).toFixed(1)}]` : ''));
}
