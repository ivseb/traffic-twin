// Red-team fixture app for the Node SDK (invented data). Before the SDK loads it records every
// outbound TCP connection and DNS lookup of the process, then starts the SDK from the
// environment (TT_*). Routes:
//   GET  /__rt/status        agent status, recorded connections and lookups
//   POST /out                calls CARRIER_URL with fetch and node:http (canary in every part)
//   *                        echoes the canary (x-rt-canary) in body, headers and cookies
// Prints {"port": N} on stdout when listening.

import http from 'node:http';
import net from 'node:net';
import dns from 'node:dns';

const connects = [];
const lookups = [];
const origConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...args) {
  const o = args[0];
  if (o && typeof o === 'object' && !Array.isArray(o)) connects.push(`${o.host ?? o.path ?? '?'}:${o.port ?? ''}`);
  else if (Array.isArray(o)) connects.push(`${o[0]?.host ?? '?'}:${o[0]?.port ?? ''}`);
  else connects.push(`${args[1] ?? '?'}:${o}`);
  return origConnect.apply(this, args);
};
const origLookup = dns.lookup;
dns.lookup = function (host, ...rest) {
  lookups.push(String(host));
  return origLookup.call(this, host, ...rest);
};

const sdk = await import(new URL('../../../../sdk/node/dist/esm/index.js', import.meta.url).href);
const agent = await Promise.race([sdk.start(), new Promise((r) => setTimeout(r, 50))]);
void agent;

const carrier = process.env.CARRIER_URL;

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
  });
}

const server = http.createServer(async (req, res) => {
  const canary = String(req.headers['x-rt-canary'] ?? 'none');
  if (req.url === '/__rt/status') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ status: sdk.current()?.status() ?? null, connects, lookups, otel: globalThis.__rtOtelAccess ?? null }));
    return;
  }
  await readBody(req);
  if (req.url.startsWith('/out') && carrier) {
    try {
      const r = await fetch(carrier + '/v1/shipments/' + canary + '?ref=' + canary, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-rt-out': canary, cookie: 'sid=' + canary },
        body: JSON.stringify({ orderId: canary, note: canary }),
      });
      await r.text();
      await new Promise((resolve) => {
        const q = http.request(carrier + '/v1/shipments?orderId=' + canary, { headers: { 'x-rt-out': canary } }, (rs) => {
          rs.resume();
          rs.on('end', resolve);
        });
        q.on('error', resolve);
        q.end();
      });
    } catch {
      // ignore
    }
  }
  res.writeHead(200, { 'content-type': 'application/json', 'x-rt-echo': canary, 'set-cookie': 'sess=' + canary + '; Path=/' });
  res.end(JSON.stringify({ id: canary, email: canary + '@example.com', nested: { deep: [canary, { k: canary }] } }));
});
server.listen(0, '127.0.0.1', () => process.stdout.write(JSON.stringify({ port: server.address().port }) + '\n'));
process.on('SIGTERM', () => server.close(() => process.exit(0)));
