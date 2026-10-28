// A tiny e-commerce service without frameworks (invented data): POST /orders creates an
// order and books a shipment at the carrier with fetch (undici) and node:http.
//
// Prints {"port": N} on stdout when listening. Env: CARRIER_URL.

import http from 'node:http';

const carrier = process.env.CARRIER_URL;
let seq = 184;

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function httpGet(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const r = http.request(url, { method: 'GET', headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    r.on('error', reject);
    r.end();
  });
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/__cpu') {
      // Benchmark helper: CPU time used by this process so far (microseconds).
      // `us`: whole process (all threads); `main`: this thread only (the one serving requests).
      const u = process.cpuUsage();
      const m = typeof process.threadCpuUsage === 'function' ? process.threadCpuUsage() : u;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ us: u.user + u.system, main: m.user + m.system }));
      return;
    }
    if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('ok');
      return;
    }
    if (req.method === 'POST' && req.url.startsWith('/orders')) {
      const order = JSON.parse((await readBody(req)).toString('utf8'));
      // Benchmark knob: a handler that waits on async I/O (a database, a queue) before answering.
      if (process.env.ORDER_IO_MS) await new Promise((r) => setTimeout(r, Number(process.env.ORDER_IO_MS)));
      const id = `ORD-2026-${String(seq++).padStart(6, '0')}`;
      if (carrier) {
        const s = await fetch(carrier + '/v1/shipments', {
          method: 'POST',
          headers: { 'content-type': 'application/json', authorization: 'Bearer carrier-api-key-not-real' },
          body: JSON.stringify({ orderId: id, email: order.email, weightGrams: 1200 }),
        });
        await s.json();
        await httpGet(carrier + '/v1/shipments?orderId=' + encodeURIComponent(id));
      }
      if (process.env.INTERNAL_URL) {
        await (await fetch(process.env.INTERNAL_URL + '/stock?sku=TSHIRT-RED-M', { headers: { baggage: 'tenant=acme' } })).text();
        await httpGet(process.env.INTERNAL_URL + '/stock?sku=MUG-BLUE');
      }
      res.writeHead(201, { 'content-type': 'application/json; charset=utf-8', 'set-cookie': 'cart=c-9f8e7d6c5b4a; Path=/' });
      res.end(JSON.stringify({ id, status: 'CREATED', total: 73.4, email: order.email }));
      return;
    }
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end('{"error":{"code":"NOT_FOUND"}}');
  } catch (e) {
    res.writeHead(500, { 'content-type': 'application/json' });
    res.end('{"error":{"code":"INTERNAL"}}');
  }
});

server.keepAliveTimeout = 30_000;
server.listen(0, '127.0.0.1', () => {
  process.stdout.write(JSON.stringify({ port: server.address().port }) + '\n');
});
process.on('SIGTERM', () => server.close(() => process.exit(0)));
