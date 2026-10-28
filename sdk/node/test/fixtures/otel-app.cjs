'use strict';
// An app that already uses OpenTelemetry (NodeSDK + HTTP instrumentation, in-memory span
// exporter). GET /work calls an internal downstream over node:http and fetch; GET /spans
// returns the spans the app exported so far. Prints {"port": N} when listening.

const { NodeSDK } = require('@opentelemetry/sdk-node');
const { InMemorySpanExporter, SimpleSpanProcessor } = require('@opentelemetry/sdk-trace');
const { HttpInstrumentation } = require('@opentelemetry/instrumentation-http');

const exporter = new InMemorySpanExporter();
const sdk = new NodeSDK({
  serviceName: 'shop-api',
  spanProcessors: [new SimpleSpanProcessor({ exporter })],
  instrumentations: [new HttpInstrumentation()],
});
sdk.start();

const http = require('node:http');
const api = require('@opentelemetry/api');

const downstream = http.createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ stock: 3, traceparent: req.headers.traceparent ? 'present' : 'absent' }));
});

function get(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let b = '';
      res.on('data', (c) => (b += c));
      res.on('end', () => resolve(b));
    }).on('error', reject);
  });
}

const app = http.createServer(async (req, res) => {
  if (req.url === '/spans') {
    const spans = exporter.getFinishedSpans().map((s) => ({
      name: s.name,
      kind: s.kind,
      traceId: s.spanContext().traceId,
      spanId: s.spanContext().spanId,
      parentSpanId: s.parentSpanContext ? s.parentSpanContext.spanId : s.parentSpanId,
      attributes: Object.keys(s.attributes).sort(),
      status: s.status.code,
    }));
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ spans, provider: api.trace.getTracerProvider().constructor.name }));
    return;
  }
  if (req.url === '/work') {
    const a = await get(`http://127.0.0.1:${downstream.address().port}/stock?sku=TSHIRT-RED-M`);
    const r = await fetch(`http://127.0.0.1:${downstream.address().port}/stock?sku=MUG-BLUE`);
    const b = await r.text();
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ a: JSON.parse(a), b: JSON.parse(b) }));
    return;
  }
  res.writeHead(404);
  res.end();
});

downstream.listen(0, '127.0.0.1', () => {
  app.listen(0, '127.0.0.1', () => process.stdout.write(JSON.stringify({ port: app.address().port }) + '\n'));
});
process.on('SIGTERM', () => {
  sdk.shutdown().finally(() => process.exit(0));
});
