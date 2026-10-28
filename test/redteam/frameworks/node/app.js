// Red team round 3: Express app, Node SDK injected zero-code
// (NODE_OPTIONS=--import /tt/sdk/node/dist/esm/register.js, as the injector does).
// The app itself never logs request data: any canary in the logs comes from the SDK.
const express = require('express');

const app = express();
app.use(express.json());
app.get('/health', (req, res) => res.type('text/plain').send('ok'));
app.post('/orders/:id', (req, res) => {
  const b = req.body || {};
  res.set('x-echo', String(req.get('x-secret') || ''));
  res.cookie('sess', String(b.secret || ''));
  res.status(201).json({ id: req.params.id, status: 'created', echo: b.secret, email: b.nested && b.nested.email });
});
app.get('/fail/:v', (req, res) => {
  res.status(500).json({ error: { code: 'E_FAIL', message: `order ${req.params.v} failed` } });
});
app.get('/boom/:v', (req) => {
  throw new Error(`boom ${req.params.v}`); // Express default error handler: 500, stack on stderr
});
app.listen(8080, '0.0.0.0', () => console.log('listening on 8080'));
