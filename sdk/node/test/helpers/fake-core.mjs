// A fake tt-core intake listener for tests: Fleet source endpoints (enroll, heartbeat,
// policy, renew) and OTLP/HTTP JSON intake, TLS with the root in the chain, mTLS checked
// on every route except enroll. Invented data only.

import https from 'node:https';
import { generateKeyPairSync, randomBytes, sign, createHash } from 'node:crypto';
import { createPki } from './pki.mjs';
import { pinOf } from '../../dist/esm/fleet/asn1.js';
import { nodeToOut, parseJson, writeCanonical } from '../../dist/esm/sanitizer/json.js';

export const SIGNING_KID = 'policy-test-1';

export function canonicalBytes(obj) {
  return Buffer.from(writeCanonical(nodeToOut(parseJson(Buffer.from(JSON.stringify(obj))))), 'utf8');
}

export function basePolicy(overrides = {}) {
  const now = Date.now();
  return {
    format: 'tt.policy.body/v1',
    policy_id: 'p-shop',
    version: 1,
    issued_seq: 1,
    created_at: new Date(now - 60_000).toISOString().replace(/\.\d+Z$/, 'Z'),
    not_after: new Date(now + 30 * 86400_000).toISOString().replace(/\.\d+Z$/, 'Z'),
    targets: { groups: ['shop'] },
    hmac: { kid: 'k1', accept_kids: [], epoch: '2026-10' },
    sampling: { rate_bp: 10000, trust_baggage: false, propagate_to: [] },
    segments: { auto_words: false, allow: ['v1'], hosts_allow: [] },
    limits: { max_body_bytes: 1048576, max_depth: 32, max_array: 32, max_keys: 256, keep_max_bytes: 64 },
    global: { request: { headers: { 'content-type': { action: 'keep' } } }, response: { headers: { 'content-type': { action: 'keep' } } } },
    services: [],
    ...overrides,
  };
}

/** A fresh Ed25519 policy signing key: { privateKey, publicKey, pub (raw, base64url) }. */
export function newSigner() {
  const k = generateKeyPairSync('ed25519');
  return { ...k, pub: k.publicKey.export({ format: 'jwk' }).x };
}

/** The add_signing_keys entry for `newKey` (from newSigner) endorsed by `endorser` under `endorsedBy`. */
export function endorsedKey(endorser, endorsedBy, kid, newKey) {
  const raw = Buffer.from(newKey.pub, 'base64url');
  const endorsement = sign(null, Buffer.concat([Buffer.from('tt-fleet-key/v1\0' + kid + '\0', 'latin1'), raw]), endorser.privateKey);
  return { kid, alg: 'Ed25519', public_key: newKey.pub, endorsed_by: endorsedBy, endorsement: endorsement.toString('base64url') };
}

export async function startFakeCore(opts = {}) {
  const pki = createPki();
  const signer = generateKeyPairSync('ed25519');
  const publicKey = signer.publicKey.export({ format: 'jwk' }).x;
  const state = {
    events: [],
    eventStrings: [],
    otlpRequests: [],
    heartbeats: [],
    enrollments: [],
    policyFetches: 0,
    kill: false,
    minIssuedSeq: 0,
    failLogs: 0,
    policyBody: opts.policy ?? basePolicy(),
    envelope: null,
    // Merged into every heartbeat response (add_signing_keys, revoke_signing_keys, ...).
    heartbeatExtra: {},
  };
  const secret = randomBytes(24).toString('base64url');
  const token = `tte_${secret}.${pinOf(pki.caDer)}`;

  function makeEnvelope(body, key = signer, kid = SIGNING_KID) {
    const bytes = canonicalBytes(body);
    const sig = sign(null, Buffer.concat([Buffer.from('tt.policy.body/v1\0', 'latin1'), bytes]), key.privateKey);
    return {
      format: 'tt.policy.compiled/v1',
      policy_id: body.policy_id,
      version: body.version,
      issued_seq: body.issued_seq,
      hash: 'sha256:' + createHash('sha256').update(bytes).digest('hex'),
      body_b64: bytes.toString('base64url'),
      signature: { alg: 'Ed25519', kid, sig: sig.toString('base64url') },
    };
  }
  state.envelope = state.policyBody ? makeEnvelope(state.policyBody) : null;

  const server = https.createServer({
    key: pki.serverKeyPem,
    cert: pki.serverCertChainPem,
    ca: pki.caPem,
    requestCert: true,
    rejectUnauthorized: false,
  });
  let base = '';
  const json = (res, status, obj, headers = {}) => {
    const b = obj === undefined ? '' : JSON.stringify(obj);
    res.writeHead(status, { 'content-type': 'application/json', ...headers });
    res.end(b);
  };
  server.on('request', (req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const path = req.url.split('?')[0];
      if (path === '/fleet/v1/enroll' && req.method === 'POST') {
        const j = JSON.parse(body.toString('utf8'));
        if (j.token !== token) return json(res, 401, { code: 'token', message: 'unknown token' });
        state.enrollments.push(j);
        const sourceId = 'src-' + randomBytes(6).toString('hex');
        let clientCert;
        let clientKey;
        if (j.csr) clientCert = pki.issueFromCsr(j.csr, sourceId);
        else ({ certPem: clientCert, keyPem: clientKey } = pki.issueWithKey(sourceId));
        return json(res, 201, {
          source_id: sourceId,
          group: 'shop',
          service_name: j.source.service_name,
          client_cert: clientCert,
          ...(clientKey ? { client_key: clientKey } : {}),
          ca_chain: pki.caPem,
          policy_signing_keys: [{ kid: SIGNING_KID, alg: 'Ed25519', public_key: publicKey }],
          intake_url: base + '/v1/logs',
          fleet_url: base,
          policy_max_age_s: 86400,
          heartbeat_interval_s: 30,
          policy_poll_interval_s: 60,
        });
      }
      if (!req.socket.authorized) return json(res, 401, { code: 'mtls', message: 'client certificate required' });
      if (path === '/fleet/v1/heartbeat' && req.method === 'POST') {
        state.heartbeats.push(JSON.parse(body.toString('utf8')));
        return json(res, 200, {
          next_heartbeat_s: 30,
          kill: state.kill,
          min_issued_seq: state.minIssuedSeq,
          policy_current: state.envelope ? { policy_id: state.envelope.policy_id, version: state.envelope.version, issued_seq: state.envelope.issued_seq, hash: state.envelope.hash } : null,
          ...state.heartbeatExtra,
        });
      }
      if (path === '/fleet/v1/policy' && req.method === 'GET') {
        state.policyFetches++;
        if (!state.envelope) return json(res, 404, { code: 'none', message: 'no policy' });
        const etag = `"${state.envelope.hash}"`;
        if (req.headers['if-none-match'] === etag) {
          res.writeHead(304);
          return res.end();
        }
        return json(res, 200, state.envelope, { etag });
      }
      if (path === '/v1/logs' && req.method === 'POST') {
        if (state.failLogs > 0) {
          state.failLogs--;
          return json(res, 503, { code: 'busy' }, { 'retry-after': '0' });
        }
        const doc = JSON.parse(body.toString('utf8'));
        state.otlpRequests.push(doc);
        for (const rl of doc.resourceLogs) {
          for (const sl of rl.scopeLogs) {
            for (const lr of sl.logRecords) {
              state.eventStrings.push(lr.body.stringValue);
              state.events.push({ event: JSON.parse(lr.body.stringValue), record: lr, resource: rl.resource });
            }
          }
        }
        return json(res, 200, {});
      }
      json(res, 404, { code: 'not_found', message: 'no route' });
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `https://127.0.0.1:${server.address().port}`;

  return {
    url: base,
    token,
    state,
    pki,
    signer,
    /** Publishes `body`, signed by `key` (default: the enrollment key) under `kid`. */
    setPolicy(body, key = signer, kid = SIGNING_KID) {
      state.policyBody = body;
      state.envelope = body ? makeEnvelope(body, key, kid) : null;
    },
    makeEnvelope,
    async waitFor(pred, timeoutMs = 10_000) {
      const t0 = Date.now();
      while (Date.now() - t0 < timeoutMs) {
        if (pred(state)) return true;
        await new Promise((r) => setTimeout(r, 25));
      }
      return false;
    },
    close() {
      server.closeAllConnections?.();
      return new Promise((r) => server.close(() => r()));
    },
  };
}
