// Red-team fake tt-core for the Node SDK: the Fleet source endpoints and the OTLP intake,
// like sdk/node/test/helpers/fake-core.mjs, but every answer can be overridden so a test can
// play a malicious or broken tt-core. Invented data only.

import https from 'node:https';
import { generateKeyPairSync, randomBytes, sign, createHash } from 'node:crypto';
import { createPki } from '../../../sdk/node/test/helpers/pki.mjs';
import { basePolicy, canonicalBytes } from '../../../sdk/node/test/helpers/fake-core.mjs';
import { pinOf } from '../../../sdk/node/dist/esm/fleet/asn1.js';

export { basePolicy, createPki };
export const SIGNING_KID = 'policy-rt-1';

export function newSigner() {
  const k = generateKeyPairSync('ed25519');
  return { ...k, pub: k.publicKey.export({ format: 'jwk' }).x };
}

export function envelope(body, signer, kid = SIGNING_KID) {
  const bytes = canonicalBytes(body);
  const sig = sign(null, Buffer.concat([Buffer.from('tt.policy.body/v1\0', 'latin1'), bytes]), signer.privateKey);
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

/**
 * hooks: { heartbeat(state, body) -> object to merge into the answer,
 *          policy(req, res, state) -> true when it answered itself,
 *          logs(req, res, state, body) -> true when it answered itself }
 */
export async function startEvilCore({ policy = basePolicy(), hooks = {} } = {}) {
  const pki = createPki();
  const signer = newSigner();
  const state = {
    events: [], eventStrings: [], heartbeats: [], enrollments: [], policyFetches: 0, logPosts: 0,
    kill: false, minIssuedSeq: 0, envelope: policy ? envelope(policy, signer) : null,
  };
  const token = `tte_${randomBytes(24).toString('base64url')}.${pinOf(pki.caDer)}`;
  const server = https.createServer({ key: pki.serverKeyPem, cert: pki.serverCertChainPem, ca: pki.caPem, requestCert: true, rejectUnauthorized: false });
  let base = '';
  const json = (res, status, obj, headers = {}) => {
    res.writeHead(status, { 'content-type': 'application/json', ...headers });
    res.end(obj === undefined ? '' : JSON.stringify(obj));
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
          source_id: sourceId, group: 'shop', service_name: j.source.service_name, client_cert: clientCert,
          ...(clientKey ? { client_key: clientKey } : {}), ca_chain: pki.caPem,
          policy_signing_keys: [{ kid: SIGNING_KID, alg: 'Ed25519', public_key: signer.pub }],
          intake_url: base + '/v1/logs', fleet_url: base, policy_max_age_s: 86400, heartbeat_interval_s: 30, policy_poll_interval_s: 60,
        });
      }
      if (!req.socket.authorized) return json(res, 401, { code: 'mtls', message: 'client certificate required' });
      if (path === '/fleet/v1/heartbeat' && req.method === 'POST') {
        const hb = JSON.parse(body.toString('utf8'));
        state.heartbeats.push(hb);
        const e = state.envelope;
        return json(res, 200, {
          next_heartbeat_s: 30, kill: state.kill, min_issued_seq: state.minIssuedSeq,
          policy_current: e ? { policy_id: e.policy_id, version: e.version, issued_seq: e.issued_seq, hash: e.hash } : null,
          ...(hooks.heartbeat ? hooks.heartbeat(state, hb) : {}),
        });
      }
      if (path === '/fleet/v1/policy' && req.method === 'GET') {
        state.policyFetches++;
        if (hooks.policy && hooks.policy(req, res, state)) return;
        if (!state.envelope) return json(res, 404, { code: 'none', message: 'no policy' });
        const etag = `"${state.envelope.hash}"`;
        if (req.headers['if-none-match'] === etag) {
          res.writeHead(304);
          return res.end();
        }
        return json(res, 200, state.envelope, { etag });
      }
      if (path === '/v1/logs' && req.method === 'POST') {
        state.logPosts++;
        if (hooks.logs && hooks.logs(req, res, state, body)) return;
        const doc = JSON.parse(body.toString('utf8'));
        for (const rl of doc.resourceLogs) for (const sl of rl.scopeLogs) for (const lr of sl.logRecords) {
          state.eventStrings.push(lr.body.stringValue);
          state.events.push(JSON.parse(lr.body.stringValue));
        }
        return json(res, 200, {});
      }
      json(res, 404, { code: 'not_found', message: 'no route' });
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `https://127.0.0.1:${server.address().port}`;
  return {
    url: base, port: server.address().port, token, state, pki, signer, server,
    setPolicy(body, s = signer, kid = SIGNING_KID) { state.envelope = body ? envelope(body, s, kid) : null; },
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
