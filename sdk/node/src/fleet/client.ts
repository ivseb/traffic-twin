// Fleet API client (api/fleet-api.v1.openapi.yaml): enrollment with a `tte_` token and CA
// pin, then mTLS calls for heartbeat, policy and certificate renewal.

import https from 'node:https';
import tls from 'node:tls';
import { X509Certificate } from 'node:crypto';
import { generateCsr, pem, pemBlocks, pinOf } from './asn1.js';
import { parseJsonBody, request } from './http.js';
import { internalAgents } from '../capture/common.js';

export const TOKEN_RE = /^tte_[A-Za-z0-9_-]{32,128}\.([A-Za-z0-9_-]{43})$/;

export interface SigningKey { kid: string; alg: 'Ed25519'; public_key: string }

export interface Enrollment {
  source_id: string;
  group: string;
  service_name: string;
  client_cert: string;
  ca_chain: string;
  not_after?: string;
  policy_signing_keys: SigningKey[];
  intake_url: string;
  fleet_url: string;
  policy_max_age_s: number;
  heartbeat_interval_s: number;
  policy_poll_interval_s: number;
  /** Local bookkeeping. */
  enroll_url: string;
  pin: string;
}

export interface SourceInfo {
  kind: string;
  version: string;
  service_name: string;
  instance?: string;
  runtime?: { lang: string; lang_version: string; os: string; arch: string };
  hmac_kids?: string[];
}

export class FleetError extends Error {
  constructor(readonly code: string, readonly status?: number) {
    super(code);
    this.name = 'FleetError';
  }
}

/** Extracts the CA pin from an enrollment token. */
export function tokenPin(token: string): string | null {
  const m = TOKEN_RE.exec(token);
  return m ? m[1]! : null;
}

interface PeerCert { raw: Buffer; fingerprint256: string; issuerCertificate?: PeerCert }

/**
 * Opens a TLS connection without trusting anything, walks the chain the server presents
 * to its top (the root, which tt-core must include) and checks it against the pin.
 * Returns the root as PEM, to be used as the only trust anchor for the real request.
 */
export function fetchPinnedRoot(url: URL, pin: string, timeoutMs = 10_000): Promise<string> {
  return new Promise((resolve, reject) => {
    const host = url.hostname.replace(/^\[|\]$/g, '');
    const sock = tls.connect({
      host,
      port: Number(url.port || 443),
      servername: /^[0-9.]+$|:/.test(host) ? undefined : host,
      rejectUnauthorized: false,
    });
    const fail = (code: string) => {
      sock.destroy();
      reject(new FleetError(code));
    };
    sock.setTimeout(timeoutMs, () => fail('enroll_tls_timeout'));
    sock.once('error', () => fail('enroll_tls_error'));
    sock.once('secureConnect', () => {
      try {
        let c = sock.getPeerCertificate(true) as unknown as PeerCert;
        if (!c || !c.raw) return fail('enroll_no_peer_cert');
        for (let i = 0; i < 16; i++) {
          const up = c.issuerCertificate;
          if (!up || up === c || up.fingerprint256 === c.fingerprint256 || !up.raw) break;
          c = up;
        }
        const root = new X509Certificate(c.raw);
        if (!root.ca || root.issuer !== root.subject) return fail('enroll_root_missing');
        if (pinOf(c.raw) !== pin) return fail('enroll_pin_mismatch');
        sock.end();
        resolve(pem('CERTIFICATE', c.raw));
      } catch {
        fail('enroll_pin_check');
      }
    });
  });
}

function isHttpsUrl(v: unknown): v is string {
  try {
    return typeof v === 'string' && new URL(v).protocol === 'https:';
  } catch {
    return false;
  }
}

/** Enrolls with a token. Returns the enrollment and the private key PEM (generated locally when useCsr). */
export async function enroll(o: {
  enrollUrl: string;
  token: string;
  source: SourceInfo;
  useCsr: boolean;
  timeoutMs?: number;
}): Promise<{ enrollment: Enrollment; keyPem: string }> {
  const pin = tokenPin(o.token);
  if (!pin) throw new FleetError('enroll_token_malformed');
  const base = new URL(o.enrollUrl);
  if (base.protocol !== 'https:') throw new FleetError('enroll_url_not_https');
  const rootPem = await fetchPinnedRoot(base, pin, o.timeoutMs);
  const agent = new https.Agent({ ca: rootPem, keepAlive: false });
  internalAgents.add(agent);
  let keyPem = '';
  const body: Record<string, unknown> = { token: o.token, source: o.source };
  if (o.useCsr) {
    const g = generateCsr(o.source.service_name);
    keyPem = g.keyPem;
    body.csr = g.csrPem;
  }
  const url = new URL('/fleet/v1/enroll', base).toString();
  let res;
  try {
    res = await request({ method: 'POST', url, agent, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), timeoutMs: o.timeoutMs });
  } catch {
    throw new FleetError('enroll_network');
  } finally {
    agent.destroy();
  }
  if (res.status !== 201 && res.status !== 200) throw new FleetError('enroll_http_' + res.status, res.status);
  const j = parseJsonBody(res) as Record<string, unknown> | undefined;
  if (!j || typeof j !== 'object') throw new FleetError('enroll_bad_response');
  if (!o.useCsr) {
    if (typeof j.client_key !== 'string') throw new FleetError('enroll_no_key');
    keyPem = j.client_key;
  }
  const keys = Array.isArray(j.policy_signing_keys) ? j.policy_signing_keys : [];
  const enrollment: Enrollment = {
    source_id: String(j.source_id ?? ''),
    group: String(j.group ?? ''),
    service_name: String(j.service_name ?? ''),
    client_cert: String(j.client_cert ?? ''),
    ca_chain: String(j.ca_chain ?? ''),
    not_after: typeof j.not_after === 'string' ? j.not_after : undefined,
    policy_signing_keys: keys
      .filter((k: { kid?: unknown; alg?: unknown; public_key?: unknown }) =>
        typeof k?.kid === 'string' && /^[A-Za-z0-9._-]{1,64}$/.test(k.kid) && k.alg === 'Ed25519' &&
        typeof k.public_key === 'string' && /^[A-Za-z0-9_-]{43}$/.test(k.public_key))
      .map((k: SigningKey) => ({ kid: k.kid, alg: 'Ed25519' as const, public_key: k.public_key })),
    intake_url: String(j.intake_url ?? ''),
    fleet_url: String(j.fleet_url ?? ''),
    policy_max_age_s: typeof j.policy_max_age_s === 'number' ? j.policy_max_age_s : 86400,
    heartbeat_interval_s: typeof j.heartbeat_interval_s === 'number' ? j.heartbeat_interval_s : 30,
    policy_poll_interval_s: typeof j.policy_poll_interval_s === 'number' ? j.policy_poll_interval_s : 60,
    enroll_url: o.enrollUrl,
    pin,
  };
  if (!/^src-[0-9A-Za-z]{1,32}$/.test(enrollment.source_id)) throw new FleetError('enroll_bad_source_id');
  if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(enrollment.group)) throw new FleetError('enroll_bad_group');
  if (!/^[a-z0-9][a-z0-9._-]{0,62}$/.test(enrollment.service_name)) throw new FleetError('enroll_bad_service_name');
  if (pemBlocks(enrollment.client_cert, 'CERTIFICATE').length === 0) throw new FleetError('enroll_bad_cert');
  if (!pemBlocks(enrollment.ca_chain, 'CERTIFICATE').some((d) => pinOf(d) === pin)) throw new FleetError('enroll_chain_without_pinned_root');
  if (enrollment.policy_signing_keys.length === 0) throw new FleetError('enroll_no_signing_keys');
  if (!isHttpsUrl(enrollment.intake_url) || !isHttpsUrl(enrollment.fleet_url)) throw new FleetError('enroll_bad_urls');
  return { enrollment, keyPem };
}

/** mTLS agent for the intake and Fleet calls. Trust anchors: the CA chain received over the pinned channel. */
export function mtlsAgent(e: Enrollment, keyPem: string): https.Agent {
  const a = new https.Agent({ cert: e.client_cert, key: keyPem, ca: e.ca_chain, keepAlive: true, maxSockets: 2 });
  internalAgents.add(a);
  return a;
}

export class FleetClient {
  constructor(private e: Enrollment, private agent: https.Agent) {}

  setAgent(agent: https.Agent): void {
    this.agent = agent;
  }

  private url(path: string): string {
    return new URL(path, this.e.fleet_url).toString();
  }

  async heartbeat(body: unknown): Promise<{ status: number; json?: Record<string, unknown> }> {
    const r = await request({ method: 'POST', url: this.url('/fleet/v1/heartbeat'), agent: this.agent, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    return { status: r.status, json: r.status === 200 ? (parseJsonBody(r) as Record<string, unknown>) : undefined };
  }

  async getPolicy(etag?: string): Promise<{ status: number; body?: Buffer; etag?: string }> {
    const headers: Record<string, string> = {};
    if (etag) headers['if-none-match'] = etag;
    const r = await request({ method: 'GET', url: this.url('/fleet/v1/policy'), agent: this.agent, headers, maxResponseBytes: 8 << 20 });
    const et = r.headers.etag;
    return { status: r.status, body: r.status === 200 ? r.body : undefined, etag: typeof et === 'string' ? et : undefined };
  }

  async renew(useCsr: boolean, commonName: string): Promise<{ cert: string; keyPem?: string; notAfter?: string } | null> {
    let keyPem: string | undefined;
    const body: Record<string, unknown> = {};
    if (useCsr) {
      const g = generateCsr(commonName);
      keyPem = g.keyPem;
      body.csr = g.csrPem;
    }
    const r = await request({ method: 'POST', url: this.url('/fleet/v1/renew'), agent: this.agent, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    if (r.status !== 200) return null;
    const j = parseJsonBody(r) as Record<string, unknown> | undefined;
    if (!j || typeof j.client_cert !== 'string') return null;
    if (!useCsr) keyPem = typeof j.client_key === 'string' ? j.client_key : undefined;
    if (!keyPem) return null;
    return { cert: j.client_cert, keyPem, notAfter: typeof j.not_after === 'string' ? j.not_after : undefined };
  }
}
