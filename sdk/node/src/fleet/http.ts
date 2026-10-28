// Minimal HTTPS client used by the exporter and the Fleet client. Requests made here are
// marked internal so the capture hooks never see them.

import https from 'node:https';
import { runInternal } from '../capture/common.js';

export interface HttpResult {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
}

export interface HttpOptions {
  method: 'GET' | 'POST';
  url: string;
  agent: https.Agent;
  headers?: Record<string, string>;
  body?: string | Buffer;
  timeoutMs?: number;
  maxResponseBytes?: number;
}

export function request(o: HttpOptions): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (err: Error | null, res?: HttpResult) => {
      if (settled) return;
      settled = true;
      if (err) reject(err);
      else resolve(res!);
    };
    const u = new URL(o.url);
    if (u.protocol !== 'https:') {
      done(new Error('https_required'));
      return;
    }
    const body = o.body === undefined ? undefined : Buffer.isBuffer(o.body) ? o.body : Buffer.from(o.body, 'utf8');
    const headers: Record<string, string> = { ...(o.headers ?? {}) };
    if (body) headers['content-length'] = String(body.length);
    const max = o.maxResponseBytes ?? 1 << 20;
    const req = runInternal(() =>
      https.request(
        {
          method: o.method,
          hostname: u.hostname.replace(/^\[|\]$/g, ''),
          port: u.port || 443,
          path: u.pathname + u.search,
          agent: o.agent,
          headers,
          servername: /^[0-9.]+$|:/.test(u.hostname) ? undefined : u.hostname,
        },
        (res) => {
          const chunks: Buffer[] = [];
          let n = 0;
          const tooBig = () => {
            // Over the cap: hang up now instead of reading what the peer decides to send.
            const e = Object.assign(new Error('response_too_large'), { code: 'RESPONSE_TOO_LARGE' });
            done(e);
            req.destroy(e);
          };
          const declared = Number(res.headers['content-length']);
          if (Number.isFinite(declared) && declared > max) {
            tooBig();
            return;
          }
          res.on('data', (c: Buffer) => {
            n += c.length;
            if (n > max) {
              chunks.length = 0;
              tooBig();
              return;
            }
            chunks.push(c);
          });
          res.on('end', () => done(null, { status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks) }));
          res.on('error', (e) => done(e));
        },
      ),
    );
    req.setTimeout(o.timeoutMs ?? 10_000, () => req.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })));
    req.on('error', (e) => done(e));
    req.end(body);
  });
}

export function parseJsonBody(r: HttpResult): unknown {
  try {
    return JSON.parse(r.body.toString('utf8'));
  } catch {
    return undefined;
  }
}
