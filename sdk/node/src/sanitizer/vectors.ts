// Executes one conformance vector (conformance/format.md, "Executing a vector").
// This is the test function every source must expose (sanitizer.md 16).

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { KeyObject } from 'node:crypto';
import { Lex, nodeToPlain, parseJson, type Plain } from './json.js';
import {
  Policy, Refused, checkAcceptance, ed25519PublicKey, parseKeyRing, parseTime, selectKey, validateBodySchema, verifyEnvelope,
} from './policy.js';
import { Sanitizer, type Exchange, type NetError } from './sanitizer.js';

export type VectorResult =
  | { outcome: 'event'; canonical: string }
  | { outcome: 'not_sampled'; sampled_by: string }
  | { outcome: 'refused'; code: string };

type Obj = { [k: string]: Plain };

function decodeBytes(v: Plain | undefined): Buffer {
  if (v === undefined || v === null) return Buffer.alloc(0);
  if (typeof v === 'string') return Buffer.from(v, 'utf8');
  if (typeof v === 'object' && !Array.isArray(v) && !(v instanceof Lex) && typeof v.b64 === 'string') {
    return Buffer.from(v.b64, 'base64');
  }
  throw new Error('bad bytes value');
}

function num(v: Plain | undefined): number | undefined {
  return v instanceof Lex ? Number(v.lex) : undefined;
}

function headers(v: Plain | undefined): Array<[string, Buffer]> {
  if (!Array.isArray(v)) return [];
  return v.map((pair) => {
    const p = pair as Plain[];
    return [p[0] as string, decodeBytes(p[1])];
  });
}

function total(v: Plain | undefined): number | 'unknown' | undefined {
  if (v === 'unknown') return 'unknown';
  return num(v);
}

function bool(v: Plain | undefined): boolean | undefined {
  return typeof v === 'boolean' ? v : undefined;
}

/** Converts the `input` object of a vector into a sanitizer exchange. */
export function vectorExchange(inp: Obj): Exchange {
  const ex: Exchange = {
    dir: inp.dir as 'inbound' | 'outbound',
    method: (inp.method as string) ?? '',
    raw_path: decodeBytes(inp.raw_path),
    raw_query: inp.raw_query === undefined ? undefined : decodeBytes(inp.raw_query),
    req_headers: headers(inp.req_headers),
    req_body: decodeBytes(inp.req_body),
    req_body_total: total(inp.req_body_total),
    req_body_consumed: bool(inp.req_body_consumed),
    req_body_decoded: bool(inp.req_body_decoded),
    resp_headers: headers(inp.resp_headers),
    resp_body: decodeBytes(inp.resp_body),
    resp_body_total: total(inp.resp_body_total),
    resp_body_consumed: bool(inp.resp_body_consumed),
    resp_body_decoded: bool(inp.resp_body_decoded),
  };
  if (typeof inp.service_name === 'string') ex.service_name = inp.service_name;
  if (typeof inp.url_base === 'string') ex.url_base = inp.url_base;
  if (typeof inp.framework_route === 'string') ex.framework_route = inp.framework_route;
  if (typeof inp.framework === 'string') ex.framework = inp.framework;
  if (typeof inp.trace_id === 'string') ex.trace_id = inp.trace_id;
  if (typeof inp.inherited === 'boolean') ex.inherited = inp.inherited;
  const st = num(inp.status);
  if (st !== undefined) ex.status = st;
  if (typeof inp.net_error === 'string') ex.net_error = inp.net_error as NetError;
  return ex;
}

/** Parses a vector file (bytes) with the lexeme-preserving parser. */
export function parseVector(bytes: Uint8Array): Obj {
  return nodeToPlain(parseJson(bytes), false) as Obj;
}

/** Runs one parsed vector. `root` is the conformance/ directory (for policy_ref). */
export function runVector(vec: Obj, root: string): VectorResult {
  const now = typeof vec.now === 'string' ? parseTime(vec.now) : undefined;
  let policy: Policy;
  let sanitizer: Sanitizer;
  try {
    let body: Obj;
    if (vec.policy_envelope !== undefined) {
      const keys = new Map<string, KeyObject>();
      const fk = vec.fleet_keys as Obj | undefined;
      for (const kid of Object.keys(fk ?? {})) {
        const k = ed25519PublicKey(fk![kid] as string);
        if (k) keys.set(kid, k);
      }
      body = verifyEnvelope(vec.policy_envelope, keys, true).body;
    } else if (typeof vec.policy_ref === 'string') {
      body = validateBodySchema(nodeToPlain(parseJson(readFileSync(join(root, vec.policy_ref))), true));
    } else if (vec.policy !== undefined) {
      body = validateBodySchema(vec.policy);
    } else {
      throw new Refused('no_policy');
    }
    policy = new Policy(body);
    checkAcceptance(policy, {
      group: typeof vec.source_group === 'string' ? vec.source_group : '',
      now: now ?? NaN,
      lastIssuedSeq: num(vec.last_issued_seq) ?? 0,
      minIssuedSeq: num(vec.min_issued_seq) ?? 0,
    });
    const ring = parseKeyRing(typeof vec.hmac_key === 'string' ? vec.hmac_key : undefined);
    sanitizer = new Sanitizer(policy, selectKey(ring, policy));
  } catch (e) {
    if (e instanceof Refused) return { outcome: 'refused', code: e.code };
    throw e;
  }
  const r = sanitizer.run(vectorExchange(vec.input as Obj), now);
  if (r.outcome === 'not_sampled') return { outcome: 'not_sampled', sampled_by: r.sampledBy };
  if (r.outcome === 'too_large') return { outcome: 'refused', code: 'event_too_large' };
  return { outcome: 'event', canonical: r.canonical };
}
