// Compiled policy model (policy.md 2), body validation (policy.md 4, schema policy-compiled.v1),
// signed envelope verification (policy.md 3) and HMAC key parsing (sanitizer.md 7.1).

import { createHash, createPublicKey, verify as cryptoVerify, type KeyObject } from 'node:crypto';
import { JsonError, Lex, canonicalNumber, lexemeWithinLimits, nodeToPlain, parseJson, type Plain } from './json.js';
import { cmpUtf8 } from './utf8.js';

export class Refused extends Error {
  constructor(readonly code: 'no_policy' | 'policy_rejected' | 'expired_policy' | 'key_missing' | 'key_mismatch', readonly detail = '') {
    super(code + (detail ? ': ' + detail : ''));
    this.name = 'Refused';
  }
}

export const RESERVED_DOMAINS = new Set(['subject', 'sample', 'sample-trace', 'discovery']);
export const BODY_FORMAT = 'tt.policy.body/v1';
export const ENVELOPE_FORMAT = 'tt.policy.compiled/v1';
export const SIGNATURE_PREFIX = Buffer.from('tt.policy.body/v1\0', 'latin1');
const DAY_MS = 86_400_000;

// ---------------------------------------------------------------------------------
// Model

export interface Bound { canon: string; d: number }
export interface Action {
  action: 'drop' | 'keep' | 'code' | 'graphql' | 'hmac' | 'bucket';
  domain?: string;
  kind?: 'num' | 'time';
  bounds?: Bound[];
  unit?: 'year' | 'month' | 'day' | 'hour';
  /** code only (spec v1.19, sanitizer.md 5.6): the alnum shape. */
  shape?: 'alnum';
}
export type Step = { t: 'name'; name: string } | { t: 'any' } | { t: 'idx' };
export interface BodyRule { path: string; steps: Step[]; names: number; action: Action }
export interface Part {
  query: Map<string, Action>;
  headers: Map<string, Action>;
  cookies: Map<string, Action>;
  path: Map<string, Action>;
  body: BodyRule[];
}
export interface TemplateSeg { lit?: string; param?: string }
export interface Op { key: string; method: string; segs: TemplateSeg[]; literals: number; request?: Part; response?: Part }
export interface Service {
  name: string;
  inbound: boolean;
  internal: boolean;
  base?: { origin: string; segs: string[] };
  request?: Part;
  response?: Part;
  errors?: Part;
  ops: Op[];
  /** Candidate ops by `METHOD/segment-count`, in policy order (built on first use; same result as scanning `ops`). */
  opIndex?: Map<string, Op[]>;
}
export interface Limits { maxBodyBytes: number; maxDepth: number; maxArray: number; maxKeys: number; keepMaxBytes: number }

/** Spec v1.19 (sanitizer.md 22.1): `bodies` of the compiled body; absent = every switch off. */
export interface Bodies { xml: boolean; multipart: boolean; docs: boolean; maxLargeBodyBytes: number; largeArray: number; largeNestedArray: number }

export const BODIES_OFF: Bodies = Object.freeze({ xml: false, multipart: false, docs: false, maxLargeBodyBytes: 0, largeArray: 0, largeNestedArray: 0 });

export const DEFAULT_LIMITS: Limits = { maxBodyBytes: 1048576, maxDepth: 32, maxArray: 32, maxKeys: 256, keepMaxBytes: 64 };

/** `jsonPath` (spec v1.18): dotted path of members inside a header whose value is a JSON object or base64/base64url of one. */
export interface SubjectSpec { from: 'header' | 'cookie'; name: string; jwtClaim?: string; jsonPath?: string }

/** Ready-to-use compiled policy. */
export class Policy {
  readonly policyId: string;
  readonly version: number;
  readonly issuedSeq: number;
  readonly createdAt: number;
  readonly notAfter: number;
  readonly groups: string[];
  readonly kid: string;
  readonly acceptKids: string[];
  readonly epoch: string;
  readonly subject?: SubjectSpec;
  readonly rateBp: number;
  readonly trustBaggage: boolean;
  readonly propagateTo: Set<string>;
  readonly autoWords: boolean;
  readonly autoWordsExpiresAt: number;
  readonly allow: Set<string>;
  readonly hostsAllow: Set<string>;
  /** Spec v1.5 `hosts.discovery`: true = `auto` (default, also when `hosts` is absent), false = `off` (strict mode). */
  readonly hostsAuto: boolean;
  readonly limits: Limits;
  readonly bodies: Bodies;
  /**
   * Bytes of a body a source keeps (sanitizer.md 9.0 and 22.5): max(max_body_bytes,
   * bodies.max_large_body_bytes) + 1. The rest is only counted.
   */
  readonly captureLimit: number;
  readonly discoveryEnabled: boolean;
  readonly discoveryExpiresAt: number;
  readonly global: { request?: Part; response?: Part; errors?: Part };
  readonly services: Service[];
  readonly inbound: Map<string, Service>;
  readonly baseHosts: Set<string>;
  /** SHA-256 of the body bytes, when known (`sha256:<hex>`). */
  hash = '';
  /** Signed body bytes, when known: lets a worker thread rebuild this policy. */
  bodyBytes?: Buffer;

  constructor(readonly body: { [k: string]: Plain }) {
    const b = body;
    this.policyId = str(b.policy_id, '');
    this.version = int(b.version, 0);
    this.issuedSeq = int(b.issued_seq, 0);
    this.createdAt = parseTime(b.created_at);
    this.notAfter = parseTime(b.not_after);
    const targets = obj(b.targets);
    this.groups = arr(targets?.groups).map((g) => str(g, ''));
    const hmac = obj(b.hmac) ?? {};
    this.kid = str(hmac.kid, '');
    this.acceptKids = arr(hmac.accept_kids).map((k) => str(k, ''));
    this.epoch = str(hmac.epoch, '');
    const subj = obj(obj(b.identity)?.subject);
    if (subj) {
      this.subject = { from: str(subj.from, 'header') as 'header' | 'cookie', name: str(subj.name, '') };
      if (typeof subj.jwt_claim === 'string') this.subject.jwtClaim = subj.jwt_claim;
      if (typeof subj.json_path === 'string') this.subject.jsonPath = subj.json_path;
    }
    const sampling = obj(b.sampling) ?? {};
    this.rateBp = int(sampling.rate_bp, 0);
    this.trustBaggage = sampling.trust_baggage === true;
    this.propagateTo = new Set(arr(sampling.propagate_to).map((h) => str(h, '')));
    const seg = obj(b.segments) ?? {};
    this.autoWords = seg.auto_words === true;
    this.autoWordsExpiresAt = parseTime(seg.auto_words_expires_at);
    this.allow = new Set(arr(seg.allow).map((x) => str(x, '')));
    this.hostsAllow = new Set(arr(seg.hosts_allow).map((x) => str(x, '')));
    this.hostsAuto = obj(b.hosts)?.discovery !== 'off';
    const lim = obj(b.limits) ?? {};
    this.limits = {
      maxBodyBytes: int(lim.max_body_bytes, DEFAULT_LIMITS.maxBodyBytes),
      maxDepth: int(lim.max_depth, DEFAULT_LIMITS.maxDepth),
      maxArray: int(lim.max_array, DEFAULT_LIMITS.maxArray),
      maxKeys: int(lim.max_keys, DEFAULT_LIMITS.maxKeys),
      keepMaxBytes: int(lim.keep_max_bytes, DEFAULT_LIMITS.keepMaxBytes),
    };
    const bd = obj(b.bodies);
    this.bodies = bd
      ? {
        xml: bd.xml === true,
        multipart: bd.multipart === true,
        docs: bd.docs === true,
        maxLargeBodyBytes: int(bd.max_large_body_bytes, 0),
        largeArray: int(bd.large_array, 0),
        largeNestedArray: int(bd.large_nested_array, 0),
      }
      : BODIES_OFF;
    this.captureLimit = Math.max(this.limits.maxBodyBytes, this.bodies.maxLargeBodyBytes) + 1;
    const disc = obj(b.discovery);
    this.discoveryEnabled = disc?.enabled === true;
    this.discoveryExpiresAt = parseTime(disc?.expires_at);
    const g = obj(b.global) ?? {};
    this.global = { request: part(g.request), response: part(g.response), errors: part(g.errors) };
    this.services = [];
    this.inbound = new Map();
    this.baseHosts = new Set();
    for (const s of arr(b.services)) {
      const so = obj(s);
      if (!so) continue;
      const m = obj(so.match) ?? {};
      const svc: Service = {
        name: str(so.name, ''),
        inbound: m.inbound === true,
        internal: m.internal === true,
        request: part(so.request),
        response: part(so.response),
        errors: part(so.errors),
        ops: [],
      };
      if (typeof m.base === 'string') {
        svc.base = splitBase(m.base);
        const auth = svc.base.origin.replace(/^[a-z]+:\/\//, '');
        this.baseHosts.add(auth);
        this.baseHosts.add(auth.replace(/:[0-9]+$/, ''));
      }
      for (const o of arr(so.ops)) {
        const oo = obj(o);
        if (!oo) continue;
        const parsed = parseOpKey(str(oo.op, ''));
        if (!parsed) continue;
        svc.ops.push({ ...parsed, request: part(oo.request), response: part(oo.response) });
      }
      this.services.push(svc);
      if (svc.inbound && !this.inbound.has(svc.name)) this.inbound.set(svc.name, svc);
    }
  }

  /** 4.3: auto words active at `now` (ms). */
  autoWordsActive(now: number | undefined): boolean {
    return this.autoWords && now !== undefined && now < this.autoWordsExpiresAt && now < this.createdAt + 7 * DAY_MS;
  }

  /** 15: discovery active at `now` (ms). */
  discoveryActive(now: number | undefined): boolean {
    return this.discoveryEnabled && now !== undefined && now < this.discoveryExpiresAt && now < this.createdAt + 7 * DAY_MS;
  }
}

function obj(v: Plain | undefined): { [k: string]: Plain } | undefined {
  return v !== null && typeof v === 'object' && !Array.isArray(v) && !(v instanceof Lex) ? v : undefined;
}
function arr(v: Plain | undefined): Plain[] {
  return Array.isArray(v) ? v : [];
}
function str(v: Plain | undefined, d: string): string {
  return typeof v === 'string' ? v : d;
}
function int(v: Plain | undefined, d: number): number {
  if (v instanceof Lex) {
    const n = Number(v.lex);
    return Number.isFinite(n) ? n : d;
  }
  return d;
}

const RFC3339 = /^([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?([Zz]|([+-])([0-9]{2}):([0-9]{2}))$/;

/** RFC 3339 timestamp to epoch milliseconds; NaN when absent or malformed. */
export function parseTime(v: Plain | undefined): number {
  if (typeof v !== 'string') return NaN;
  const m = RFC3339.exec(v);
  if (!m) return NaN;
  const [y, mo, d, h, mi, s] = [m[1], m[2], m[3], m[4], m[5], m[6]].map(Number) as [number, number, number, number, number, number];
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 60) return NaN;
  let ms = Date.UTC(y, mo - 1, d, h, mi, s);
  if (m[7]) ms += Math.floor(Number('0' + m[7]) * 1000);
  if (m[9]) {
    const off = (Number(m[10]) * 60 + Number(m[11])) * 60_000;
    ms += m[9] === '+' ? -off : off;
  }
  return ms;
}

function parseAction(v: Plain | undefined): Action | undefined {
  const o = obj(v);
  if (!o) return undefined;
  const a = o.action;
  if (a === 'code' && o.shape === 'alnum') return { action: 'code', shape: 'alnum' };
  if (a === 'drop' || a === 'keep' || a === 'code' || a === 'graphql') return { action: a };
  if (a === 'hmac') return { action: 'hmac', domain: str(o.domain, 'id') };
  if (a === 'bucket' && o.kind === 'num') {
    return {
      action: 'bucket',
      kind: 'num',
      bounds: arr(o.bounds).map((x) => {
        const lex = x instanceof Lex ? x.lex : String(x);
        return { canon: canonicalNumber(lex), d: Number(lex) };
      }),
    };
  }
  if (a === 'bucket' && o.kind === 'time') return { action: 'bucket', kind: 'time', unit: str(o.unit, 'day') as Action['unit'] };
  return { action: 'drop' };
}

function nameMap(v: Plain | undefined): Map<string, Action> {
  const m = new Map<string, Action>();
  const o = obj(v);
  if (!o) return m;
  for (const k of Object.keys(o)) {
    const a = parseAction(o[k]);
    if (a) m.set(k, a);
  }
  return m;
}

/** Parses a tt-path; returns null if it does not follow the grammar. */
export function parseTtPath(p: string): Step[] | null {
  if (p[0] !== '$') return null;
  const steps: Step[] = [];
  let i = 1;
  while (i < p.length) {
    if (p.startsWith('.*', i)) {
      steps.push({ t: 'any' });
      i += 2;
    } else if (p.startsWith('[*]', i)) {
      steps.push({ t: 'idx' });
      i += 3;
    } else if (p.startsWith('.#text', i)) {
      // Spec v1.19 (sanitizer.md 5.0): mixed text of an XML element.
      steps.push({ t: 'name', name: '#text' });
      i += 6;
    } else if (p[i] === '.') {
      // `.name`, or (spec v1.19) `.@name` for an XML attribute.
      const m = /^@?[A-Za-z_][A-Za-z0-9_-]{0,63}/.exec(p.slice(i + 1));
      if (!m) return null;
      steps.push({ t: 'name', name: m[0] });
      i += 1 + m[0].length;
    } else {
      return null;
    }
  }
  return steps;
}

function part(v: Plain | undefined): Part | undefined {
  const o = obj(v);
  if (!o) return undefined;
  const body: BodyRule[] = [];
  for (const r of arr(o.body)) {
    const ro = obj(r);
    if (!ro) continue;
    const path = str(ro.path, '');
    const steps = parseTtPath(path);
    const action = parseAction(ro.action);
    if (!steps || !action) continue;
    body.push({ path, steps, names: steps.filter((s) => s.t === 'name').length, action });
  }
  return { query: nameMap(o.query), headers: nameMap(o.headers), cookies: nameMap(o.cookies), path: nameMap(o.path), body };
}

export function parseOpKey(key: string): Omit<Op, 'request' | 'response'> | null {
  const sp = key.indexOf(' ');
  if (sp <= 0) return null;
  const method = key.slice(0, sp);
  const tmpl = key.slice(sp + 1);
  if (tmpl[0] !== '/') return null;
  const segs: TemplateSeg[] = [];
  let literals = 0;
  for (const s of tmpl.split('/')) {
    if (s === '') continue;
    if (s[0] === '{' && s[s.length - 1] === '}') segs.push({ param: s.slice(1, -1) });
    else {
      segs.push({ lit: s });
      literals++;
    }
  }
  return { key, method, segs, literals };
}

/** Splits a normalized `match.base` into origin and path segments. */
export function splitBase(base: string): { origin: string; segs: string[] } {
  const m = /^([a-z][a-z0-9+.-]*:\/\/[^/]*)(\/.*)?$/.exec(base);
  if (!m) return { origin: base, segs: [] };
  return { origin: m[1]!, segs: (m[2] ?? '').split('/').filter((s) => s !== '') };
}

// ---------------------------------------------------------------------------------
// Body checks

/** Every hmac domain used by any rule of the body. */
function* actionsOf(body: { [k: string]: Plain }): Generator<{ [k: string]: Plain }> {
  const parts = (scope: Plain | undefined, keys: string[]) => {
    const out: { [k: string]: Plain }[] = [];
    const s = obj(scope);
    if (!s) return out;
    for (const k of keys) {
      const p = obj(s[k]);
      if (p) out.push(p);
    }
    return out;
  };
  const all: { [k: string]: Plain }[] = [...parts(body.global, ['request', 'response', 'errors'])];
  for (const svc of arr(body.services)) {
    all.push(...parts(svc, ['request', 'response', 'errors']));
    for (const op of arr(obj(svc)?.ops)) all.push(...parts(op, ['request', 'response']));
  }
  for (const p of all) {
    for (const sec of ['query', 'headers', 'cookies', 'path']) {
      const m = obj(p[sec]);
      if (m) for (const k of Object.keys(m)) {
        const a = obj(m[k]);
        if (a) yield a;
      }
    }
    for (const r of arr(p.body)) {
      const a = obj(obj(r)?.action);
      if (a) yield a;
    }
  }
}

/** Detail prefix of a Refused raised by the v1.3 safety subset; the agent reports it as `policy_unsafe`. */
export const UNSAFE_DETAIL = 'unsafe';

const CREDENTIAL_HEADERS = new Set(['authorization', 'cookie', 'set-cookie', 'proxy-authorization']);

/**
 * Source-side safety subset (hardening.md 2.1, v1.3), applied to every signed body, whatever
 * the validity of tt-core and keyguard:
 *   H1 keep, code (v1.11, any shape) or hmac on authorization, cookie, set-cookie, proxy-authorization (header rules of
 *      request, response and errors; global, services and operations);
 *   H2 keep, code (v1.11) or hmac on a tt-path with any wildcard step (`.*` or `[*]`) in the global body rules;
 *   H3 discovery or auto_words expiring later than created_at + 7 days.
 * Properties of the body: neither the clock nor the group matter.
 */
export function checkUnsafe(b: { [k: string]: Plain }): void {
  const unsafe = (why: string): never => {
    throw new Refused('policy_rejected', UNSAFE_DETAIL + ': ' + why);
  };
  const g = obj(b.global);
  const scopes: Array<{ [k: string]: Plain }> = [];
  const add = (scope: { [k: string]: Plain } | undefined, keys: string[]) => {
    if (!scope) return;
    for (const k of keys) {
      const part = obj(scope[k]);
      if (part) scopes.push(part);
    }
  };
  add(g, ['request', 'response', 'errors']);
  for (const svc of arr(b.services)) {
    add(obj(svc), ['request', 'response', 'errors']);
    for (const op of arr(obj(svc)?.ops)) add(obj(op), ['request', 'response']);
  }
  for (const part of scopes) {
    const headers = obj(part.headers);
    if (!headers) continue;
    for (const name of Object.keys(headers)) {
      const act = obj(headers[name])?.action;
      if (CREDENTIAL_HEADERS.has(name) && (act === 'keep' || act === 'code' || act === 'hmac')) unsafe(act + ' on header ' + name);
    }
  }
  if (g) {
    for (const k of ['request', 'response', 'errors']) {
      for (const r of arr(obj(g[k])?.body)) {
        const rule = obj(r);
        const act = obj(rule?.action)?.action;
        if ((act === 'keep' || act === 'code' || act === 'hmac') && typeof rule?.path === 'string' && (rule.path.includes('.*') || rule.path.includes('[*]'))) {
          unsafe(act + ' on ' + rule.path + ' in a global rule');
        }
      }
    }
  }
  const limit = parseTime(b.created_at) + 7 * DAY_MS;
  const seg = obj(b.segments);
  if (seg?.auto_words === true && parseTime(seg.auto_words_expires_at) > limit) unsafe('auto_words expires beyond created_at + 7 days');
  const d = obj(b.discovery);
  if (d?.enabled === true && parseTime(d.expires_at) > limit) unsafe('discovery expires beyond created_at + 7 days');
}

/** Minimal body checks of the conformance runner (format.md, step 1), plus the v1.3 safety subset. */
export function checkBodyMinimal(body: Plain): { [k: string]: Plain } {
  const b = obj(body);
  if (!b || b.format !== BODY_FORMAT) throw new Refused('policy_rejected', 'body format');
  for (const a of actionsOf(b)) {
    if (a.action === 'hmac' && typeof a.domain === 'string' && RESERVED_DOMAINS.has(a.domain)) {
      throw new Refused('policy_rejected', 'reserved domain');
    }
  }
  checkUnsafe(b);
  return b;
}

// --- full schema validation (schemas/policy-compiled.v1.schema.json#/$defs/body) ---

type V = (v: Plain | undefined, at: string) => void;
class SchemaError extends Error {}
const fail = (at: string, why: string): never => {
  throw new SchemaError(at + ': ' + why);
};
const isObj = (v: Plain | undefined): v is { [k: string]: Plain } => obj(v) !== undefined;
const vStr = (re: RegExp): V => (v, at) => {
  if (typeof v !== 'string' || !re.test(v)) fail(at, 'string');
};
const vInt = (min: number, max = Number.MAX_SAFE_INTEGER): V => (v, at) => {
  if (!(v instanceof Lex) || !/^-?(0|[1-9][0-9]*)$/.test(v.lex)) return fail(at, 'integer');
  const n = Number(v.lex);
  if (n < min || n > max) fail(at, 'range');
};
const vBool: V = (v, at) => {
  if (typeof v !== 'boolean') fail(at, 'boolean');
};
const vTime: V = (v, at) => {
  if (Number.isNaN(parseTime(v))) fail(at, 'date-time');
};
const vConst = (c: string): V => (v, at) => {
  if (v !== c) fail(at, 'const');
};
const vEnum = (vals: string[]): V => (v, at) => {
  if (typeof v !== 'string' || !vals.includes(v)) fail(at, 'enum');
};
const vArr = (item: V, max: number, unique: boolean, min = 0): V => (v, at) => {
  if (!Array.isArray(v) || v.length > max || v.length < min) return fail(at, 'array');
  const seen = new Set<string>();
  v.forEach((x, i) => {
    item(x, at + '[' + i + ']');
    if (unique) {
      const k = JSON.stringify(x instanceof Lex ? x.lex : x);
      if (seen.has(k)) fail(at, 'unique');
      seen.add(k);
    }
  });
};
const vObj = (props: Record<string, V>, required: string[]): V => (v, at) => {
  if (!isObj(v)) return fail(at, 'object');
  for (const k of Object.keys(v)) {
    const p = props[k];
    if (!p) fail(at + '.' + k, 'unexpected');
    else p(v[k], at + '.' + k);
  }
  for (const r of required) if (!(r in v)) fail(at + '.' + r, 'required');
};
const vMap = (name: RegExp, val: V, max: number): V => (v, at) => {
  if (!isObj(v)) return fail(at, 'object');
  const keys = Object.keys(v);
  if (keys.length > max) fail(at, 'maxProperties');
  for (const k of keys) {
    if (!name.test(k)) fail(at + '.' + k, 'name');
    val(v[k], at + '.' + k);
  }
};

const RE_POLICY_ID = /^[a-z0-9][a-z0-9-]{0,62}$/;
const RE_DOMAIN = /^[a-z][a-z0-9_-]{0,31}$/;
const RE_KID = /^[a-z0-9]{1,8}$/;
const RE_HOSTPORT = /^[a-z0-9.-]{1,253}(:[0-9]{1,5})?$/;
const RE_KEYNAME = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const RE_HEADERNAME = /^[a-z0-9!#$%&'*+.^_`|~-]{1,64}$/;
const RE_PARAMNAME = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const RE_TTPATH = /^\$(\.@?[A-Za-z_][A-Za-z0-9_-]{0,63}|\.#text|\.\*|\[\*\]){0,64}$/;
const RE_OPKEY = /^[A-Z]{1,16} \/([A-Za-z0-9._~-]{1,64}|\{[A-Za-z_][A-Za-z0-9_]{0,63}\})?(\/([A-Za-z0-9._~-]{1,64}|\{[A-Za-z_][A-Za-z0-9_]{0,63}\})){0,31}$/;
const RE_BASE = /^https?:\/\/[a-z0-9.-]{1,253}(:[0-9]{1,5})?(\/[A-Za-z0-9._~-]{1,64})*$/;

const vAction: V = (v, at) => {
  if (!isObj(v)) return fail(at, 'action');
  const a = v.action;
  // Spec v1.19 (sanitizer.md 5.6): code may carry the alnum shape; no other action takes a shape.
  if (a === 'code' && 'shape' in v) return vObj({ action: () => {}, shape: vConst('alnum') }, ['action', 'shape'])(v, at);
  if (a === 'drop' || a === 'keep' || a === 'code' || a === 'graphql') return vObj({ action: () => {} }, ['action'])(v, at);
  if (a === 'hmac') {
    vObj({ action: () => {}, domain: vStr(RE_DOMAIN) }, ['action', 'domain'])(v, at);
    if (RESERVED_DOMAINS.has(v.domain as string)) fail(at, 'reserved domain');
    return;
  }
  if (a === 'bucket' && v.kind === 'num') {
    vObj({
      action: () => {},
      kind: () => {},
      bounds: vArr((x, a2) => {
        if (!(x instanceof Lex)) fail(a2, 'number');
        else if (x.lex.length > 64) fail(a2, 'lexeme');
      }, 32, false, 1),
    }, ['action', 'kind', 'bounds'])(v, at);
    const ds = (v.bounds as Lex[]).map((x) => Number(x.lex));
    for (let i = 1; i < ds.length; i++) if (!(ds[i - 1]! < ds[i]!)) fail(at, 'bounds not increasing');
    return;
  }
  if (a === 'bucket' && v.kind === 'time') {
    return vObj({ action: () => {}, kind: () => {}, unit: vStr(/^(year|month|day|hour)$/) }, ['action', 'kind', 'unit'])(v, at);
  }
  fail(at, 'action');
};
const vBodyRules: V = vArr(vObj({ path: vStr(RE_TTPATH), action: vAction }, ['path', 'action']), 1024, false);
const vPart: V = vObj({
  query: vMap(RE_KEYNAME, vAction, 256),
  headers: vMap(RE_HEADERNAME, vAction, 256),
  cookies: vMap(RE_KEYNAME, vAction, 256),
  body: vBodyRules,
}, []);
const vOpPart: V = vObj({
  path: vMap(RE_PARAMNAME, vAction, 32),
  query: vMap(RE_KEYNAME, vAction, 256),
  headers: vMap(RE_HEADERNAME, vAction, 256),
  cookies: vMap(RE_KEYNAME, vAction, 256),
  body: vBodyRules,
}, []);
const vScope: V = vObj({ request: vPart, response: vPart, errors: vPart }, []);
const vMatch: V = (v, at) => {
  if (!isObj(v)) return fail(at, 'match');
  if ('base' in v) return vObj({ base: vStr(RE_BASE) }, ['base'])(v, at);
  vObj({ inbound: vConst(true as unknown as string), internal: vBool }, ['inbound', 'internal'])(v, at);
};
const vService: V = vObj({
  name: vStr(/^[a-z0-9][a-z0-9._-]{0,62}$/),
  match: vMatch,
  request: vPart,
  response: vPart,
  errors: vPart,
  ops: vArr(vObj({ op: vStr(RE_OPKEY), request: vOpPart, response: vOpPart }, ['op']), 4096, false),
}, ['name', 'match', 'ops']);

const RE_JSON_PATH = /^[A-Za-z0-9_-]{1,64}(\.[A-Za-z0-9_-]{1,64}){0,7}$/;

const vBody: V = vObj({
  format: vConst(BODY_FORMAT),
  policy_id: vStr(RE_POLICY_ID),
  version: vInt(1),
  issued_seq: vInt(1),
  created_at: vTime,
  not_after: vTime,
  targets: vObj({ groups: vArr(vStr(RE_POLICY_ID), 256, true, 1) }, ['groups']),
  hmac: vObj({ kid: vStr(RE_KID), accept_kids: vArr(vStr(RE_KID), 4, true), epoch: vStr(/^[A-Za-z0-9._-]{1,32}$/) }, ['kid', 'epoch', 'accept_kids']),
  identity: vObj({
    subject: (v, at) => {
      vObj({
        from: vStr(/^(header|cookie)$/),
        name: vStr(/^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$/),
        jwt_claim: vStr(RE_KEYNAME),
        json_path: vStr(RE_JSON_PATH),
      }, ['from', 'name'])(v, at);
      // Spec v1.18: json_path reads a header only and excludes jwt_claim.
      if (isObj(v) && 'json_path' in v && ('jwt_claim' in v || v.from !== 'header')) fail(at + '.json_path', 'header only, excludes jwt_claim');
    },
  }, []),
  sampling: vObj({ rate_bp: vInt(0, 10000), trust_baggage: vBool, propagate_to: vArr(vStr(RE_HOSTPORT), 256, true) }, ['rate_bp', 'trust_baggage', 'propagate_to']),
  segments: (v, at) => {
    vObj({
      auto_words: vBool,
      auto_words_expires_at: vTime,
      allow: vArr(vStr(/^[A-Za-z0-9._~-]{1,64}$/), 1024, true),
      hosts_allow: vArr(vStr(RE_HOSTPORT), 1024, true),
    }, ['auto_words', 'allow', 'hosts_allow'])(v, at);
    if (isObj(v) && v.auto_words === true && !('auto_words_expires_at' in v)) fail(at, 'auto_words_expires_at required');
  },
  limits: vObj({
    max_body_bytes: vInt(0, 16777216),
    max_depth: vInt(1, 128),
    max_array: vInt(0, 1024),
    max_keys: vInt(1, 4096),
    keep_max_bytes: vInt(0, 1024),
  }, ['max_body_bytes', 'max_depth', 'max_array', 'max_keys', 'keep_max_bytes']),
  // Spec v1.19 (sanitizer.md 22.1): XML/SOAP, multipart, base64 documents, large bodies. Absent = all off.
  bodies: vObj({
    xml: vBool,
    multipart: vBool,
    docs: vBool,
    max_large_body_bytes: vInt(0, 67108864),
    large_array: vInt(0, 1024),
    large_nested_array: vInt(0, 1024),
  }, ['xml', 'multipart', 'docs', 'max_large_body_bytes', 'large_array', 'large_nested_array']),
  discovery: vObj({ enabled: vBool, expires_at: vTime }, ['enabled', 'expires_at']),
  // Spec v1.5 (sanitizer.md 3.5): how hosts without a matching base leave. Absent = auto.
  hosts: vObj({ discovery: vEnum(['auto', 'off']) }, ['discovery']),
  global: vScope,
  services: vArr(vService, 1024, false),
}, ['format', 'policy_id', 'version', 'issued_seq', 'created_at', 'not_after', 'targets', 'hmac', 'sampling', 'segments', 'limits', 'global', 'services']);

/** Full schema validation of a policy body, plus reserved domains, double bounds and the v1.3 safety subset. */
export function validateBodySchema(body: Plain): { [k: string]: Plain } {
  try {
    vBody(body, '$');
  } catch (e) {
    if (e instanceof SchemaError) throw new Refused('policy_rejected', 'schema ' + e.message);
    throw e;
  }
  checkUnsafe(body as { [k: string]: Plain });
  return body as { [k: string]: Plain };
}

// ---------------------------------------------------------------------------------
// Envelope

const B64URL = /^[A-Za-z0-9_-]*$/;

/** Strict base64url without padding; null on any other character or impossible length. */
export function b64urlDecodeStrict(s: string): Buffer | null {
  if (!B64URL.test(s) || s.length % 4 === 1) return null;
  return Buffer.from(s, 'base64url');
}

export function b64urlNoPad(b: Uint8Array): string {
  return Buffer.from(b.buffer, b.byteOffset, b.length).toString('base64url');
}

/** Ed25519 public key object from the raw 32 bytes (base64url, no padding). */
export function ed25519PublicKey(rawB64url: string): KeyObject | null {
  const raw = b64urlDecodeStrict(rawB64url);
  if (!raw || raw.length !== 32) return null;
  try {
    return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: rawB64url }, format: 'jwk' });
  } catch {
    return null;
  }
}

export interface VerifiedPolicy { bodyBytes: Buffer; body: { [k: string]: Plain }; hash: string }

/**
 * Verifies a `tt.policy.compiled/v1` envelope (policy.md 3-4 conditions 1-2). `keys` maps a
 * pinned, non-revoked signature kid to its public key. `strict` applies the full body
 * schema (production); otherwise only the minimal body checks of the conformance runner.
 */
export function verifyEnvelope(env: Plain, keys: Map<string, KeyObject>, strict: boolean): VerifiedPolicy {
  const reject = (why: string): never => {
    throw new Refused('policy_rejected', why);
  };
  const e = obj(env);
  if (!e) return reject('envelope');
  if (strict) {
    const allowed = new Set(['format', 'policy_id', 'version', 'issued_seq', 'hash', 'body_b64', 'signature']);
    for (const k of Object.keys(e)) if (!allowed.has(k)) reject('envelope field');
  }
  if (e.format !== ENVELOPE_FORMAT) reject('envelope format');
  const sig = obj(e.signature);
  if (!sig || sig.alg !== 'Ed25519' || typeof sig.kid !== 'string' || typeof sig.sig !== 'string') return reject('signature');
  const pub = keys.get(sig.kid);
  if (!pub) return reject('unknown kid');
  if (typeof e.body_b64 !== 'string') return reject('body_b64');
  const bodyBytes = b64urlDecodeStrict(e.body_b64);
  if (!bodyBytes || bodyBytes.length === 0) return reject('body_b64');
  const hash = 'sha256:' + createHash('sha256').update(bodyBytes).digest('hex');
  if (e.hash !== hash) reject('hash');
  const sigBytes = b64urlDecodeStrict(sig.sig);
  if (!sigBytes || sigBytes.length !== 64) return reject('signature encoding');
  let ok = false;
  try {
    ok = cryptoVerify(null, Buffer.concat([SIGNATURE_PREFIX, bodyBytes]), pub, sigBytes);
  } catch {
    ok = false;
  }
  if (!ok) reject('signature');
  let plain: Plain;
  try {
    plain = nodeToPlain(parseJson(bodyBytes), true);
  } catch (err) {
    if (err instanceof JsonError) return reject('body json');
    throw err;
  }
  const body = strict ? validateBodySchema(plain) : checkBodyMinimal(plain);
  const same = (a: Plain | undefined, b: Plain | undefined) =>
    a instanceof Lex && b instanceof Lex ? a.lex === b.lex : a === b;
  if (!same(e.policy_id, body.policy_id)) reject('policy_id mismatch');
  if (!same(e.version, body.version)) reject('version mismatch');
  if ((strict || e.issued_seq !== undefined || body.issued_seq !== undefined) && !same(e.issued_seq, body.issued_seq)) reject('issued_seq mismatch');
  if (strict && body.format !== BODY_FORMAT) reject('body format');
  checkBodyMinimal(body);
  return { bodyBytes, body, hash };
}

/**
 * policy.md 4, conditions 3-5: group, expiry, issued_seq ordering. `allowEqualSeq` lets a
 * source re-verify the very policy it already accepted (cache at start-up).
 */
export function checkAcceptance(
  p: Policy,
  o: { group: string; now: number; lastIssuedSeq: number; minIssuedSeq: number; allowEqualSeq?: boolean },
): void {
  if (!p.groups.includes(o.group)) throw new Refused('policy_rejected', 'group');
  if (!(o.now < p.notAfter)) throw new Refused('expired_policy');
  const fresh = o.allowEqualSeq ? p.issuedSeq >= o.lastIssuedSeq : p.issuedSeq > o.lastIssuedSeq;
  if (!fresh) throw new Refused('policy_rejected', 'issued_seq replay');
  if (p.issuedSeq < o.minIssuedSeq) throw new Refused('policy_rejected', 'issued_seq below minimum');
}

// ---------------------------------------------------------------------------------
// HMAC key (7.1)

export interface KeyRing { keys: Map<string, Buffer>; order: string[] }

/** Parses the content of TT_HMAC_KEY / TT_HMAC_KEY_FILE. Throws Refused('key_missing'). */
export function parseKeyRing(text: string | undefined | null): KeyRing {
  if (text === undefined || text === null) throw new Refused('key_missing', 'absent');
  const keys = new Map<string, Buffer>();
  const order: string[] = [];
  for (let line of text.split('\n')) {
    if (line.endsWith('\r')) line = line.slice(0, -1);
    if (line === '') continue;
    const c = line.indexOf(':');
    if (c < 0) throw new Refused('key_missing', 'malformed');
    const kid = line.slice(0, c);
    if (!RE_KID.test(kid)) throw new Refused('key_missing', 'kid');
    const raw = b64urlDecodeStrict(line.slice(c + 1));
    if (!raw || raw.length < 32) throw new Refused('key_missing', 'key bytes');
    if (!keys.has(kid)) {
      keys.set(kid, raw);
      order.push(kid);
    }
  }
  if (keys.size === 0) throw new Refused('key_missing', 'empty');
  return { keys, order };
}

/** 7.1: picks the key for a policy (hmac.kid, then accept_kids in order). */
export function selectKey(ring: KeyRing, policy: Policy): { kid: string; key: Buffer } {
  const k = ring.keys.get(policy.kid);
  if (k) return { kid: policy.kid, key: k };
  for (const kid of policy.acceptKids) {
    const a = ring.keys.get(kid);
    if (a) return { kid, key: a };
  }
  throw new Refused('key_mismatch');
}

export { cmpUtf8, lexemeWithinLimits };
