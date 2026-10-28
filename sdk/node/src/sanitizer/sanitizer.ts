// The sanitizer, docs/spec/sanitizer.md v1.1. Input: one normalized exchange (section 1),
// a verified compiled policy, the local HMAC key and the clock. Output: the canonical
// object of section 2, or not_sampled.
//
// Guiding rule: in doubt, drop. Any exception escaping from here must be treated by the
// caller as an internal error (no event, `sanitizer_errors` + 1).

import { createHmac } from 'node:crypto';
import { inflateSync, gunzipSync } from 'node:zlib';
import {
  CNum, INT_LEXEME, JsonError, canonicalNumber, lexemeWithinLimits, parseJson, writeCanonical, writeString,
  type JNode, type OMap, type Out,
} from './json.js';
import {
  AUTO_WORD_RE, CODE_ALNUM_RE, CODE_RE, PATH_TOKEN_RE, RE_DATE, RE_DATETIME, detectFormat, headerOutName, isLiteralName, isPrintableAscii,
  lenClass, strShape,
} from './formats.js';
import {
  InvalidMultipart, InvalidXml, base64Doc, fileToken, mediaParams, parseMultipart, parseXml, soapActionName, xmlNamespaces, xmlValue,
  type XmlValue,
} from './bodies.js';
import { GQL_INTROSPECTION_MAX_ARRAY, gqlIsName, gqlNameSafe, gqlShape } from './graphql.js';
import { hostPattern, parseIpv6 } from './hostpat.js';
import { b64urlDecodeStrict, type Action, type BodyRule, type Op, type Part, type Policy, type Service, type TemplateSeg } from './policy.js';
import {
  asciiLower, asciiUpper, cmpUtf8, decodeUtf8, pctDecode, splitBytes, trimOws, trimOwsStr, utf8, utf8Length,
} from './utf8.js';

export type NetError = 'timeout' | 'reset' | 'refused' | 'dns' | 'tls' | 'other';
export type SampledBy = 'baggage' | 'subject' | 'trace' | 'random' | 'inherited';

/** Normalized exchange (sanitizer.md 1). */
export interface Exchange {
  dir: 'inbound' | 'outbound';
  service_name?: string;
  url_base?: string;
  method: string;
  raw_path: Buffer;
  /** undefined/null = the URL had no "?". */
  raw_query?: Buffer | null;
  /** A-FRAMEWORK-ID: identifier of the 3.4 table; required with framework_route. */
  framework?: string;
  framework_route?: string;
  trace_id?: string;
  inherited?: boolean;
  req_headers: Array<[string, Buffer]>;
  req_body?: Buffer;
  req_body_total?: number | 'unknown';
  req_body_consumed?: boolean;
  req_body_decoded?: boolean;
  status?: number;
  net_error?: NetError;
  resp_headers?: Array<[string, Buffer]>;
  resp_body?: Buffer;
  resp_body_total?: number | 'unknown';
  resp_body_consumed?: boolean;
  resp_body_decoded?: boolean;
}

export interface Decision { sampled: boolean; by: SampledBy }

export type Result =
  | { outcome: 'event'; out: OMap; parts: Map<string, string>; canonical: string; sampledBy: SampledBy }
  | { outcome: 'not_sampled'; sampledBy: SampledBy }
  /** 10.3 step 4: no event; the source counts it in `sanitizer_errors`. */
  | { outcome: 'too_large'; sampledBy: SampledBy };

export const MAX_EVENT_BYTES = 524288;

interface HdrEntry { out: string; values: Buffer[]; origs: Set<string> }
interface Headers { order: string[]; map: Map<string, HdrEntry> }
/** `token`: a ready output token (multipart file part, sanitizer.md 22.3); the value is then not read. */
interface NamedEntry { orig: string | null; out: string; value: Buffer; noEq: boolean; token?: string }
/** Body treatment (sanitizer.md 9.1 and 22.1); null = not parsed. */
type Treatment = 'json' | 'form' | 'xml' | 'multipart' | null;
type Side = 'req' | 'resp';
type Groups = Array<Part | undefined>;

const D_SUBJECT_YES: Decision = Object.freeze({ sampled: true, by: 'subject' });
const D_SUBJECT_NO: Decision = Object.freeze({ sampled: false, by: 'subject' });
const D_RANDOM_YES: Decision = Object.freeze({ sampled: true, by: 'random' });
const D_RANDOM_NO: Decision = Object.freeze({ sampled: false, by: 'random' });
const ZERO = Buffer.from([0]);
const SEP_COMMA = Buffer.from(', ');
const SEP_SEMI = Buffer.from('; ');
const MAX_SEGMENTS = 32;
const MAX_NAMES = 64;
const MAX_DISC = 4096;
const SUBJECT_MAX = 8192;

// ---------------------------------------------------------------------------------
// Header normalization (8.0)

export function normalizeHeaders(list: Array<[string, Buffer]> | undefined): Headers {
  const order: string[] = [];
  const map = new Map<string, HdrEntry>();
  for (const [name, value] of list ?? []) {
    if (name.charCodeAt(0) === 0x3a) continue;
    const lower = asciiLower(name);
    const out = headerOutName(lower);
    let e = map.get(out);
    if (!e) {
      e = { out, values: [], origs: new Set() };
      map.set(out, e);
      order.push(out);
    }
    e.values.push(trimOws(value));
    e.origs.add(lower);
  }
  return { order, map };
}

function joined(e: HdrEntry): Buffer {
  if (e.values.length === 1) return e.values[0]!;
  const parts: Buffer[] = [];
  const sep = e.out === 'cookie' ? SEP_SEMI : SEP_COMMA;
  e.values.forEach((v, i) => {
    if (i > 0) parts.push(sep);
    parts.push(v);
  });
  return Buffer.concat(parts);
}

/** Joined value of one exact lowercase header name (subject, baggage). */
function headerValue(list: Array<[string, Buffer]> | undefined, lower: string): Buffer | null {
  const vals: Buffer[] = [];
  for (const [n, v] of list ?? []) {
    if (n.charCodeAt(0) === 0x3a) continue;
    if (asciiLower(n) === lower) vals.push(trimOws(v));
  }
  if (vals.length === 0) return null;
  if (vals.length === 1) return vals[0]!;
  const sep = lower === 'cookie' ? SEP_SEMI : SEP_COMMA;
  const parts: Buffer[] = [];
  vals.forEach((v, i) => {
    if (i > 0) parts.push(sep);
    parts.push(v);
  });
  return Buffer.concat(parts);
}

const CT_RE = /^[a-z0-9.+-]{1,64}\/[a-z0-9.+-]{1,64}$/;

/** 8.1.5: `ct` from the normalized content-type value; undefined without the header. */
export function contentType(h: Headers): string | undefined {
  const e = h.map.get('content-type');
  if (!e) return undefined;
  let v = joined(e);
  const semi = v.indexOf(0x3b);
  if (semi >= 0) v = v.subarray(0, semi);
  const s = asciiLower(trimOws(v).toString('latin1'));
  return CT_RE.test(s) ? s : 'invalid';
}

function contentEncoding(h: Headers): string | undefined {
  const e = h.map.get('content-encoding');
  if (!e) return undefined;
  return asciiLower(trimOws(joined(e)).toString('latin1'));
}

// ---------------------------------------------------------------------------------
// Path (4.1) and routing (3)

interface Seg { dec: string | null }

export function decomposePath(raw: Buffer): { segs: Seg[]; truncated: boolean } {
  const segs: Seg[] = [];
  let truncated = false;
  for (const s of splitBytes(raw, 0x2f)) {
    if (s.length === 0) continue;
    if (segs.length === MAX_SEGMENTS) {
      truncated = true;
      break;
    }
    segs.push({ dec: decodeUtf8(pctDecode(s, false)) });
  }
  return { segs, truncated };
}

interface UrlBase {
  invalid: boolean;
  origin: string;
  hostport: string;
  /** Normalized host without port (an IPv6 literal keeps its lowercase text, without brackets). */
  host: string;
  /** Normalized port; null when absent or the scheme default. */
  port: string | null;
  /** The 16 bytes of a bracketed IPv6 literal (3.1 point 5, spec v1.5), else null. */
  ip6: Uint8Array | null;
}

/** 3.1 normalization of `url_base`. */
export function normalizeUrlBase(u: string | undefined): UrlBase {
  const bad: UrlBase = { invalid: true, origin: '', hostport: '', host: '', port: null, ip6: null };
  if (typeof u !== 'string') return bad;
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/(.*)$/s.exec(u);
  if (!m) return bad;
  const scheme = asciiLower(m[1]!);
  const rest = m[2]!;
  if (/[@/?#]/.test(rest)) return bad;
  let host: string;
  let portText: string | null = null;
  let ip6: Uint8Array | null = null;
  let shown: string;
  if (rest.startsWith('[')) {
    // IPv6 literal: "]" required, then the end or ":port".
    const end = rest.indexOf(']');
    if (end < 0) return bad;
    host = asciiLower(rest.slice(1, end));
    ip6 = parseIpv6(host);
    if (!ip6) return bad;
    const tail = rest.slice(end + 1);
    if (tail.startsWith(':')) portText = tail.slice(1);
    else if (tail !== '') return bad;
    shown = '[' + host + ']';
  } else {
    host = rest;
    const c = rest.lastIndexOf(':');
    if (c >= 0) {
      host = rest.slice(0, c);
      portText = rest.slice(c + 1);
    }
    host = asciiLower(host);
    if (!/^[a-z0-9.-]{1,253}$/.test(host)) return bad;
    shown = host;
  }
  let port: string | null = null;
  if (portText !== null) {
    if (!/^[0-9]{1,5}$/.test(portText)) return bad;
    const pn = Number(portText);
    if (pn < 1 || pn > 65535) return bad;
    port = String(pn); // A-PORT-ZEROS
    if ((scheme === 'http' && pn === 80) || (scheme === 'https' && pn === 443)) port = null;
  }
  const hostport = port ? shown + ':' + port : shown;
  return { invalid: false, origin: scheme + '://' + hostport, hostport, host, port, ip6 };
}

export const FRAMEWORKS: ReadonlySet<string> = new Set([
  'express', 'koa', 'fastify', 'flask', 'fastapi', 'django', 'spring', 'jaxrs',
  'aspnetcore', 'gin', 'chi', 'nethttp', 'laravel', 'symfony',
]);

const RE_COLON = /^:([A-Za-z_][A-Za-z0-9_]{0,63})$/;
const RE_COLON_REGEX = /^:([A-Za-z_][A-Za-z0-9_]{0,63})\((.*)\)$/s;
const RE_ANGLE = /^<(?:([A-Za-z_][A-Za-z0-9_]*):)?([A-Za-z_][A-Za-z0-9_]{0,63})>$/;
const RE_BRACE = /^\{([A-Za-z_][A-Za-z0-9_]{0,63})\}$/;
const RE_BRACE_CONV = /^\{([A-Za-z_][A-Za-z0-9_]{0,63}):(.+)\}$/s;
const RE_BRACE_SYMFONY = /^\{([A-Za-z_][A-Za-z0-9_]{0,63})<(.+)>\}$/s;
const RE_PNAME = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;

/** One segment of a framework route: the parameter name, or null when it is not a parameter syntax of that framework. */
function frameworkParam(fw: string, s: string): string | null {
  let m: RegExpExecArray | null;
  switch (fw) {
    case 'express':
    case 'koa':
    case 'fastify':
      if ((m = RE_COLON.exec(s))) return m[1]!;
      // ":name(regex)"; a regex holding another ":param" means several parameters.
      if ((m = RE_COLON_REGEX.exec(s)) && !/:[A-Za-z_]/.test(m[2]!.replace(/\\./g, ''))) return m[1]!;
      return null;
    case 'gin':
      return (m = RE_COLON.exec(s)) ? m[1]! : null;
    case 'flask':
    case 'django':
      return (m = RE_ANGLE.exec(s)) && m[1] !== 'path' ? m[2]! : null;
    case 'fastapi':
      if ((m = RE_BRACE.exec(s))) return m[1]!;
      return (m = RE_BRACE_CONV.exec(s)) && m[2] !== 'path' ? m[1]! : null;
    case 'spring':
    case 'chi':
      if ((m = RE_BRACE.exec(s))) return m[1]!;
      return (m = RE_BRACE_CONV.exec(s)) ? m[1]! : null;
    case 'jaxrs': {
      // "{ name : regex }": spaces around the name and the colon are ignored.
      if (s[0] !== '{' || s[s.length - 1] !== '}') return null;
      const inner = s.slice(1, -1);
      const c = inner.indexOf(':');
      const name = (c < 0 ? inner : inner.slice(0, c)).trim();
      if (!RE_PNAME.test(name)) return null;
      if (c >= 0 && inner.slice(c + 1).trim() === '') return null;
      return name;
    }
    case 'aspnetcore':
      if ((m = RE_BRACE.exec(s))) return m[1]!;
      // "{name:constraint[:constraint...]}"; "?" marks an optional parameter, "=" a default.
      if ((m = RE_BRACE_CONV.exec(s)) && !m[2]!.endsWith('?') && !m[2]!.includes('=')) return m[1]!;
      return null;
    case 'nethttp':
    case 'laravel':
      return (m = RE_BRACE.exec(s)) ? m[1]! : null;
    case 'symfony':
      if ((m = RE_BRACE.exec(s))) return m[1]!;
      return (m = RE_BRACE_SYMFONY.exec(s)) ? m[1]! : null;
    default:
      return null;
  }
}

/**
 * 3.4 with A-FRAMEWORK-ID (normative since 1.1.1): normalizes `route` with the table of
 * `framework`. Every segment must be a parameter syntax of that framework or a literal of
 * the operation-key grammar; anything else (every "not normalizable" case) fails.
 */
export function normalizeFrameworkRoute(route: string, framework: string): TemplateSeg[] | null {
  if (!FRAMEWORKS.has(framework)) return null;
  const raw = route.split('/').filter((s) => s !== '');
  const out: TemplateSeg[] = [];
  for (let i = 0; i < raw.length; i++) {
    const s = raw[i]!;
    if (framework === 'nethttp' && s === '{$}' && i === raw.length - 1) continue; // exact-match marker
    const p = frameworkParam(framework, s);
    if (p !== null) out.push({ param: p });
    else if (PATH_TOKEN_RE.test(s)) out.push({ lit: s });
    else return null;
  }
  return out.length > MAX_SEGMENTS ? null : out;
}

// ---------------------------------------------------------------------------------
// Buckets (5.5)

function daysFromCivil(y: number, m: number, d: number): number {
  y -= m <= 2 ? 1 : 0;
  const era = Math.floor(y / 400);
  const yoe = y - era * 400;
  const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146097 + doe - 719468;
}

function civilFromDays(z: number): [number, number, number] {
  z += 719468;
  const era = Math.floor(z / 146097);
  const doe = z - era * 146097;
  const yoe = Math.floor((doe - Math.floor(doe / 1460) + Math.floor(doe / 36524) - Math.floor(doe / 146096)) / 365);
  const y = yoe + era * 400;
  const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100));
  const mp = Math.floor((5 * doy + 2) / 153);
  const d = doy - Math.floor((153 * mp + 2) / 5) + 1;
  const m = mp + (mp < 10 ? 3 : -9);
  return [m <= 2 ? y + 1 : y, m, d];
}

const TIME_PARSE = /^([0-9]{4})-([0-9]{2})-([0-9]{2})(?:[Tt ]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]{1,9})?(?:[Zz]|([+-])([0-9]{2}):([0-9]{2})))?$/;

export function bucketTime(s: string, unit: string): string | null {
  if (!isPrintableAscii(s) || !(RE_DATETIME.test(s) || RE_DATE.test(s))) return null;
  const m = TIME_PARSE.exec(s);
  if (!m) return null;
  const y = Number(m[1]);
  const mo = Number(m[2]);
  const d = Number(m[3]);
  const h = m[4] ? Number(m[4]) : 0;
  const mi = m[5] ? Number(m[5]) : 0;
  const se = m[6] ? Number(m[6]) : 0;
  if (y < 1 || y > 9999 || mo < 1 || mo > 12 || d < 1) return null;
  const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
  const dim = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]!;
  if (d > dim || h > 23 || mi > 59 || se > 59) return null;
  let off = 0;
  if (m[7]) {
    const oh = Number(m[8]);
    const om = Number(m[9]);
    if (oh > 23 || om > 59) return null;
    off = (oh * 60 + om) * (m[7] === '+' ? 1 : -1);
  }
  const total = daysFromCivil(y, mo, d) * 1440 + h * 60 + mi - off;
  const days = Math.floor(total / 1440);
  const hour = Math.floor((total - days * 1440) / 60);
  const [uy, um, ud] = civilFromDays(days);
  if (uy < 1 || uy > 9999) return null;
  const p2 = (n: number) => String(n).padStart(2, '0');
  const ys = String(uy).padStart(4, '0');
  switch (unit) {
    case 'year': return 'time:' + ys;
    case 'month': return 'time:' + ys + '-' + p2(um);
    case 'day': return 'time:' + ys + '-' + p2(um) + '-' + p2(ud);
    case 'hour': return 'time:' + ys + '-' + p2(um) + '-' + p2(ud) + 'T' + p2(hour);
    default: return null;
  }
}

export function bucketNum(lex: string, a: Action): string {
  const b = a.bounds!;
  const v = Number(lex);
  if (v < b[0]!.d) return 'num:<' + b[0]!.canon;
  for (let i = 0; i + 1 < b.length; i++) {
    if (v >= b[i]!.d && v < b[i + 1]!.d) return 'num:' + b[i]!.canon + '-' + b[i + 1]!.canon;
  }
  return 'num:>=' + b[b.length - 1]!.canon;
}

// ---------------------------------------------------------------------------------
// Sanitizer

export interface KeyRef { kid: string; key: Buffer }

const B64_ANY = /^[A-Za-z0-9_+/-]*$/;

/**
 * Standard or URL-safe base64 (never mixed), with or without padding (at most two '=' at the end, then a
 * length that is a multiple of 4). Null on any other character or an impossible length.
 */
function b64Any(s: string): Buffer | null {
  let body = s;
  for (let k = 0; k < 2 && body.endsWith('='); k++) body = body.slice(0, -1);
  if (body === '' || (body.length !== s.length && s.length % 4 !== 0)) return null;
  if (!B64_ANY.test(body) || body.length % 4 === 1) return null;
  const std = body.includes('+') || body.includes('/');
  if (std && (body.includes('-') || body.includes('_'))) return null;
  return Buffer.from(body, std ? 'base64' : 'base64url');
}

/**
 * Spec v1.18 (sanitizer.md 11, step 4 bis): the subject is a member of a header whose value is a JSON object, or
 * base64/base64url of one. No bearer prefix is stripped; the dot always separates members.
 */
function jsonMember(s: string, path: string): Buffer | null {
  let a = 0;
  let b = s.length;
  while (a < b && (s.charCodeAt(a) === 0x20 || s.charCodeAt(a) === 0x09)) a++;
  while (b > a && (s.charCodeAt(b - 1) === 0x20 || s.charCodeAt(b - 1) === 0x09)) b--;
  const t = s.slice(a, b);
  if (t === '') return null;
  const bytes = t.charCodeAt(0) === 0x7b ? utf8(t) : b64Any(t);
  if (bytes === null) return null;
  let v: JNode;
  try {
    v = parseJson(bytes);
  } catch {
    return null;
  }
  for (const name of path.split('.')) {
    if (v.k !== 'o') return null;
    let found: JNode | undefined;
    for (const [k, val] of v.m) if (!k.bad && k.s === name) found = val;
    if (!found) return null;
    v = found;
  }
  if (v.k === 's') return v.s !== '' && !v.bad ? utf8(v.s) : null;
  if (v.k === 'n') return lexemeWithinLimits(v.lex) ? Buffer.from(canonicalNumber(v.lex), 'latin1') : null;
  return null;
}

export class Sanitizer {
  private readonly epochBuf: Buffer;

  constructor(
    readonly policy: Policy,
    readonly key: KeyRef,
    readonly options: { rand?: () => number; rateOverrideBp?: number | null } = {},
  ) {
    this.epochBuf = Buffer.from(policy.epoch, 'latin1');
    this.subjName = policy.subject ? (policy.subject.from === 'header' ? asciiLower(policy.subject.name) : 'cookie') : '';
  }

  mac(domain: string, value: Buffer): Buffer {
    const h = createHmac('sha256', this.key.key);
    h.update(this.epochBuf);
    h.update(ZERO);
    h.update(domain, 'latin1');
    h.update(ZERO);
    h.update(value);
    return h.digest();
  }

  token(domain: string, value: Buffer): string {
    return 'tk1:' + this.key.kid + ':' + this.mac(domain, value).subarray(0, 16).toString('base64url');
  }

  rateBp(): number {
    const o = this.options.rateOverrideBp;
    return typeof o === 'number' ? Math.min(o, this.policy.rateBp) : this.policy.rateBp;
  }

  // --- subject (11) ---------------------------------------------------------------

  subjectValue(reqHeaders: Array<[string, Buffer]> | undefined): Buffer | null {
    const spec = this.policy.subject;
    if (!spec) return null;
    let raw: Buffer | null = null;
    if (spec.from === 'header') {
      raw = headerValue(reqHeaders, asciiLower(spec.name));
    } else {
      const cookie = headerValue(reqHeaders, 'cookie');
      if (cookie) {
        for (const p of splitBytes(cookie, 0x3b)) {
          const piece = trimOws(p);
          const eq = piece.indexOf(0x3d);
          if (eq < 0) continue;
          if (decodeUtf8(piece.subarray(0, eq)) === spec.name) {
            raw = piece.subarray(eq + 1);
            break;
          }
        }
      }
    }
    if (raw === null || raw.length === 0 || raw.length > SUBJECT_MAX) return null;
    let s = decodeUtf8(raw);
    if (s === null || s === '') return null;
    if (spec.from === 'header' && spec.jsonPath !== undefined) return jsonMember(s, spec.jsonPath);
    if (spec.from === 'header') {
      const m = /^bearer[ \t]+/i.exec(s);
      if (m) {
        s = s.slice(m[0].length);
        if (s === '') return null;
      }
    }
    if (spec.jwtClaim === undefined) return utf8(s);
    const parts = s.split('.');
    if (parts.length !== 3) return null;
    const payload = parts[1]!.replace(/={1,2}$/, '');
    const bytes = b64urlDecodeStrict(payload);
    if (bytes === null) return null;
    let doc: JNode;
    try {
      doc = parseJson(bytes);
    } catch {
      return null;
    }
    if (doc.k !== 'o') return null;
    let v: JNode | undefined;
    for (const [k, val] of doc.m) if (!k.bad && k.s === spec.jwtClaim) v = val;
    if (!v) return null;
    if (v.k === 's') return v.s !== '' && !v.bad ? utf8(v.s) : null;
    if (v.k === 'n') return lexemeWithinLimits(v.lex) ? Buffer.from(canonicalNumber(v.lex), 'latin1') : null;
    return null;
  }

  // --- sampling (12) --------------------------------------------------------------

  private hashSample(domain: string, value: Buffer): boolean {
    return this.mac(domain, value).readUInt32BE(0) % 10000 < this.rateBp();
  }

  private randomSample(): boolean {
    const rate = this.rateBp();
    if (rate <= 0) return false;
    if (rate >= 10000) return true;
    return Math.floor((this.options.rand ?? Math.random)() * 10000) < rate;
  }

  private readonly subjName: string;
  /** Subject header value (as received) -> 1 sampled, 2 not sampled, 3 no usable subject. Per policy and key, bounded. */
  private readonly subjCache = new Map<string, number>();

  /**
   * Inbound decision straight from node's rawHeaders (flat latin1 strings) and the
   * traceparent trace id, with no per-request allocation on the common paths. It returns the
   * same decision as `decide()` on the same headers, or null when it cannot answer fast
   * (baggage trusted, repeated subject header): the caller then uses `decide()`.
   * The subject answer is remembered per header value: the HMAC and the parsing run once per
   * distinct value (a user's cookie or token repeats on every request).
   */
  decideRaw(service: string, raw: readonly string[], traceId: string | undefined): Decision | null {
    const p = this.policy;
    if (p.trustBaggage && p.inbound.get(service)?.internal) return null;
    const spec = p.subject;
    if (spec) {
      const want = this.subjName;
      let val: string | undefined;
      for (let i = 0; i + 1 < raw.length; i += 2) {
        const n = raw[i]!;
        if (n.length === want.length && (n === want || asciiLower(n) === want)) {
          if (val !== undefined) return null;
          val = raw[i + 1]!;
        }
      }
      if (val !== undefined) {
        let c = this.subjCache.get(val);
        if (c === undefined) {
          const subj = this.subjectValue([[want, Buffer.from(val, 'latin1')]]);
          c = subj ? (this.hashSample('sample', subj) ? 1 : 2) : 3;
          if (val.length <= 2048) {
            if (this.subjCache.size >= 4096) this.subjCache.clear();
            this.subjCache.set(val, c);
          }
        }
        if (c === 1) return D_SUBJECT_YES;
        if (c === 2) return D_SUBJECT_NO;
      }
    }
    if (traceId) return { sampled: this.hashSample('sample-trace', Buffer.from(asciiLower(traceId), 'latin1')), by: 'trace' };
    const rate = this.rateBp();
    if (rate <= 0) return D_RANDOM_NO;
    if (rate >= 10000) return D_RANDOM_YES;
    return Math.floor((this.options.rand ?? Math.random)() * 10000) < rate ? D_RANDOM_YES : D_RANDOM_NO;
  }

  /** Sampling decision for an exchange (needs only the request line and headers). */
  decide(ex: Pick<Exchange, 'dir' | 'service_name' | 'req_headers' | 'trace_id' | 'inherited'>, subject?: Buffer | null): Decision {
    if (ex.dir === 'inbound') {
      const svc = ex.service_name !== undefined ? this.policy.inbound.get(ex.service_name) : undefined;
      if (this.policy.trustBaggage && svc?.internal) {
        const bag = headerValue(ex.req_headers, 'baggage');
        const s = bag ? decodeUtf8(bag) : null;
        if (s !== null) {
          for (const member of s.split(',')) {
            const kv = trimOwsStr(member.split(';', 1)[0]!);
            const eq = kv.indexOf('=');
            if (eq < 0) continue;
            const k = trimOwsStr(kv.slice(0, eq));
            const v = trimOwsStr(kv.slice(eq + 1));
            if (k === 'tt.s' && (v === '0' || v === '1')) return { sampled: v === '1', by: 'baggage' };
          }
        }
      }
      const subj = subject === undefined ? this.subjectValue(ex.req_headers) : subject;
      if (subj) return { sampled: this.hashSample('sample', subj), by: 'subject' };
    } else if (typeof ex.inherited === 'boolean') {
      return { sampled: ex.inherited, by: 'inherited' };
    }
    if (ex.trace_id) return { sampled: this.hashSample('sample-trace', Buffer.from(asciiLower(ex.trace_id), 'latin1')), by: 'trace' };
    return { sampled: this.randomSample(), by: 'random' };
  }

  // --- whole exchange -------------------------------------------------------------

  run(ex: Exchange, now: number | undefined, decision?: Decision): Result {
    const subject = this.subjectValue(ex.req_headers);
    const d = decision ?? this.decide(ex, subject);
    if (!d.sampled) return { outcome: 'not_sampled', sampledBy: d.by };
    const run = new Run(this, ex, now);
    const out = run.build(d.by, subject);
    // Each top-level member is serialized once; the source reuses these parts to assemble
    // the full event without serializing the tree again.
    const parts = new Map<string, string>();
    for (const [k, v] of out) parts.set(k, writeCanonical(v));
    let canonical = composeCanonical(parts);
    // 10.3, measured on the sanitizer output (A-EVENT-SIZE-BASE). Canonical output is ASCII.
    if (canonical.length > MAX_EVENT_BYTES) {
      const steps: Array<() => string | null> = [
        () => (replaceBody(out.get('req')) ? 'req' : null),
        () => (replaceBody(out.get('resp')) ? 'resp' : null),
        () => (out.delete('disc') ? 'disc' : null),
      ];
      for (const step of steps) {
        const k = step();
        if (k === null) continue;
        if (out.has(k)) parts.set(k, writeCanonical(out.get(k)!));
        else parts.delete(k);
        canonical = composeCanonical(parts);
        if (canonical.length <= MAX_EVENT_BYTES) break;
      }
      if (canonical.length > MAX_EVENT_BYTES) return { outcome: 'too_large', sampledBy: d.by };
    }
    return { outcome: 'event', out, parts, canonical, sampledBy: d.by };
  }
}

/** Ops of a service with this method and segment count, in policy order. */
function candidateOps(svc: Service, method: string, nsegs: number): Op[] {
  let idx = svc.opIndex;
  if (!idx) {
    idx = new Map();
    for (const op of svc.ops) {
      const k = op.method + '/' + op.segs.length;
      const l = idx.get(k);
      if (l) l.push(op);
      else idx.set(k, [op]);
    }
    svc.opIndex = idx;
  }
  return idx.get(method + '/' + nsegs) ?? NO_OPS;
}

const NO_OPS: Op[] = [];

/** Per-exchange state. */
class Run {
  private readonly p: Policy;
  private readonly disc: Map<string, Buffer> | null;
  private readonly autoWords: boolean;
  private svc: Service | undefined;
  private op: Op | undefined;
  /** limits.max_array, raised for the response body when the introspection gate is open (5.7.2). */
  private maxArray: number;
  // GraphQL (5.7): resp is set while the response is sanitized; gqlSeen and gqlNonIntro
  // record the request values with a graphql rule.
  private resp = false;
  private gqlSeen = false;
  private gqlNonIntro = false;

  constructor(private readonly s: Sanitizer, private readonly ex: Exchange, private readonly now: number | undefined) {
    this.p = s.policy;
    this.maxArray = this.p.limits.maxArray;
    this.disc = this.p.discoveryActive(now) ? new Map() : null;
    this.autoWords = this.p.autoWordsActive(now);
  }

  build(by: SampledBy, subject: Buffer | null): OMap {
    const ex = this.ex;
    const p = this.p;
    let method = asciiUpper(ex.method ?? '');
    if (!/^[A-Z]{1,16}$/.test(method)) method = 'OTHER';
    const { segs, truncated } = decomposePath(ex.raw_path ?? Buffer.alloc(0));

    // 3.1 service
    let service: string;
    let baseCount = 0;
    if (ex.dir === 'inbound') {
      service = ex.service_name ?? '';
      this.svc = p.inbound.get(service);
    } else {
      const ub = normalizeUrlBase(ex.url_base);
      let best: Service | undefined;
      if (!ub.invalid) {
        for (const svc of p.services) {
          if (!svc.base || svc.base.origin !== ub.origin) continue;
          const bs = svc.base.segs;
          if (bs.length > segs.length) continue;
          let ok = true;
          for (let i = 0; i < bs.length; i++) if (segs[i]!.dec !== bs[i]) ok = false;
          if (ok && (!best || bs.length > best.base!.segs.length)) best = svc;
        }
      }
      if (best) {
        this.svc = best;
        service = best.name;
        baseCount = best.base!.segs.length;
      } else if (ub.invalid) service = 'host:invalid';
      else if (!ub.ip6 && p.hostsAllow.has(ub.hostport)) service = 'host:' + ub.hostport;
      else if (p.hostsAuto || this.disc) {
        // v1.5: the host leaves as a pattern, never in clear (3.5). An empty label is invalid.
        const pat = hostPattern(ub.host, ub.port, ub.ip6);
        service = pat === null ? 'host:invalid' : 'host:' + pat;
      } else service = 'host:unlisted';
    }

    // 3.3 template
    const opSegs = segs.slice(baseCount);
    let routeSource: 'framework' | 'policy' | 'raw' = 'raw';
    if (this.svc && method !== 'OTHER' && !truncated) {
      if (ex.dir === 'inbound' && typeof ex.framework_route === 'string' && typeof ex.framework === 'string') {
        const fr = normalizeFrameworkRoute(ex.framework_route, ex.framework);
        if (fr && fr.length === opSegs.length) {
          for (const op of this.svc.ops) {
            if (op.method !== method || op.segs.length !== fr.length) continue;
            if (op.segs.every((t, i) => (t.lit !== undefined ? fr[i]!.lit === t.lit : fr[i]!.param !== undefined))) {
              this.op = op;
              routeSource = 'framework';
              break;
            }
          }
        }
      }
      if (!this.op) {
        let best: Op | undefined;
        for (const op of candidateOps(this.svc, method, opSegs.length)) {
          let ok = true;
          for (let i = 0; i < op.segs.length && ok; i++) {
            const t = op.segs[i]!;
            const sd = opSegs[i]!.dec;
            ok = t.lit !== undefined ? sd === t.lit : sd !== null;
          }
          if (!ok) continue;
          if (!best || op.literals > best.literals || (op.literals === best.literals && cmpUtf8(op.key, best.key) < 0)) best = op;
        }
        if (best) {
          this.op = best;
          routeSource = 'policy';
        }
      }
    }

    // 4.2 path
    const outSegs: string[] = [];
    for (let i = 0; i < segs.length; i++) {
      const dec = segs[i]!.dec;
      if (dec === null) {
        outSegs.push('{drop:bytes}');
        continue;
      }
      if (i < baseCount) {
        outSegs.push(dec);
        continue;
      }
      if (this.op) {
        const t = this.op.segs[i - baseCount]!;
        if (t.lit !== undefined) {
          outSegs.push(t.lit);
          continue;
        }
        const action = this.op.request?.path.get(t.param!);
        outSegs.push('{' + this.strAction(dec, action, true, 'req.path.' + i) + '}');
        continue;
      }
      if (p.allow.has(dec) || (this.autoWords && AUTO_WORD_RE.test(dec) && utf8Length(dec) <= 40)) {
        outSegs.push(dec);
        continue;
      }
      outSegs.push('{' + this.strAction(dec, undefined, true, 'req.path.' + i) + '}');
    }
    if (truncated) outSegs.push('{trunc}');
    const path = '/' + outSegs.join('/');
    const op = this.op ? this.op.key : method + ' /' + outSegs.slice(baseCount).join('/');

    const out: OMap = new Map();
    out.set('service', service);
    out.set('op', op);
    out.set('route_source', routeSource);
    out.set('sampled_by', by);

    // request
    const req: OMap = new Map();
    req.set('path', path);
    const reqGroups = this.groups('req', undefined);
    if (ex.raw_query !== undefined && ex.raw_query !== null) {
      const q = this.namedMap(parseUrlencoded(ex.raw_query), reqGroups, 'query', 'req.query');
      if (q.size > 0) req.set('query', q);
    }
    const rh = normalizeHeaders(ex.req_headers);
    this.side(req, 'req', rh, reqGroups, ex.req_body, ex.req_body_total, ex.req_body_consumed, ex.req_body_decoded);
    out.set('req', req);

    // Response: ignored with net_error, even if the source passed parts.
    this.resp = true;
    if (ex.net_error === undefined || ex.net_error === null) {
      const resp: OMap = new Map();
      const respGroups = this.groups('resp', ex.status);
      const sh = normalizeHeaders(ex.resp_headers);
      this.side(resp, 'resp', sh, respGroups, ex.resp_body, ex.resp_body_total, ex.resp_body_consumed, ex.resp_body_decoded);
      out.set('resp', resp);
    }
    if (subject) out.set('subject', this.s.token('subject', subject));
    if (this.disc && this.disc.size > 0) {
      const d: OMap = new Map();
      const keys = [...this.disc.keys()].sort(cmpUtf8).slice(0, MAX_DISC);
      for (const k of keys) {
        const mac = this.s.mac('discovery', Buffer.concat([Buffer.from(k, 'utf8'), Buffer.from([0]), this.disc.get(k)!]));
        d.set(k, 'tkd:' + mac.subarray(0, 4).toString('base64url'));
      }
      out.set('disc', d);
    }
    return out;
  }

  private groups(side: Side, status: number | undefined): Groups {
    const key = side === 'req' ? 'request' : 'response';
    const err = side === 'resp' && typeof status === 'number' && status >= 400;
    return [
      this.op?.[key],
      err ? this.svc?.errors : undefined,
      err ? this.p.global.errors : undefined,
      this.svc?.[key],
      this.p.global[key],
    ];
  }

  private side(
    dst: OMap, side: Side, h: Headers, groups: Groups,
    body: Buffer | undefined, total: number | 'unknown' | undefined, consumed: boolean | undefined, decoded: boolean | undefined,
  ): void {
    // 8.1 headers (cookie / set-cookie never appear)
    const hdrEntries: NamedEntry[] = [];
    for (const name of h.order) {
      if (name === 'cookie' || name === 'set-cookie') continue;
      const e = h.map.get(name)!;
      hdrEntries.push({ orig: e.origs.size === 1 ? [...e.origs][0]! : null, out: name, value: joined(e), noEq: false });
    }
    const hm = this.namedMap(hdrEntries, groups, 'headers', side + '.headers');
    if (hm.size > 0) dst.set('headers', hm);

    // 8.2 cookies
    const ck: NamedEntry[] = [];
    if (side === 'req') {
      const e = h.map.get('cookie');
      if (e) {
        for (const p of splitBytes(joined(e), 0x3b)) cookiePart(trimOws(p), ck);
      }
    } else {
      const e = h.map.get('set-cookie');
      if (e) {
        for (const v of e.values) {
          const semi = v.indexOf(0x3b);
          cookiePart(trimOws(semi >= 0 ? v.subarray(0, semi) : v), ck);
        }
      }
    }
    const cm = this.namedMap(ck, groups, 'cookies', side + '.cookies');
    if (cm.size > 0) dst.set('cookies', cm);

    const ct = contentType(h);
    if (ct !== undefined) dst.set('ct', ct);
    const kind = this.treatment(ct);
    if (side === 'req' && kind === 'xml') {
      // 22.2 point 11: the SOAP operation, also without a body.
      const sa = h.map.get('soapaction');
      let raw: string | null;
      if (sa === undefined) {
        const ctv = h.map.get('content-type');
        raw = mediaParams(ctv ? joined(ctv) : null).get('action') ?? null;
      } else {
        raw = decodeUtf8(joined(sa)) ?? '{*}';
      }
      if (raw !== null) {
        const name = raw === '{*}' ? '{*}' : soapActionName(raw, isLiteralName);
        if (name !== null) dst.set('soap_action', name);
      }
    }
    // 5.7.2: with the introspection gate open the response body keeps arrays up to 4096.
    const raise = side === 'resp' && this.gqlGate() && this.maxArray < GQL_INTROSPECTION_MAX_ARRAY;
    if (raise) this.maxArray = GQL_INTROSPECTION_MAX_ARRAY;
    try {
      this.body(dst, side, h, kind, groups, body ?? Buffer.alloc(0), total, consumed, decoded);
    } finally {
      if (raise) this.maxArray = this.p.limits.maxArray;
    }
    // 22.1: fmt whenever a body leaves under the XML or multipart treatment.
    if ((kind === 'xml' || kind === 'multipart') && dst.has('body') && !dst.has('fmt')) dst.set('fmt', kind);
  }

  /** 9.1 and 22.1: how a body with this `ct` is read. */
  private treatment(ct: string | undefined): Treatment {
    if (ct === undefined) return null;
    if (ct === 'application/json' || ct.endsWith('+json')) return 'json';
    if (ct === 'application/x-www-form-urlencoded') return 'form';
    const b = this.p.bodies;
    if (b.xml && (ct === 'application/xml' || ct === 'text/xml' || ct.endsWith('+xml'))) return 'xml';
    if (b.multipart && ct === 'multipart/form-data') return 'multipart';
    return null;
  }

  // --- body (9) -------------------------------------------------------------------

  private body(
    dst: OMap, side: Side, h: Headers, kind: Treatment, groups: Groups,
    data: Buffer, total: number | 'unknown' | undefined, consumed: boolean | undefined, decoded: boolean | undefined,
  ): void {
    const max = this.p.limits.maxBodyBytes;
    const largeMax = this.p.bodies.maxLargeBodyBytes;
    let tot = total === undefined ? data.length : total;
    if (consumed === false || tot === 'unknown') {
      dst.set('body', 'trunc:size');
      dst.set('size', 'lmax');
      return;
    }
    if (tot === 0) {
      dst.set('size', 'l8');
      return;
    }
    const ce = contentEncoding(h);
    if (ce !== undefined && ce !== 'identity') {
      if (ce !== 'gzip' && ce !== 'x-gzip' && ce !== 'deflate') {
        dst.set('body', 'drop:bytes');
        return;
      }
      if (decoded !== true) {
        // 22.5: the decoding cap includes the large-body limit.
        const r = decodeBody(data, ce === 'deflate', Math.max(max, largeMax) + 1);
        if (r === 'cap') {
          dst.set('body', 'trunc:size');
          dst.set('size', 'lmax');
          return;
        }
        if (r === null) {
          dst.set('body', 'drop:bytes');
          return;
        }
        data = r;
        tot = data.length;
      }
    }
    let large = false;
    if (tot > max) {
      if (kind === null || tot > largeMax) {
        dst.set('body', 'trunc:size');
        dst.set('size', 'lmax');
        return;
      }
      large = true; // 22.5
    }
    dst.set('size', lenClass(tot));
    if (kind !== null && data.length < tot) {
      // 9.1: only a prefix of a parsed body was kept; it cannot be analysed.
      dst.set('body', 'trunc:size');
      return;
    }
    const dpath = this.disc ? side + '.body' : null;
    switch (kind) {
      case 'json': {
        let root: JNode;
        try {
          root = parseJson(data);
        } catch (e) {
          if (e instanceof JsonError) {
            dst.set('body', 'trunc:invalid-json');
            return;
          }
          throw e;
        }
        dst.set('body', this.walk(root, 0, groups.map((g) => g?.body ?? []), dpath, false, large, 0));
        return;
      }
      case 'form':
        dst.set('body', this.namedMap(parseUrlencoded(data), groups, 'form', side + '.body'));
        return;
      case 'xml': {
        let root;
        try {
          root = parseXml(data);
        } catch (e) {
          if (e instanceof InvalidXml) {
            dst.set('body', 'trunc:invalid-xml');
            return;
          }
          throw e;
        }
        const { entries, fmt } = xmlNamespaces(root, isLiteralName, this.p.limits.maxDepth);
        dst.set('fmt', fmt);
        const tree: JNode = { k: 'o', m: [[jstr(root.local), xmlToNode(xmlValue(root))]] };
        dst.set('body', this.walk(tree, 0, groups.map((g) => g?.body ?? []), dpath, true, large, 0));
        if (entries.length > 0) {
          const ns: OMap = new Map();
          for (const [k, v] of entries.slice(0, MAX_NAMES)) ns.set(k, v);
          if (entries.length > MAX_NAMES) ns.set('{trunc}', 'trunc:keys:' + lenClass(entries.length));
          dst.set('xmlns', ns);
        }
        return;
      }
      case 'multipart': {
        const ctv = h.map.get('content-type');
        const boundary = mediaParams(ctv ? joined(ctv) : null).get('boundary');
        let parts;
        try {
          parts = parseMultipart(data, boundary);
        } catch (e) {
          if (e instanceof InvalidMultipart) {
            dst.set('body', 'trunc:invalid-multipart');
            return;
          }
          throw e;
        }
        const entries: NamedEntry[] = parts.map((p) => {
          const e: NamedEntry = { orig: p.name, out: isLiteralName(p.name) ? p.name : '{*}', value: p.content, noEq: false };
          if (p.isFile) e.token = fileToken(p.content, p.ct);
          return e;
        });
        dst.set('body', this.namedMap(entries, groups, 'form', side + '.body'));
        return;
      }
      default: {
        if (contentType(h) === 'application/graphql' && data.length === tot) {
          // 9.1 (spec v1.14): with a winning graphql rule for $ the body is one string leaf.
          const a = rootRule(groups);
          if (a?.action === 'graphql') {
            const s = decodeUtf8(data);
            if (s === null) {
              this.gqlUnusable(a);
              dst.set('body', 'drop:str:invalid');
            } else {
              dst.set('body', this.strAction(s, a, false, null));
            }
            return;
          }
        }
        dst.set('body', 'drop:bytes:' + lenClass(tot));
      }
    }
  }

  /**
   * `xml`: keys follow 22.2 point 8; `large`: 22.5 array caps, chosen by `arrLevel` (the
   * number of arrays among the ancestors).
   */
  private walk(node: JNode, pos: number, alive: BodyRule[][], dpath: string | null, xml: boolean, large: boolean, arrLevel: number): Out {
    const lim = this.p.limits;
    const maxArray = this.maxArray;
    if (node.k === 'o' || node.k === 'a') {
      if (pos + 1 > lim.maxDepth) return 'trunc:depth';
      // 5.0 explicit drop on a container
      for (let g = 0; g < alive.length; g++) {
        if (!alive[g]!.some((r) => r.steps.length === pos && r.action.action === 'drop')) continue;
        let reach = false;
        for (let h = 0; h <= g && !reach; h++) reach = alive[h]!.some((r) => r.steps.length > pos);
        if (!reach) {
          if (node.k === 'a') return 'drop:arr:' + lenClass(node.a.length);
          return 'drop:obj:' + lenClass(dedupe(node.m).length);
        }
        break;
      }
      const anyAlive = alive.some((rs) => rs.length > 0);
      if (node.k === 'a') {
        const res: Out[] = [];
        const cap = large ? (arrLevel === 0 ? this.p.bodies.largeArray : this.p.bodies.largeNestedArray) : maxArray;
        const n = Math.min(node.a.length, cap);
        const child = anyAlive
          ? alive.map((rs) => rs.filter((r) => r.steps.length > pos && r.steps[pos]!.t === 'idx'))
          : alive;
        for (let i = 0; i < n; i++) res.push(this.walk(node.a[i]!, pos + 1, child, dpath === null ? null : dpath + '[*]', xml, large, arrLevel + 1));
        if (node.a.length > cap) res.push('trunc:n:' + lenClass(node.a.length));
        return res;
      }
      const members = dedupe(node.m);
      const res: OMap = new Map();
      const dyn: Out[] = [];
      const kept = members.length > lim.maxKeys ? members.slice(0, lim.maxKeys) : members;
      for (const [k, v] of kept) {
        const literal = xml ? xmlKeyIsLiteral(k.s) : !k.bad && isLiteralName(k.s);
        const child = anyAlive
          ? alive.map((rs) => rs.filter((r) => {
            if (r.steps.length <= pos) return false;
            const st = r.steps[pos]!;
            return st.t === 'any' || (st.t === 'name' && !k.bad && st.name === k.s);
          }))
          : alive;
        const o = this.walk(v, pos + 1, child, dpath === null ? null : dpath + (literal ? '.' + k.s : '.*'), xml, large, arrLevel);
        if (literal) res.set(k.s, o);
        else dyn.push(o);
      }
      if (dyn.length > 0) {
        const keyed = dyn.map((o) => [writeCanonical(o), o] as const);
        keyed.sort((a, b) => cmpUtf8(a[0], b[0]));
        res.set('{*}', keyed.map((x) => x[1]));
      }
      if (members.length > lim.maxKeys) res.set('{trunc}', 'trunc:keys:' + lenClass(members.length));
      return res;
    }
    // leaf
    for (const rs of alive) {
      let best: BodyRule | undefined;
      for (const r of rs) {
        if (r.steps.length !== pos) continue;
        if (!best || r.names > best.names || (r.names === best.names && cmpUtf8(r.path, best.path) < 0)) best = r;
      }
      if (best) return this.leaf(node, best.action, null);
    }
    return this.leaf(node, undefined, dpath);
  }

  private leaf(node: JNode, a: Action | undefined, dpath: string | null): Out {
    // 5.7: a number, boolean, null or invalid string under graphql leaves as its form; in
    // the request it closes the introspection gate.
    if (a?.action === 'graphql' && (node.k !== 's' || node.bad)) this.gqlUnusable(a);
    switch (node.k) {
      case 'z':
        if (a?.action === 'keep') return null;
        if (!a && dpath !== null) this.discAdd(dpath, Buffer.from('null'));
        return 'drop:null';
      case 'b':
        if (a?.action === 'keep') return node.v;
        if (!a && dpath !== null) this.discAdd(dpath, Buffer.from(node.v ? 'true' : 'false'));
        return 'drop:bool';
      case 'n': {
        const within = lexemeWithinLimits(node.lex);
        const shape = INT_LEXEME.test(node.lex) ? 'drop:int' : 'drop:dec';
        if (!a) {
          if (dpath !== null && within) this.discAdd(dpath, Buffer.from(canonicalNumber(node.lex), 'latin1'));
          return shape;
        }
        if (!within) return shape;
        if (a.action === 'keep') return new CNum(canonicalNumber(node.lex));
        if (a.action === 'hmac') return this.s.token(a.domain ?? 'id', Buffer.from(canonicalNumber(node.lex), 'latin1'));
        if (a.action === 'bucket' && a.kind === 'num') return bucketNum(node.lex, a);
        return shape;
      }
      case 's':
        if (node.bad) return 'drop:str:invalid';
        return this.strAction(node.s, a, false, dpath);
      default:
        return 'drop:null';
    }
  }

  /** Action on a string value (named parts, path segments, JSON strings). null = not UTF-8. */
  private strAction(s: string | null, a: Action | undefined, pathParam: boolean, dpath: string | null): string {
    if (s === null) {
      this.gqlUnusable(a);
      return 'drop:bytes';
    }
    if (!a) {
      if (dpath !== null && this.disc) this.discAdd(dpath, utf8(s));
      return this.shape(s);
    }
    switch (a.action) {
      case 'keep':
        if (utf8Length(s) <= this.p.limits.keepMaxBytes && (!pathParam || PATH_TOKEN_RE.test(s))) return 'keep:' + s;
        return this.shape(s);
      case 'code':
        // 5.6 (spec v1.11): only a code-shaped string within keep_max_bytes leaves;
        // v1.19: the alnum shape allows digits and dots, 1 to 16 bytes.
        if ((a.shape === 'alnum' ? CODE_ALNUM_RE : CODE_RE).test(s) && s.length <= this.p.limits.keepMaxBytes) return 'keep:' + s;
        return this.shape(s);
      case 'graphql':
        return this.graphqlStr(s);
      case 'hmac':
        return this.s.token(a.domain ?? 'id', utf8(s));
      case 'bucket':
        if (a.kind === 'time' && (!pathParam || PATH_TOKEN_RE.test(s))) return bucketTime(s, a.unit ?? '') ?? this.shape(s);
        return this.shape(s);
      default:
        return this.shape(s);
    }
  }

  /** 6.2 drop shape of a well-formed string, with the document shape of 22.4 when `bodies.docs` is on. */
  private shape(s: string): string {
    if (this.p.bodies.docs && detectFormat(s) === null) {
      const d = base64Doc(s);
      if (d !== null) return d;
    }
    return strShape(s);
  }

  // --- graphql (5.7, spec v1.14) ------------------------------------------------------

  /**
   * Request: a document leaves as gql: and its shape, anything else as its form; every
   * value is recorded for the gate. Response: with the gate open, a GraphQL name passing
   * the name rule leaves as gql: and the name; anything else as its form.
   */
  private graphqlStr(s: string): string {
    if (!this.resp) {
      this.gqlSeen = true;
      const r = gqlShape(s);
      if (r === null) {
        this.gqlNonIntro = true;
        return this.shape(s);
      }
      if (!r.introspection) this.gqlNonIntro = true;
      return 'gql:' + r.shape;
    }
    if (this.gqlGate() && gqlIsName(s) && gqlNameSafe(s)) return 'gql:' + s;
    return this.shape(s);
  }

  /** 5.7.2: open iff the request had a graphql value and all of them were introspection-only documents. */
  private gqlGate(): boolean {
    return this.gqlSeen && !this.gqlNonIntro;
  }

  /** A request value under a graphql rule without a usable string closes the gate. */
  private gqlUnusable(a: Action | undefined): void {
    if (a?.action === 'graphql' && !this.resp) {
      this.gqlSeen = true;
      this.gqlNonIntro = true;
    }
  }

  private discAdd(path: string, value: Buffer): void {
    if (!this.disc) return;
    const prev = this.disc.get(path);
    if (prev === undefined || Buffer.compare(value, prev) < 0) this.disc.set(path, value);
  }

  // --- named parts (8.1-8.3, 9.1 form) ---------------------------------------------

  private namedRule(groups: Groups, section: 'query' | 'headers' | 'cookies' | 'form', name: string | null): Action | undefined {
    if (name === null) return undefined;
    for (const g of groups) {
      if (!g) continue;
      if (section === 'form') {
        let best: BodyRule | undefined;
        for (const r of g.body) {
          if (r.steps.length !== 1) continue;
          const st = r.steps[0]!;
          if (!(st.t === 'any' || (st.t === 'name' && st.name === name))) continue;
          if (!best || r.names > best.names || (r.names === best.names && cmpUtf8(r.path, best.path) < 0)) best = r;
        }
        if (best) return best.action;
        continue;
      }
      const a = g[section].get(name);
      if (a) return a;
    }
    return undefined;
  }

  private namedMap(entries: NamedEntry[], groups: Groups, section: 'query' | 'headers' | 'cookies' | 'form', disc: string): OMap {
    const order: string[] = [];
    const byName = new Map<string, NamedEntry[]>();
    for (const e of entries) {
      let l = byName.get(e.out);
      if (!l) {
        l = [];
        byName.set(e.out, l);
        order.push(e.out);
      }
      l.push(e);
    }
    const res: OMap = new Map();
    // After 8.0 every header name has exactly one value: max_array applies to cookies,
    // query and form values only (8.2, 8.3).
    const maxArr = section === 'headers' ? Number.MAX_SAFE_INTEGER : this.maxArray;
    for (const name of order.slice(0, MAX_NAMES)) {
      const list = byName.get(name)!;
      const vals: Out[] = [];
      // 15: named parts use the output name ({*} when collapsed); form fields use tt-path style.
      const dpath = this.disc ? disc + '.' + (section === 'form' && name === '{*}' ? '*' : name) : null;
      for (let i = 0; i < Math.min(list.length, maxArr); i++) {
        const e = list[i]!;
        if (e.token !== undefined) {
          vals.push(e.token); // 22.3: a file part, whatever the rule; no discovery entry
          continue;
        }
        // Parts without "=" have no name: always drop (no rule can select them).
        const a = e.noEq ? undefined : this.namedRule(groups, section, e.orig);
        vals.push(this.strAction(decodeUtf8(e.value), a, false, dpath));
      }
      if (list.length > maxArr) vals.push('trunc:n:' + lenClass(list.length));
      res.set(name, vals);
    }
    if (order.length > MAX_NAMES) res.set('{trunc}', ['trunc:keys:' + lenClass(order.length)]);
    return res;
  }
}

/**
 * 9.0 decoding, one level, with an output cap (A-GZIP-STRICT): returns the decoded bytes,
 * 'cap' when the output reaches `cap` bytes, or null on any error (truncated stream,
 * bytes after the end of the stream, corrupt data).
 */
export function decodeBody(data: Buffer, zlibFormat: boolean, cap: number): Buffer | 'cap' | null {
  try {
    const fn = zlibFormat ? inflateSync : gunzipSync;
    const res = fn(data, { maxOutputLength: cap, info: true } as Parameters<typeof gunzipSync>[1]) as unknown as {
      buffer: Buffer;
      engine: { bytesWritten: number };
    };
    if (res.buffer.length >= cap) return 'cap';
    if (res.engine.bytesWritten !== data.length) return null;
    return res.buffer;
  } catch (e) {
    if ((e as { code?: string }).code === 'ERR_BUFFER_TOO_LARGE') return 'cap';
    return null;
  }
}

/** tt-cjson object from already serialized members (keys sorted by bytes). */
export function composeCanonical(parts: Map<string, string>): string {
  const keys = [...parts.keys()].sort(cmpUtf8);
  let s = '{';
  for (let i = 0; i < keys.length; i++) {
    if (i > 0) s += ',';
    s += writeString(keys[i]!) + ':' + parts.get(keys[i]!)!;
  }
  return s + '}';
}

/** Winning body rule for the path $ (5.0): first group with a rule without steps. */
function rootRule(groups: Groups): Action | undefined {
  for (const g of groups) {
    let best: BodyRule | undefined;
    for (const r of g?.body ?? []) {
      if (r.steps.length !== 0) continue;
      if (!best || cmpUtf8(r.path, best.path) < 0) best = r;
    }
    if (best) return best.action;
  }
  return undefined;
}

function replaceBody(side: Out | undefined): boolean {
  if (!(side instanceof Map) || !side.has('body')) return false;
  side.set('body', 'trunc:size');
  return true;
}

/** 22.2 point 8: keys of an XML tree: #text, @ + attribute name, element name. */
function xmlKeyIsLiteral(k: string): boolean {
  if (k === '#text') return true;
  return isLiteralName(k.charCodeAt(0) === 0x40 ? k.slice(1) : k);
}

function jstr(s: string): import('./json.js').JStr {
  return { k: 's', s, bad: false };
}

/** XML tree value (22.2 point 7) as a JSON node: every leaf is a string. */
function xmlToNode(v: XmlValue): JNode {
  if (typeof v === 'string') return jstr(v);
  if (Array.isArray(v)) return { k: 'a', a: v.map(xmlToNode) };
  return { k: 'o', m: v.members.map(([k, x]) => [jstr(k), xmlToNode(x)] as [import('./json.js').JStr, JNode]) };
}

function dedupe(m: Array<[import('./json.js').JStr, JNode]>): Array<[import('./json.js').JStr, JNode]> {
  if (m.length < 2) return m;
  const last = new Map<string, number>();
  m.forEach(([k], i) => last.set(k.s, i));
  if (last.size === m.length) return m;
  return m.filter(([k], i) => last.get(k.s) === i);
}

function cookiePart(piece: Buffer, out: NamedEntry[]): void {
  const eq = piece.indexOf(0x3d);
  if (eq < 0) return;
  const nb = piece.subarray(0, eq);
  const name = decodeUtf8(nb);
  out.push({
    orig: name,
    out: name !== null && isLiteralName(name) ? name : '{*}',
    value: piece.subarray(eq + 1),
    noEq: false,
  });
}

/** 8.3 / 9.1: query string or form body into named entries. */
export function parseUrlencoded(raw: Buffer): NamedEntry[] {
  const out: NamedEntry[] = [];
  for (const part of splitBytes(raw, 0x26)) {
    if (part.length === 0) continue;
    const eq = part.indexOf(0x3d);
    if (eq < 0) {
      out.push({ orig: null, out: '{*}', value: pctDecode(part, true), noEq: true });
      continue;
    }
    const name = decodeUtf8(pctDecode(part.subarray(0, eq), true));
    out.push({
      orig: name,
      out: name !== null && isLiteralName(name) ? name : '{*}',
      value: pctDecode(part.subarray(eq + 1), true),
      noEq: false,
    });
  }
  return out;
}
