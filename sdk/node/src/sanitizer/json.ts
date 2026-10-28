// Strict RFC 8259 JSON parser that keeps number lexemes (sanitizer.md 9.2), the tt-cjson
// canonical writer (10.1) and the canonical number form (10.2).
//
// The parser is iterative (no recursion), validates the whole input, rejects a leading
// BOM, invalid UTF-8, control characters in strings, and anything outside RFC 8259.
// Lone surrogates produced by \u escapes are allowed syntactically and flagged on the
// string node (`bad`), as 9.2 requires.

import { cmpUtf8, isWellFormed } from './utf8.js';

export type JNode = JObj | JArr | JStr | JNum | JBool | JNull;
export interface JObj { k: 'o'; m: Array<[JStr, JNode]> }
export interface JArr { k: 'a'; a: JNode[] }
export interface JStr { k: 's'; s: string; bad: boolean }
export interface JNum { k: 'n'; lex: string }
export interface JBool { k: 'b'; v: boolean }
export interface JNull { k: 'z' }

export class JsonError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = 'JsonError';
  }
}

const strictDecoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const NULL_NODE: JNull = { k: 'z' };
const TRUE_NODE: JBool = { k: 'b', v: true };
const FALSE_NODE: JBool = { k: 'b', v: false };

interface Frame {
  node: JObj | JArr;
  key: JStr | null;
}

function isWs(c: number | undefined): boolean {
  return c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d;
}

function hex4(buf: Uint8Array, i: number): number {
  let v = 0;
  for (let j = 0; j < 4; j++) {
    const c = buf[i + j];
    let d: number;
    if (c === undefined) throw new JsonError('eof in escape');
    if (c >= 0x30 && c <= 0x39) d = c - 0x30;
    else if (c >= 0x41 && c <= 0x46) d = c - 0x37;
    else if (c >= 0x61 && c <= 0x66) d = c - 0x57;
    else throw new JsonError('bad hex escape');
    v = v * 16 + d;
  }
  return v;
}

/** Parses a complete JSON document. Throws JsonError on any deviation from RFC 8259. */
export function parseJson(input: Uint8Array): JNode {
  const buf = input;
  const n = buf.length;
  let i = 0;
  if (n >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) throw new JsonError('bom');

  const ws = () => {
    while (i < n && isWs(buf[i])) i++;
  };

  const readString = (): JStr => {
    // buf[i] === '"'
    i++;
    let out = '';
    let start = i;
    let nonAscii = false;
    const flush = (end: number) => {
      if (end > start) {
        if (nonAscii) {
          try {
            out += strictDecoder.decode(buf.subarray(start, end));
          } catch {
            throw new JsonError('invalid utf-8');
          }
        } else {
          out += Buffer.from(buf.buffer, buf.byteOffset + start, end - start).toString('latin1');
        }
      }
      nonAscii = false;
    };
    for (;;) {
      if (i >= n) throw new JsonError('unterminated string');
      const c = buf[i]!;
      if (c === 0x22) {
        flush(i);
        i++;
        break;
      }
      if (c === 0x5c) {
        flush(i);
        const e = buf[i + 1];
        switch (e) {
          case 0x22: out += '"'; i += 2; break;
          case 0x5c: out += '\\'; i += 2; break;
          case 0x2f: out += '/'; i += 2; break;
          case 0x62: out += '\b'; i += 2; break;
          case 0x66: out += '\f'; i += 2; break;
          case 0x6e: out += '\n'; i += 2; break;
          case 0x72: out += '\r'; i += 2; break;
          case 0x74: out += '\t'; i += 2; break;
          case 0x75: out += String.fromCharCode(hex4(buf, i + 2)); i += 6; break;
          default: throw new JsonError('bad escape');
        }
        start = i;
        continue;
      }
      if (c < 0x20) throw new JsonError('control character in string');
      if (c >= 0x80) nonAscii = true;
      i++;
    }
    return { k: 's', s: out, bad: !isWellFormed(out) };
  };

  const readNumber = (): JNum => {
    const s = i;
    if (buf[i] === 0x2d) i++;
    if (buf[i] === 0x30) {
      i++;
    } else if (buf[i] !== undefined && buf[i]! >= 0x31 && buf[i]! <= 0x39) {
      while (i < n && buf[i]! >= 0x30 && buf[i]! <= 0x39) i++;
    } else {
      throw new JsonError('bad number');
    }
    if (buf[i] === 0x2e) {
      i++;
      const f = i;
      while (i < n && buf[i]! >= 0x30 && buf[i]! <= 0x39) i++;
      if (i === f) throw new JsonError('bad fraction');
    }
    if (buf[i] === 0x65 || buf[i] === 0x45) {
      i++;
      if (buf[i] === 0x2b || buf[i] === 0x2d) i++;
      const f = i;
      while (i < n && buf[i]! >= 0x30 && buf[i]! <= 0x39) i++;
      if (i === f) throw new JsonError('bad exponent');
    }
    return { k: 'n', lex: Buffer.from(buf.buffer, buf.byteOffset + s, i - s).toString('latin1') };
  };

  const literal = (word: string, node: JNode): JNode => {
    for (let j = 0; j < word.length; j++) {
      if (buf[i + j] !== word.charCodeAt(j)) throw new JsonError('bad literal');
    }
    i += word.length;
    return node;
  };

  const readKey = (): JStr => {
    if (buf[i] !== 0x22) throw new JsonError('expected key');
    const k = readString();
    ws();
    if (buf[i] !== 0x3a) throw new JsonError('expected colon');
    i++;
    ws();
    return k;
  };

  const stack: Frame[] = [];
  ws();
  for (;;) {
    let v: JNode;
    const c = buf[i];
    if (c === 0x7b) {
      i++;
      ws();
      const o: JObj = { k: 'o', m: [] };
      if (buf[i] === 0x7d) {
        i++;
        v = o;
      } else {
        stack.push({ node: o, key: readKey() });
        continue;
      }
    } else if (c === 0x5b) {
      i++;
      ws();
      const a: JArr = { k: 'a', a: [] };
      if (buf[i] === 0x5d) {
        i++;
        v = a;
      } else {
        stack.push({ node: a, key: null });
        continue;
      }
    } else if (c === 0x22) {
      v = readString();
    } else if (c === 0x2d || (c !== undefined && c >= 0x30 && c <= 0x39)) {
      v = readNumber();
    } else if (c === 0x74) {
      v = literal('true', TRUE_NODE);
    } else if (c === 0x66) {
      v = literal('false', FALSE_NODE);
    } else if (c === 0x6e) {
      v = literal('null', NULL_NODE);
    } else {
      throw new JsonError('unexpected character');
    }
    // Attach v to its parent, closing containers as needed.
    for (;;) {
      const f = stack[stack.length - 1];
      if (f === undefined) {
        ws();
        if (i !== n) throw new JsonError('trailing data');
        return v;
      }
      if (f.node.k === 'o') f.node.m.push([f.key!, v]);
      else f.node.a.push(v);
      ws();
      const d = buf[i];
      if (d === 0x2c) {
        i++;
        ws();
        if (f.node.k === 'o') f.key = readKey();
        break;
      }
      if ((f.node.k === 'o' && d === 0x7d) || (f.node.k === 'a' && d === 0x5d)) {
        i++;
        stack.pop();
        v = f.node;
        continue;
      }
      throw new JsonError('expected separator');
    }
  }
}

// ---------------------------------------------------------------------------------
// Canonical numbers (10.2)

export const INT_LEXEME = /^-?(0|[1-9][0-9]*)$/;

/** 5.3: lexeme of at most 64 bytes and |written exponent| <= 9999. */
export function lexemeWithinLimits(lex: string): boolean {
  if (lex.length > 64) return false;
  let e = lex.indexOf('e');
  if (e < 0) e = lex.indexOf('E');
  if (e < 0) return true;
  let d = lex.slice(e + 1);
  if (d[0] === '+' || d[0] === '-') d = d.slice(1);
  d = d.replace(/^0+/, '');
  return d.length <= 4;
}

/** Canonical form of a valid JSON number lexeme, computed in exact decimal arithmetic. */
export function canonicalNumber(lex: string): string {
  let i = 0;
  let neg = false;
  if (lex[0] === '-') {
    neg = true;
    i = 1;
  }
  let j = i;
  while (j < lex.length && lex.charCodeAt(j) >= 0x30 && lex.charCodeAt(j) <= 0x39) j++;
  const intp = lex.slice(i, j);
  let frac = '';
  if (lex[j] === '.') {
    let k = j + 1;
    while (k < lex.length && lex.charCodeAt(k) >= 0x30 && lex.charCodeAt(k) <= 0x39) k++;
    frac = lex.slice(j + 1, k);
    j = k;
  }
  let exp = 0;
  if (lex[j] === 'e' || lex[j] === 'E') exp = parseInt(lex.slice(j + 1), 10);
  let digits = intp + frac;
  exp -= frac.length;
  let s = 0;
  while (s < digits.length && digits[s] === '0') s++;
  digits = digits.slice(s);
  let t = digits.length;
  while (t > 0 && digits[t - 1] === '0') t--;
  exp += digits.length - t;
  digits = digits.slice(0, t);
  if (digits.length === 0) return '0';
  const nd = digits.length;
  const e = exp + nd;
  let out: string;
  if (e > -6 && e <= 21) {
    if (e <= 0) out = '0.' + '0'.repeat(-e) + digits;
    else if (e >= nd) out = digits + '0'.repeat(e - nd);
    else out = digits.slice(0, e) + '.' + digits.slice(e);
  } else {
    const k = e - 1;
    out = digits[0] + (nd > 1 ? '.' + digits.slice(1) : '') + 'e' + (k >= 0 ? '+' : '-') + Math.abs(k);
  }
  return (neg ? '-' : '') + out;
}

// ---------------------------------------------------------------------------------
// Output values and the tt-cjson writer (10.1)

/** A number already in canonical form. */
export class CNum {
  constructor(readonly canon: string) {}
}

export type Out = string | boolean | null | CNum | Out[] | OMap;
export type OMap = Map<string, Out>;

const NEEDS_ESCAPE = /["\\\u0000-\u001f\u007f-￿]/;

export function writeString(s: string): string {
  if (!NEEDS_ESCAPE.test(s)) return '"' + s + '"';
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += '\\\\';
    else if (c < 0x20 || c >= 0x7f) out += '\\u' + c.toString(16).padStart(4, '0');
    else out += s[i];
  }
  return out + '"';
}

export function writeCanonical(v: Out): string {
  if (typeof v === 'string') return writeString(v);
  if (v === null) return 'null';
  if (v === true) return 'true';
  if (v === false) return 'false';
  if (v instanceof CNum) return v.canon;
  if (Array.isArray(v)) {
    let out = '[';
    for (let i = 0; i < v.length; i++) {
      if (i > 0) out += ',';
      out += writeCanonical(v[i]!);
    }
    return out + ']';
  }
  const keys = [...v.keys()].sort(cmpUtf8);
  let out = '{';
  for (let i = 0; i < keys.length; i++) {
    if (i > 0) out += ',';
    out += writeString(keys[i]!) + ':' + writeCanonical(v.get(keys[i]!)!);
  }
  return out + '}';
}

/** Converts a parsed JSON document to an Out tree (numbers canonicalized). Used for policy and event documents. */
export function nodeToOut(node: JNode): Out {
  switch (node.k) {
    case 'z': return null;
    case 'b': return node.v;
    case 'n': return new CNum(canonicalNumber(node.lex));
    case 's': return node.s;
    case 'a': return node.a.map(nodeToOut);
    case 'o': {
      const m: OMap = new Map();
      for (const [k, v] of node.m) m.set(k.s, nodeToOut(v));
      return m;
    }
  }
}

/** Plain JS value with numbers kept as lexeme wrappers. */
export class Lex {
  constructor(readonly lex: string) {}
  toNumber(): number {
    return Number(this.lex);
  }
}
export type Plain = string | boolean | null | Lex | Plain[] | { [k: string]: Plain };

/**
 * Converts a parsed document to plain objects (null-prototype), rejecting duplicate keys
 * and lone surrogates (used for policy bodies and envelopes: fail closed).
 */
export function nodeToPlain(node: JNode, strict: boolean): Plain {
  switch (node.k) {
    case 'z': return null;
    case 'b': return node.v;
    case 'n': return new Lex(node.lex);
    case 's':
      if (strict && node.bad) throw new JsonError('lone surrogate');
      return node.s;
    case 'a': return node.a.map((x) => nodeToPlain(x, strict));
    case 'o': {
      const o: { [k: string]: Plain } = Object.create(null);
      for (const [k, v] of node.m) {
        if (strict && (k.bad || Object.prototype.hasOwnProperty.call(o, k.s))) throw new JsonError('duplicate or invalid key');
        o[k.s] = nodeToPlain(v, strict);
      }
      return o;
    }
  }
}
