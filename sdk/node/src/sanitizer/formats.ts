// Shapes (6.2), recognized formats (6.3), length classes (0.3) and the name rule (9.3.3).
//
// All regular expressions are whole-string, ASCII-only matches (0.1). JavaScript `$`
// without the `m` flag only matches at the end of the input, so "x\n" never matches.

import { utf8Length } from './utf8.js';

export function lenClass(n: number): string {
  if (n <= 8) return 'l8';
  if (n <= 32) return 'l32';
  if (n <= 128) return 'l128';
  if (n <= 1024) return 'l1024';
  return 'lmax';
}

const PRINTABLE = /^[\x20-\x7e]*$/;

export const RE_UUID = /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/;
export const RE_JWT = /^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;
export const RE_EMAIL = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$/;
export const RE_DATETIME = /^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt ][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?([Zz]|[+-][0-9]{2}:[0-9]{2})$/;
export const RE_DATE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/;
export const RE_URL = /^[A-Za-z][A-Za-z0-9+.-]{0,15}:\/\/[!-~]+$/;
export const RE_IPV4 = /^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$/;
export const RE_PHONE = /^\+[1-9][0-9]{6,14}$/;
export const RE_DIGITS = /^-?[0-9]{1,19}$/;
export const RE_HEX = /^[0-9A-Fa-f]{16,}$/;

const FORMATS: Array<[string, RegExp]> = [
  ['uuid', RE_UUID],
  ['jwt', RE_JWT],
  ['email', RE_EMAIL],
  ['datetime', RE_DATETIME],
  ['date', RE_DATE],
  ['url', RE_URL],
  ['ipv4', RE_IPV4],
  ['phone', RE_PHONE],
  ['digits', RE_DIGITS],
  ['hex', RE_HEX],
];

export function isPrintableAscii(s: string): boolean {
  return PRINTABLE.test(s);
}

/** First matching format of 6.3, or null. Only printable ASCII strings are considered. */
export function detectFormat(s: string): string | null {
  if (!PRINTABLE.test(s)) return null;
  for (const [name, re] of FORMATS) {
    if (re.test(s)) return name;
  }
  return null;
}

/** drop form of a well-formed string. */
export function strShape(s: string): string {
  const f = detectFormat(s);
  if (f !== null) return 'drop:str:' + f;
  return 'drop:str:' + lenClass(utf8Length(s));
}

const KEY_RE = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const SIX_DIGITS = /[0-9]{6}/;
const HEADER_NAME_RE = /^[a-z0-9!#$%&'*+.^_`|~-]{1,64}$/;

function looksLikeValue(s: string): boolean {
  return RE_UUID.test(s) || RE_EMAIL.test(s) || RE_HEX.test(s) || RE_DIGITS.test(s) || RE_JWT.test(s) || SIX_DIGITS.test(s);
}

/** 9.3.3: a JSON key, query, cookie or form name leaves as a literal only if this holds. */
export function isLiteralName(s: string): boolean {
  const hit = literalMemo.get(s);
  if (hit !== undefined) return hit;
  const r = KEY_RE.test(s) && !looksLikeValue(s);
  // Names repeat (JSON keys, header and query names): remember the answer, bounded.
  if (s.length <= 64) {
    if (literalMemo.size >= MEMO_MAX) literalMemo.clear();
    literalMemo.set(s, r);
  }
  return r;
}

const MEMO_MAX = 2048;
const literalMemo = new Map<string, boolean>();
const headerMemo = new Map<string, string>();

/** 8.0.2: output name of a lowercased header name. */
export function headerOutName(lower: string): string {
  const hit = headerMemo.get(lower);
  if (hit !== undefined) return hit;
  const r = !HEADER_NAME_RE.test(lower) || looksLikeValue(lower) ? '{*}' : lower;
  if (lower.length <= 64) {
    if (headerMemo.size >= MEMO_MAX) headerMemo.clear();
    headerMemo.set(lower, r);
  }
  return r;
}

export const PATH_TOKEN_RE = /^[A-Za-z0-9._~-]{1,64}$/;
/** Code shape of the code action (sanitizer.md 5.6, spec v1.11): ASCII letters, `_`, `-`, 2 to 32 bytes. */
export const CODE_RE = /^[A-Za-z_-]{2,32}$/;
/** Shape `alnum` of the code action (sanitizer.md 5.6, spec v1.19): letters, digits, `_`, `-`, `.`, 1 to 16 bytes. */
export const CODE_ALNUM_RE = /^[A-Za-z0-9_.-]{1,16}$/;
export const AUTO_WORD_RE = /^([a-z]+([-_][a-z]+)*|v[0-9]{1,3})$/;
