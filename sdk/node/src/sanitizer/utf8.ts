// Strict UTF-8 (RFC 3629, sanitizer.md 0.2) helpers.
//
// The WHATWG decoder in fatal mode rejects overlong forms, encoded surrogates and code
// points above U+10FFFF. ignoreBOM keeps a leading U+FEFF as a character instead of
// silently removing it.

const strict = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** Decodes strictly; returns null when the bytes are not valid UTF-8. */
export function decodeUtf8(b: Uint8Array): string | null {
  if (b.length === 0) return '';
  // Fast path: pure ASCII.
  let ascii = true;
  for (let i = 0; i < b.length; i++) {
    if (b[i]! >= 0x80) {
      ascii = false;
      break;
    }
  }
  if (ascii) return Buffer.from(b.buffer, b.byteOffset, b.length).toString('latin1');
  try {
    return strict.decode(b);
  } catch {
    return null;
  }
}

const LONE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** True when the JS string has no lone surrogates (so it has a UTF-8 encoding). */
export function isWellFormed(s: string): boolean {
  const f = (s as unknown as { isWellFormed?: () => boolean }).isWellFormed;
  if (typeof f === 'function') return f.call(s);
  return !LONE.test(s);
}

/** UTF-8 length of a well-formed string. */
export function utf8Length(s: string): number {
  return Buffer.byteLength(s, 'utf8');
}

export function utf8(s: string): Buffer {
  return Buffer.from(s, 'utf8');
}

/** ASCII-only lowercase (never touches non-ASCII characters). */
export function asciiLower(s: string): string {
  let out = '';
  let changed = false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0x41 && c <= 0x5a) {
      changed = true;
      break;
    }
  }
  if (!changed) return s;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    out += c >= 0x41 && c <= 0x5a ? String.fromCharCode(c + 32) : s[i];
  }
  return out;
}

/** ASCII-only uppercase. */
export function asciiUpper(s: string): string {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    out += c >= 0x61 && c <= 0x7a ? String.fromCharCode(c - 32) : s[i];
  }
  return out;
}

/** Lowercase ASCII bytes. */
export function asciiLowerBytes(b: Buffer): Buffer {
  const out = Buffer.from(b);
  for (let i = 0; i < out.length; i++) {
    const c = out[i]!;
    if (c >= 0x41 && c <= 0x5a) out[i] = c + 32;
  }
  return out;
}

/** Strips OWS (space and horizontal tab) on both sides. */
export function trimOws(b: Buffer): Buffer {
  let s = 0;
  let e = b.length;
  while (s < e && (b[s] === 0x20 || b[s] === 0x09)) s++;
  while (e > s && (b[e - 1] === 0x20 || b[e - 1] === 0x09)) e--;
  return s === 0 && e === b.length ? b : b.subarray(s, e);
}

export function trimOwsStr(s: string): string {
  let a = 0;
  let e = s.length;
  while (a < e && (s.charCodeAt(a) === 0x20 || s.charCodeAt(a) === 0x09)) a++;
  while (e > a && (s.charCodeAt(e - 1) === 0x20 || s.charCodeAt(e - 1) === 0x09)) e--;
  return s.slice(a, e);
}

/** Splits bytes on a single byte value (keeps empty parts). */
export function splitBytes(b: Buffer, sep: number): Buffer[] {
  const out: Buffer[] = [];
  let start = 0;
  for (let i = 0; i < b.length; i++) {
    if (b[i] === sep) {
      out.push(b.subarray(start, i));
      start = i + 1;
    }
  }
  out.push(b.subarray(start));
  return out;
}

function hexVal(c: number): number {
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x41 && c <= 0x46) return c - 0x37;
  if (c >= 0x61 && c <= 0x66) return c - 0x57;
  return -1;
}

/** Percent-decoding of sanitizer.md 4.1 (optionally "+" -> space first, 8.3). */
export function pctDecode(b: Buffer, plusIsSpace: boolean): Buffer {
  let needs = false;
  for (let i = 0; i < b.length; i++) {
    if (b[i] === 0x25 || (plusIsSpace && b[i] === 0x2b)) {
      needs = true;
      break;
    }
  }
  if (!needs) return b;
  const out = Buffer.allocUnsafe(b.length);
  let o = 0;
  for (let i = 0; i < b.length; i++) {
    const c = b[i]!;
    if (c === 0x25 && i + 2 < b.length) {
      const h = hexVal(b[i + 1]!);
      const l = hexVal(b[i + 2]!);
      if (h >= 0 && l >= 0) {
        out[o++] = h * 16 + l;
        i += 2;
        continue;
      }
    }
    out[o++] = plusIsSpace && c === 0x2b ? 0x20 : c;
  }
  return out.subarray(0, o);
}

/** Byte-order comparison of two strings by their UTF-8 encoding (code point order). */
export function cmpUtf8(a: string, b: string): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    let x = a.charCodeAt(i);
    let y = b.charCodeAt(i);
    if (x === y) continue;
    // Surrogates (supplementary code points) sort after U+E000..U+FFFF in UTF-8.
    if (x >= 0xd800 && x <= 0xdfff) x += 0x10000;
    if (y >= 0xd800 && y <= 0xdfff) y += 0x10000;
    return x < y ? -1 : 1;
  }
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
}
