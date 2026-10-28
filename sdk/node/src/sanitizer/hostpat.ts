// Host patterns and IP classes, docs/spec/sanitizer.md 3.1 (IPv6 literals), 3.5 and 3.6 (spec v1.5).
//
// Everything here is written from the spec: the IPv6 parser is our own (no node:net helpers,
// whose accepted forms differ between versions) and the private ranges are the closed table
// of 3.6 (no "is private" library function).

import { RE_IPV4, detectFormat } from './formats.js';

const SAFE_LABEL = /^[a-z][a-z0-9-]{0,62}$/; // 3.5 rule a
const SIX_DIGITS = /[0-9]{6}/; // rule b
const HEX12 = /[0-9a-f]{12}/; // rule c
const HEX_GROUP = /^[0-9a-f]{1,4}$/;

/** 3.5: a host label stays literal only if every rule holds. */
export function hostLabelSafe(label: string): boolean {
  return (
    SAFE_LABEL.test(label) &&
    !SIX_DIGITS.test(label) &&
    !HEX12.test(label) &&
    detectFormat(label) === null // rule d (implied by c, kept for fidelity)
  );
}

function groups(parts: string[], tailOk: boolean): number[] | null {
  const out: number[] = [];
  for (let k = 0; k < parts.length; k++) {
    const g = parts[k]!;
    if (tailOk && k === parts.length - 1 && g.includes('.')) {
      if (!RE_IPV4.test(g)) return null;
      const o = g.split('.').map((x) => Number(x));
      out.push((o[0]! << 8) | o[1]!, (o[2]! << 8) | o[3]!);
    } else if (HEX_GROUP.test(g)) {
      out.push(parseInt(g, 16));
    } else {
      return null;
    }
  }
  return out;
}

/**
 * 3.1 point 5: RFC 4291 2.2 text form of an already lowercased string. 1-4 hex digits per
 * group, at most one `::` standing for at least one group, an optional dotted IPv4 (6.3
 * `ipv4`) as the last 32 bits, no zone. Returns the 16 address bytes or null.
 */
export function parseIpv6(s: string): Uint8Array | null {
  let g: number[];
  const first = s.indexOf('::');
  if (first >= 0) {
    if (s.indexOf('::', first + 1) >= 0) return null;
    const left = s.slice(0, first);
    const right = s.slice(first + 2);
    const a = groups(left === '' ? [] : left.split(':'), false);
    const b = groups(right === '' ? [] : right.split(':'), true);
    if (!a || !b || a.length + b.length > 7) return null;
    g = [...a, ...new Array<number>(8 - a.length - b.length).fill(0), ...b];
  } else {
    const r = groups(s.split(':'), true);
    if (!r || r.length !== 8) return null;
    g = r;
  }
  const out = new Uint8Array(16);
  g.forEach((x, i) => {
    out[2 * i] = x >> 8;
    out[2 * i + 1] = x & 0xff;
  });
  return out;
}

/** True if the first `bits` bits of `addr` equal those of `prefix` (same length arrays). */
function inPrefix(addr: ArrayLike<number>, prefix: ArrayLike<number>, bits: number): boolean {
  let i = 0;
  for (; bits >= 8; bits -= 8, i++) if (addr[i] !== prefix[i]) return false;
  if (bits > 0) {
    const mask = (0xff << (8 - bits)) & 0xff;
    if ((addr[i]! & mask) !== (prefix[i]! & mask)) return false;
  }
  return true;
}

// 3.6: every address outside these ranges is public.
const IPV4_PRIVATE: Array<[number[], number]> = [
  [[0, 0, 0, 0], 8], [[10, 0, 0, 0], 8], [[100, 64, 0, 0], 10], [[127, 0, 0, 0], 8],
  [[169, 254, 0, 0], 16], [[172, 16, 0, 0], 12], [[192, 0, 0, 0], 24], [[192, 0, 2, 0], 24],
  [[192, 168, 0, 0], 16], [[198, 18, 0, 0], 15], [[198, 51, 100, 0], 24], [[203, 0, 113, 0], 24],
  [[224, 0, 0, 0], 4], [[240, 0, 0, 0], 4],
];
const v6 = (s: string): Uint8Array => parseIpv6(s)!;
const IPV6_EMBEDDED_V4: Array<[Uint8Array, number]> = [[v6('::ffff:0:0'), 96], [v6('64:ff9b::'), 96]];
const IPV6_PRIVATE: Array<[Uint8Array, number]> = [
  [v6('::'), 96], [v6('64:ff9b:1::'), 48], [v6('100::'), 64], [v6('2001::'), 23], [v6('2001:db8::'), 32],
  [v6('fc00::'), 7], [v6('fe80::'), 10], [v6('fec0::'), 10], [v6('ff00::'), 8],
];

export function ipv4Private(a: ArrayLike<number>): boolean {
  return IPV4_PRIVATE.some(([p, n]) => inPrefix(a, p, n));
}

export function ipv6Private(a: Uint8Array): boolean {
  // The two ranges with an embedded IPv4 come first (3.6).
  for (const [p, n] of IPV6_EMBEDDED_V4) if (inPrefix(a, p, n)) return ipv4Private(a.subarray(12));
  return IPV6_PRIVATE.some(([p, n]) => inPrefix(a, p, n));
}

/**
 * 3.5: pattern of a valid host (3.1), without the `host:` prefix, or null when a label is
 * empty (`host:invalid`). `port` is the normalized port (null when absent or default).
 */
export function hostPattern(host: string, port: string | null, ip6: Uint8Array | null): string | null {
  const suffix = port ? ':' + port : '';
  if (ip6) return 'ip:' + (ipv6Private(ip6) ? 'private' : 'public') + suffix;
  const h = host.endsWith('.') ? host.slice(0, -1) : host;
  const labels = h.split('.');
  if (labels.some((l) => l === '')) return null;
  if (RE_IPV4.test(h)) {
    return 'ip:' + (ipv4Private(labels.map((x) => Number(x))) ? 'private' : 'public') + suffix;
  }
  return labels.map((l) => (hostLabelSafe(l) ? l : '{*}')).join('.') + suffix;
}
