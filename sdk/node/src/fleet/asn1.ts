// Tiny DER writer/reader, enough for a PKCS#10 certificate request (RFC 2986) with an
// ECDSA P-256 or Ed25519 key, without any dependency.

import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';

function len(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n = Math.floor(n / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

export function tlv(tag: number, ...content: Buffer[]): Buffer {
  const c = Buffer.concat(content);
  return Buffer.concat([Buffer.from([tag]), len(c.length), c]);
}

export const seq = (...c: Buffer[]) => tlv(0x30, ...c);
export const set = (...c: Buffer[]) => tlv(0x31, ...c);
export const ctx = (n: number, ...c: Buffer[]) => tlv(0xa0 + n, ...c);
export const octets = (b: Buffer) => tlv(0x04, b);
export const bitString = (b: Buffer) => tlv(0x03, Buffer.from([0]), b);
export const utf8String = (s: string) => tlv(0x0c, Buffer.from(s, 'utf8'));
export const bool = (v: boolean) => tlv(0x01, Buffer.from([v ? 0xff : 0]));
export const nul = () => Buffer.from([0x05, 0x00]);

export function int(v: number | Buffer): Buffer {
  let b: Buffer;
  if (typeof v === 'number') {
    let h = v.toString(16);
    if (h.length % 2) h = '0' + h;
    b = Buffer.from(h, 'hex');
  } else {
    b = v;
  }
  while (b.length > 1 && b[0] === 0 && b[1]! < 0x80) b = b.subarray(1);
  if (b[0]! >= 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return tlv(0x02, b);
}

export function oid(dotted: string): Buffer {
  const parts = dotted.split('.').map(Number);
  const out: number[] = [parts[0]! * 40 + parts[1]!];
  for (const p of parts.slice(2)) {
    const stack: number[] = [p & 0x7f];
    let v = Math.floor(p / 128);
    while (v > 0) {
      stack.unshift((v & 0x7f) | 0x80);
      v = Math.floor(v / 128);
    }
    out.push(...stack);
  }
  return tlv(0x06, Buffer.from(out));
}

export const OID = {
  commonName: '2.5.4.3',
  ecdsaWithSHA256: '1.2.840.10045.4.3.2',
  ed25519: '1.3.101.112',
};

export function name(cn: string): Buffer {
  return seq(set(seq(oid(OID.commonName), utf8String(cn))));
}

export interface DerNode { tag: number; start: number; header: number; length: number; raw: Buffer; content: Buffer }

/** Reads one TLV at `off`. */
export function readTlv(buf: Buffer, off = 0): DerNode {
  const tag = buf[off]!;
  let l = buf[off + 1]!;
  let header = 2;
  if (l & 0x80) {
    const n = l & 0x7f;
    if (n === 0 || n > 4) throw new Error('der length');
    l = 0;
    for (let i = 0; i < n; i++) l = l * 256 + buf[off + 2 + i]!;
    header += n;
  }
  if (off + header + l > buf.length) throw new Error('der overflow');
  return { tag, start: off, header, length: l, raw: buf.subarray(off, off + header + l), content: buf.subarray(off + header, off + header + l) };
}

export function children(node: DerNode): DerNode[] {
  const out: DerNode[] = [];
  let off = 0;
  while (off < node.content.length) {
    const c = readTlv(node.content, off);
    out.push(c);
    off += c.header + c.length;
  }
  return out;
}

export function pem(label: string, der: Buffer): string {
  const b64 = der.toString('base64').replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
}

export function pemBlocks(text: string, label: string): Buffer[] {
  const re = new RegExp(`-----BEGIN ${label}-----([\\s\\S]*?)-----END ${label}-----`, 'g');
  const out: Buffer[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) out.push(Buffer.from(m[1]!.replace(/\s+/g, ''), 'base64'));
  return out;
}

/** Signs DER `data` with `key` and returns the AlgorithmIdentifier and the signature bits. */
export function signDer(data: Buffer, key: KeyObject): { alg: Buffer; sig: Buffer } {
  if (key.asymmetricKeyType === 'ed25519') return { alg: seq(oid(OID.ed25519)), sig: sign(null, data, key) };
  return { alg: seq(oid(OID.ecdsaWithSHA256)), sig: sign('sha256', data, key) };
}

export interface GeneratedCsr { csrPem: string; keyPem: string }

/** Generates a key pair (default ECDSA P-256) and a PKCS#10 request with CN = commonName. */
export function generateCsr(commonName: string, kind: 'ec' | 'ed25519' = 'ec'): GeneratedCsr {
  const { publicKey, privateKey } = kind === 'ed25519'
    ? generateKeyPairSync('ed25519')
    : generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const info = seq(int(0), name(commonName), spki, ctx(0));
  const { alg, sig } = signDer(info, privateKey);
  const csr = seq(info, alg, bitString(sig));
  return {
    csrPem: pem('CERTIFICATE REQUEST', csr),
    keyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
  };
}

/** base64url(SHA-256(DER)), the CA pin format of the enrollment token. */
export function pinOf(der: Buffer): string {
  return createHash('sha256').update(der).digest('base64url');
}
