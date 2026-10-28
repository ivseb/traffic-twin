// Test PKI built with node:crypto and the SDK's DER helpers (no openssl binary needed):
// a root CA, a server certificate for localhost, client certificates issued from a CSR.

import { createHash, createPublicKey, generateKeyPairSync, randomBytes, verify } from 'node:crypto';
import {
  bitString, bool, children, ctx, int, name, octets, oid, pem, pemBlocks, readTlv, seq, signDer, tlv,
} from '../../dist/esm/fleet/asn1.js';

const ia5 = (s) => tlv(0x16, Buffer.from(s, 'latin1'));
function utcTime(d) {
  const p = (n) => String(n).padStart(2, '0');
  const s = `${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return tlv(0x17, Buffer.from(s, 'latin1'));
}
const ext = (id, critical, value) => seq(oid(id), ...(critical ? [bool(true)] : []), octets(value));
const keyId = (spki) => {
  const n = readTlv(spki);
  const bits = children(n)[1].content.subarray(1);
  return createHash('sha1').update(bits).digest();
};

function certificate({ subjectCn, spki, issuerCn, issuerKey, issuerSpki, isCa, dns = [], ips = [], eku = [] }) {
  const now = Date.now();
  const exts = [
    ext('2.5.29.19', true, isCa ? seq(bool(true)) : seq()),
    ext('2.5.29.15', true, isCa ? bitString(Buffer.from([0x06])) : bitString(Buffer.from([0x80]))),
    ext('2.5.29.14', false, octets(keyId(spki))),
    ext('2.5.29.35', false, seq(tlv(0x80, keyId(issuerSpki)))),
  ];
  if (dns.length || ips.length) {
    const names = [
      ...dns.map((d) => tlv(0x82, Buffer.from(d, 'latin1'))),
      ...ips.map((ip) => tlv(0x87, Buffer.from(ip.split('.').map(Number)))),
    ];
    exts.push(ext('2.5.29.17', false, seq(...names)));
  }
  if (eku.length) exts.push(ext('2.5.29.37', false, seq(...eku.map((e) => oid(e)))));
  const { alg } = signDer(Buffer.alloc(0), issuerKey);
  const tbs = seq(
    ctx(0, int(2)),
    int(randomBytes(12)),
    alg,
    name(issuerCn),
    seq(utcTime(new Date(now - 3600_000)), utcTime(new Date(now + 30 * 86400_000))),
    name(subjectCn),
    spki,
    ctx(3, seq(...exts)),
  );
  const { sig } = signDer(tbs, issuerKey);
  return seq(tbs, alg, bitString(sig));
}

const SERVER_AUTH = '1.3.6.1.5.5.7.3.1';
const CLIENT_AUTH = '1.3.6.1.5.5.7.3.2';

export function createPki() {
  const ca = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const caSpki = ca.publicKey.export({ type: 'spki', format: 'der' });
  const caDer = certificate({ subjectCn: 'tt-test-root', spki: caSpki, issuerCn: 'tt-test-root', issuerKey: ca.privateKey, issuerSpki: caSpki, isCa: true });
  const srv = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const srvSpki = srv.publicKey.export({ type: 'spki', format: 'der' });
  const srvDer = certificate({
    subjectCn: 'localhost', spki: srvSpki, issuerCn: 'tt-test-root', issuerKey: ca.privateKey, issuerSpki: caSpki,
    isCa: false, dns: ['localhost'], ips: ['127.0.0.1'], eku: [SERVER_AUTH],
  });
  const caPem = pem('CERTIFICATE', caDer);
  return {
    caDer,
    caPem,
    serverKeyPem: srv.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    // The chain includes the root, as the Fleet API requires.
    serverCertChainPem: pem('CERTIFICATE', srvDer) + caPem,
    /** Issues a client certificate for a PEM CSR (verifies its signature). */
    issueFromCsr(csrPem, sourceId) {
      const der = pemBlocks(csrPem, 'CERTIFICATE REQUEST')[0];
      const top = children(readTlv(der));
      const info = top[0];
      const spki = children(info)[2].raw;
      const pub = createPublicKey({ key: spki, format: 'der', type: 'spki' });
      const sigBits = top[2].content.subarray(1);
      const ok = pub.asymmetricKeyType === 'ed25519'
        ? verify(null, info.raw, pub, sigBits)
        : verify('sha256', info.raw, pub, sigBits);
      if (!ok) throw new Error('bad csr signature');
      return pem('CERTIFICATE', certificate({
        subjectCn: sourceId, spki, issuerCn: 'tt-test-root', issuerKey: ca.privateKey, issuerSpki: caSpki,
        isCa: false, dns: [sourceId], eku: [CLIENT_AUTH],
      }));
    },
    /** Issues a key pair and certificate (server-generated key flow). */
    issueWithKey(sourceId) {
      const k = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const spki = k.publicKey.export({ type: 'spki', format: 'der' });
      return {
        certPem: pem('CERTIFICATE', certificate({
          subjectCn: sourceId, spki, issuerCn: 'tt-test-root', issuerKey: ca.privateKey, issuerSpki: caSpki,
          isCa: false, dns: [sourceId], eku: [CLIENT_AUTH],
        })),
        keyPem: k.privateKey.export({ type: 'pkcs8', format: 'pem' }),
      };
    },
  };
}
