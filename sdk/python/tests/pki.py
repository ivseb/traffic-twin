"""Test PKI built in pure Python (no openssl binary): Ed25519 X.509 certificates in DER.

A root CA, a server certificate for localhost / 127.0.0.1 and client certificates. The
signing code is the test helper of ``traffic_twin.ed25519``. Invented names only.
"""

from __future__ import annotations

import base64
import hashlib
import os
import time
from typing import List, Tuple

from traffic_twin import ed25519

OID_ED25519 = bytes([0x2B, 0x65, 0x70])


def tlv(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = bytes([0x81, n])
    else:
        ln = bytes([0x82, n >> 8, n & 0xFF])
    return bytes([tag]) + ln + content


def seq(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def integer(v: int) -> bytes:
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big")
    return tlv(0x02, b)


def oid_bytes(dotted: str) -> bytes:
    p = [int(x) for x in dotted.split(".")]
    out = bytes([p[0] * 40 + p[1]])
    for x in p[2:]:
        chunk = [x & 0x7F]
        x >>= 7
        while x:
            chunk.append(0x80 | (x & 0x7F))
            x >>= 7
        out += bytes(reversed(chunk))
    return tlv(0x06, out)


def name(cn: str) -> bytes:
    return seq(tlv(0x31, seq(oid_bytes("2.5.4.3"), tlv(0x0C, cn.encode()))))


def utc(t: float) -> bytes:
    return tlv(0x17, time.strftime("%y%m%d%H%M%SZ", time.gmtime(t)).encode())


def pem(label: str, der: bytes) -> str:
    b = base64.b64encode(der).decode()
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, "\n".join(b[i:i + 64] for i in range(0, len(b), 64)), label)


def pkcs8(seed: bytes) -> bytes:
    return seq(integer(0), seq(tlv(0x06, OID_ED25519)), tlv(0x04, tlv(0x04, seed)))


def ext(oid: str, critical: bool, value: bytes) -> bytes:
    return seq(oid_bytes(oid), *( [tlv(0x01, b"\xff")] if critical else [] ), tlv(0x04, value))


def certificate(subject_cn: str, pub: bytes, issuer_cn: str, issuer_seed: bytes, is_ca: bool,
                dns: List[str] = (), ips: List[str] = (), eku: List[str] = ()) -> bytes:
    now = time.time()
    exts = [ext("2.5.29.19", True, seq(tlv(0x01, b"\xff")) if is_ca else seq()),
            ext("2.5.29.15", True, tlv(0x03, b"\x01\x06" if is_ca else b"\x07\x80"))]
    if dns or ips:
        names = [tlv(0x82, d.encode()) for d in dns] + [tlv(0x87, bytes(int(x) for x in ip.split("."))) for ip in ips]
        exts.append(ext("2.5.29.17", False, seq(*names)))
    if eku:
        exts.append(ext("2.5.29.37", False, seq(*[oid_bytes(e) for e in eku])))
    sig_alg = seq(tlv(0x06, OID_ED25519))
    tbs = seq(
        tlv(0xA0, integer(2)), integer(int.from_bytes(os.urandom(12), "big")), sig_alg,
        name(issuer_cn), seq(utc(now - 3600), utc(now + 30 * 86400)), name(subject_cn),
        seq(seq(tlv(0x06, OID_ED25519)), tlv(0x03, b"\x00" + pub)), tlv(0xA3, seq(*exts)))
    sig = ed25519.sign(issuer_seed, tbs)
    return seq(tbs, sig_alg, tlv(0x03, b"\x00" + sig))


SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"


class Pki:
    def __init__(self) -> None:
        self.ca_seed = os.urandom(32)
        ca_pub = ed25519.public_key(self.ca_seed)
        self.ca_der = certificate("tt-test-root", ca_pub, "tt-test-root", self.ca_seed, True)
        self.ca_pem = pem("CERTIFICATE", self.ca_der)
        srv_seed = os.urandom(32)
        srv_der = certificate("localhost", ed25519.public_key(srv_seed), "tt-test-root", self.ca_seed, False,
                              dns=["localhost"], ips=["127.0.0.1"], eku=[SERVER_AUTH])
        self.server_key_pem = pem("PRIVATE KEY", pkcs8(srv_seed))
        # The chain includes the root, as the Fleet API requires.
        self.server_chain_pem = pem("CERTIFICATE", srv_der) + self.ca_pem
        self.pin = base64.urlsafe_b64encode(hashlib.sha256(self.ca_der).digest()).rstrip(b"=").decode()

    def issue_client(self, source_id: str) -> Tuple[str, str]:
        seed = os.urandom(32)
        der = certificate(source_id, ed25519.public_key(seed), "tt-test-root", self.ca_seed, False,
                          dns=[source_id], eku=[CLIENT_AUTH])
        return pem("CERTIFICATE", der), pem("PRIVATE KEY", pkcs8(seed))
