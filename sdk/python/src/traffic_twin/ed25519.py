"""Ed25519 signature verification (RFC 8032, section 5.1.7) in pure Python.

The standard library has no Ed25519, and traffic-twin SDKs may not depend on anything
else, so policy signatures are verified here. Verification handles public data only
(policy bytes, signature, pinned public key), therefore the implementation is not
constant time.

Strictness (fail closed): the scalar S must be below the group order, the public key
and R must be canonical encodings of curve points, and the cofactorless equation
``[S]B = R + [k]A`` is used.

``sign`` and ``public_key`` exist only for the tests of this package (they build signed
policies for the fake tt-core); production code calls ``verify`` only.
"""

from __future__ import annotations

import hashlib

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, P - 2, P) % P
_SQRT_M1 = pow(2, (P - 1) // 4, P)

_Point = tuple  # (X, Y, Z, T) extended coordinates
_IDENTITY = (0, 1, 1, 0)


def _add(p1: _Point, p2: _Point) -> _Point:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * _D * t2 % P
    d = z1 * 2 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _double(p1: _Point) -> _Point:
    return _add(p1, p1)


def _mul(s: int, p1: _Point) -> _Point:
    q = _IDENTITY
    while s > 0:
        if s & 1:
            q = _add(q, p1)
        p1 = _double(p1)
        s >>= 1
    return q


def _recover_x(y: int, sign: int):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * _SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_GY = 4 * pow(5, P - 2, P) % P
_GX = _recover_x(_GY, 0)
_B: _Point = (_GX, _GY, 1, _GX * _GY % P)


def _compress(p1: _Point) -> bytes:
    zinv = pow(p1[2], P - 2, P)
    x = p1[0] * zinv % P
    y = p1[1] * zinv % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def _sha512_int(*parts: bytes) -> int:
    h = hashlib.sha512()
    for p in parts:
        h.update(p)
    return int.from_bytes(h.digest(), "little")


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True only for a valid signature. Never raises on malformed input."""
    try:
        if len(public_key) != 32 or len(signature) != 64:
            return False
        a_pt = _decompress(public_key)
        if a_pt is None:
            return False
        r_bytes = signature[:32]
        if _decompress(r_bytes) is None:
            return False
        s = int.from_bytes(signature[32:], "little")
        if s >= L:
            return False
        k = _sha512_int(r_bytes, public_key, message) % L
        # R' = [S]B - [k]A, compared with R by encoding.
        neg_a = ((P - a_pt[0]) % P, a_pt[1], a_pt[2], (P - a_pt[3]) % P)
        sb = _mul(s, _B)
        ka = _mul(k, neg_a)
        return _compress(_add(sb, ka)) == r_bytes
    except Exception:  # pragma: no cover - defensive: any doubt is a rejection
        return False


# --- test helpers (RFC 8032 section 5.1.5-5.1.6) -----------------------------------

def _expand(seed: bytes):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed: bytes) -> bytes:
    a, _ = _expand(seed)
    return _compress(_mul(a, _B))


def sign(seed: bytes, message: bytes) -> bytes:
    a, prefix = _expand(seed)
    pub = _compress(_mul(a, _B))
    r = _sha512_int(prefix, message) % L
    r_bytes = _compress(_mul(r, _B))
    k = _sha512_int(r_bytes, pub, message) % L
    s = (r + k * a) % L
    return r_bytes + int.to_bytes(s, 32, "little")
