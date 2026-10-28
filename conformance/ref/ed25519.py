"""Minimal Ed25519 (RFC 8032, section 5.1) in pure Python, for test fixtures only.

Not constant time. Never use it with real keys: it only signs the invented policy
bodies of the conformance vectors and verifies them in the reference runner.
"""

import hashlib

p = 2 ** 255 - 19
q = 2 ** 252 + 27742317777372353535851937790883648493
d = -121665 * pow(121666, p - 2, p) % p
I = pow(2, (p - 1) // 4, p)


def _sha512(b):
    return hashlib.sha512(b).digest()


def _add(P1, P2):
    X1, Y1, Z1, T1 = P1
    X2, Y2, Z2, T2 = P2
    A = (Y1 - X1) * (Y2 - X2) % p
    B = (Y1 + X1) * (Y2 + X2) % p
    C = T1 * 2 * d * T2 % p
    D = Z1 * 2 * Z2 % p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % p, G * H % p, F * G % p, E * H % p)


def _mul(s, P1):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _add(Q, P1)
        P1 = _add(P1, P1)
        s >>= 1
    return Q


def _equal(P1, P2):
    if (P1[0] * P2[2] - P2[0] * P1[2]) % p != 0:
        return False
    return (P1[1] * P2[2] - P2[1] * P1[2]) % p == 0


def _recover_x(y, sign):
    if y >= p:
        return None
    x2 = (y * y - 1) * pow(d * y * y + 1, p - 2, p)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * I % p
    if (x * x - x2) % p != 0:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


_gy = 4 * pow(5, p - 2, p) % p
_gx = _recover_x(_gy, 0)
G = (_gx, _gy, 1, _gx * _gy % p)


def _compress(P1):
    zinv = pow(P1[2], p - 2, p)
    x = P1[0] * zinv % p
    y = P1[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, 'little')


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, 'little')
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % p)


def _secret_expand(seed):
    h = _sha512(seed)
    a = int.from_bytes(h[:32], 'little')
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed):
    a, _ = _secret_expand(seed)
    return _compress(_mul(a, G))


def sign(seed, msg):
    a, prefix = _secret_expand(seed)
    A = _compress(_mul(a, G))
    r = int.from_bytes(_sha512(prefix + msg), 'little') % q
    R = _compress(_mul(r, G))
    h = int.from_bytes(_sha512(R + A + msg), 'little') % q
    s = (r + h * a) % q
    return R + int.to_bytes(s, 32, 'little')


def verify(public, msg, sig):
    if len(public) != 32 or len(sig) != 64:
        return False
    A = _decompress(public)
    if A is None:
        return False
    R = _decompress(sig[:32])
    if R is None:
        return False
    s = int.from_bytes(sig[32:], 'little')
    if s >= q:
        return False
    h = int.from_bytes(_sha512(sig[:32] + public + msg), 'little') % q
    return _equal(_mul(s, G), _add(R, _mul(h, A)))


def _self_test():
    # RFC 8032 section 7.1, TEST 1.
    seed = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
    pub = bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
    sig = bytes.fromhex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
                        '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
    assert public_key(seed) == pub
    assert sign(seed, b'') == sig
    assert verify(pub, b'', sig)
    assert not verify(pub, b'x', sig)


_self_test()
