"""Host patterns and IP classes, docs/spec/sanitizer.md 3.1 (IPv6 literals), 3.5 and 3.6 (spec v1.5).

Everything here is written from the spec: the IPv6 parser is our own (no ``ipaddress``,
``socket.inet_pton`` and the like, whose accepted forms differ between versions) and the
private ranges are the closed table of 3.6 (no ``is_private``).
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from .formats import RE_IPV4, detect_format

_SAFE_LABEL = re.compile(r"[a-z][a-z0-9-]{0,62}")  # 3.5 rule a
_SIX_DIGITS = re.compile(r"[0-9]{6}")  # rule b
_HEX12 = re.compile(r"[0-9a-f]{12}")  # rule c
_HEX_GROUP = re.compile(r"[0-9a-f]{1,4}")


def host_label_safe(label: str) -> bool:
    """3.5: a host label stays literal only if every rule holds."""
    return (
        _SAFE_LABEL.fullmatch(label) is not None
        and _SIX_DIGITS.search(label) is None
        and _HEX12.search(label) is None
        and detect_format(label) is None  # rule d (implied by c, kept for fidelity)
    )


def _groups(parts: List[str], tail_ok: bool) -> Optional[List[int]]:
    out: List[int] = []
    for k, g in enumerate(parts):
        if tail_ok and k == len(parts) - 1 and "." in g:
            if RE_IPV4.fullmatch(g) is None:
                return None
            o = [int(x) for x in g.split(".")]
            out += [(o[0] << 8) | o[1], (o[2] << 8) | o[3]]
        elif _HEX_GROUP.fullmatch(g):
            out.append(int(g, 16))
        else:
            return None
    return out


def parse_ipv6(s: str) -> Optional[bytes]:
    """3.1 point 5: RFC 4291 2.2 text form of an already lowercased string.

    1-4 hex digits per group, at most one ``::`` standing for at least one group, an
    optional dotted IPv4 (6.3 ``ipv4``) as the last 32 bits, no zone. Returns the 16
    address bytes or ``None``.
    """
    first = s.find("::")
    if first >= 0:
        if s.find("::", first + 1) >= 0:
            return None
        left, right = s[:first], s[first + 2:]
        a = _groups(left.split(":") if left else [], False)
        b = _groups(right.split(":") if right else [], True)
        if a is None or b is None or len(a) + len(b) > 7:
            return None
        g = a + [0] * (8 - len(a) - len(b)) + b
    else:
        r = _groups(s.split(":"), True)
        if r is None or len(r) != 8:
            return None
        g = r
    return b"".join(x.to_bytes(2, "big") for x in g)


def _in_prefix(addr: bytes, prefix: bytes, bits: int) -> bool:
    n = len(addr) * 8 - bits
    return int.from_bytes(addr, "big") >> n == int.from_bytes(prefix, "big") >> n


# 3.6: every address outside these ranges is public.
_IPV4_PRIVATE: List[Tuple[bytes, int]] = [
    (bytes(p), n) for p, n in [
        ((0, 0, 0, 0), 8), ((10, 0, 0, 0), 8), ((100, 64, 0, 0), 10), ((127, 0, 0, 0), 8),
        ((169, 254, 0, 0), 16), ((172, 16, 0, 0), 12), ((192, 0, 0, 0), 24), ((192, 0, 2, 0), 24),
        ((192, 168, 0, 0), 16), ((198, 18, 0, 0), 15), ((198, 51, 100, 0), 24), ((203, 0, 113, 0), 24),
        ((224, 0, 0, 0), 4), ((240, 0, 0, 0), 4),
    ]
]


def _v6(s: str) -> bytes:
    r = parse_ipv6(s)
    assert r is not None
    return r


_IPV6_EMBEDDED_V4: List[Tuple[bytes, int]] = [(_v6("::ffff:0:0"), 96), (_v6("64:ff9b::"), 96)]
_IPV6_PRIVATE: List[Tuple[bytes, int]] = [
    (_v6(s), n) for s, n in [
        ("::", 96), ("64:ff9b:1::", 48), ("100::", 64), ("2001::", 23), ("2001:db8::", 32),
        ("fc00::", 7), ("fe80::", 10), ("fec0::", 10), ("ff00::", 8),
    ]
]


def ipv4_private(addr: bytes) -> bool:
    return any(_in_prefix(addr, p, n) for p, n in _IPV4_PRIVATE)


def ipv6_private(addr: bytes) -> bool:
    # The two ranges with an embedded IPv4 come first (3.6).
    for p, n in _IPV6_EMBEDDED_V4:
        if _in_prefix(addr, p, n):
            return ipv4_private(addr[12:])
    return any(_in_prefix(addr, p, n) for p, n in _IPV6_PRIVATE)


def host_pattern(host: str, port: Optional[str], ip6: Optional[bytes]) -> Optional[str]:
    """3.5: pattern of a valid host (3.1), without the ``host:`` prefix, or ``None`` when a
    label is empty (``host:invalid``). ``port`` is the normalized port (None when absent or
    the scheme default)."""
    suffix = ":" + port if port else ""
    if ip6 is not None:
        return "ip:" + ("private" if ipv6_private(ip6) else "public") + suffix
    h = host[:-1] if host.endswith(".") else host
    labels = h.split(".")
    if any(lab == "" for lab in labels):
        return None
    if RE_IPV4.fullmatch(h):
        return "ip:" + ("private" if ipv4_private(bytes(int(x) for x in labels)) else "public") + suffix
    return ".".join(lab if host_label_safe(lab) else "{*}" for lab in labels) + suffix
