"""Shapes (sanitizer.md 6.2), recognized formats (6.3), length classes (0.3) and the
name rule (9.3 point 3).

All expressions are whole-string, ASCII-only matches (0.1): ``re.fullmatch`` with
explicit character classes, never ``$`` (which would accept a trailing newline).
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from .textutil import utf8_len


def len_class(n: int) -> str:
    if n <= 8:
        return "l8"
    if n <= 32:
        return "l32"
    if n <= 128:
        return "l128"
    if n <= 1024:
        return "l1024"
    return "lmax"


_PRINTABLE = re.compile(r"[\x20-\x7e]*")

RE_UUID = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")
RE_JWT = re.compile(r"eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
RE_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+")
RE_DATETIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt ][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?([Zz]|[+-][0-9]{2}:[0-9]{2})")
RE_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
RE_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]{0,15}://[!-~]+")
RE_IPV4 = re.compile(r"(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}")
RE_PHONE = re.compile(r"\+[1-9][0-9]{6,14}")
RE_DIGITS = re.compile(r"-?[0-9]{1,19}")
RE_HEX = re.compile(r"[0-9A-Fa-f]{16,}")

_FORMATS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("uuid", RE_UUID), ("jwt", RE_JWT), ("email", RE_EMAIL), ("datetime", RE_DATETIME), ("date", RE_DATE),
    ("url", RE_URL), ("ipv4", RE_IPV4), ("phone", RE_PHONE), ("digits", RE_DIGITS), ("hex", RE_HEX),
]


def is_printable_ascii(s: str) -> bool:
    return _PRINTABLE.fullmatch(s) is not None


def detect_format(s: str) -> Optional[str]:
    """First matching format of 6.3; only printable-ASCII strings are considered.

    Each expression is preceded by a cheap necessary condition (length, a fixed character)
    so that the common non-matching string costs a few comparisons, not ten regex runs.
    The result is identical to trying the expressions in order.
    """
    n = len(s)
    if n == 0 or not s.isascii() or not _PRINTABLE.fullmatch(s):
        return None
    if n == 36 and RE_UUID.fullmatch(s):
        return "uuid"
    if s.startswith("eyJ") and RE_JWT.fullmatch(s):
        return "jwt"
    if "@" in s and RE_EMAIL.fullmatch(s):
        return "email"
    if n >= 10 and s[4] == "-":
        if n >= 20 and RE_DATETIME.fullmatch(s):
            return "datetime"
        if n == 10 and RE_DATE.fullmatch(s):
            return "date"
    if "://" in s and RE_URL.fullmatch(s):
        return "url"
    if 7 <= n <= 15 and s.count(".") == 3 and RE_IPV4.fullmatch(s):
        return "ipv4"
    if s[0] == "+" and RE_PHONE.fullmatch(s):
        return "phone"
    if n <= 20 and RE_DIGITS.fullmatch(s):
        return "digits"
    if n >= 16 and RE_HEX.fullmatch(s):
        return "hex"
    return None


def str_shape(s: str) -> str:
    """The drop form of a well-formed string."""
    f = detect_format(s)
    if f is not None:
        return "drop:str:" + f
    return "drop:str:" + len_class(utf8_len(s))


_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}")
_SIX_DIGITS = re.compile(r"[0-9]{6}")
_HEADER_NAME_RE = re.compile(r"[a-z0-9!#$%&'*+.^_`|~-]{1,64}")


def _looks_like_value(s: str) -> bool:
    return bool(
        RE_UUID.fullmatch(s) or RE_EMAIL.fullmatch(s) or RE_HEX.fullmatch(s) or RE_DIGITS.fullmatch(s)
        or RE_JWT.fullmatch(s) or _SIX_DIGITS.search(s)
    )


# Names repeat constantly (JSON keys, header names): the verdict is cached, bounded.
_NAME_CACHE: dict = {}
_HDR_CACHE: dict = {}
_CACHE_MAX = 8192


def is_literal_name(s: str) -> bool:
    """9.3.3: a JSON key / query / cookie / form name leaves as a literal only if this holds."""
    r = _NAME_CACHE.get(s)
    if r is None:
        r = _KEY_RE.fullmatch(s) is not None and not _looks_like_value(s)
        if len(_NAME_CACHE) >= _CACHE_MAX:
            _NAME_CACHE.clear()
        _NAME_CACHE[s] = r
    return r


def header_out_name(lower: str) -> str:
    """8.0.2: output name of a lowercased header name."""
    r = _HDR_CACHE.get(lower)
    if r is None:
        r = "{*}" if (not _HEADER_NAME_RE.fullmatch(lower) or _looks_like_value(lower)) else lower
        if len(_HDR_CACHE) >= _CACHE_MAX:
            _HDR_CACHE.clear()
        _HDR_CACHE[lower] = r
    return r


PATH_TOKEN_RE = re.compile(r"[A-Za-z0-9._~-]{1,64}")
# Code shape of the code action (sanitizer.md 5.6, spec v1.11), used with fullmatch.
CODE_RE = re.compile(r"[A-Za-z_-]{2,32}")
AUTO_WORD_RE = re.compile(r"([a-z]+([-_][a-z]+)*|v[0-9]{1,3})")
# Shape alnum of the code action (sanitizer.md 5.6, spec v1.19), used with fullmatch.
CODE_ALNUM_RE = re.compile(r"[A-Za-z0-9_.-]{1,16}")
