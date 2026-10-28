"""Byte and text helpers with the exact semantics the sanitizer spec asks for.

Everything here is ASCII-only where the spec says so (lowercase, classes) and strict
RFC 3629 where UTF-8 is involved (sanitizer.md 0.1, 0.2).
"""

from __future__ import annotations

from typing import List, Optional
from urllib.parse import unquote_to_bytes

_LOWER = {c: c + 32 for c in range(0x41, 0x5B)}
_UPPER = {c: c - 32 for c in range(0x61, 0x7B)}


def ascii_lower(s: str) -> str:
    """Lowercase A-Z only; never touches other characters (str.lower() would)."""
    return s.translate(_LOWER)


def ascii_upper(s: str) -> str:
    return s.translate(_UPPER)


def decode_utf8(b: bytes) -> Optional[str]:
    """Strict UTF-8 (no overlong forms, no surrogates, no BOM handling); None if invalid."""
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return None


def utf8_len(s: str) -> int:
    return len(s) if s.isascii() else len(s.encode("utf-8"))


def trim_ows(b: bytes) -> bytes:
    """Strips spaces and horizontal tabs on both sides."""
    return b.strip(b" \t")


def pct_decode(b: bytes, plus_is_space: bool) -> bytes:
    """4.1 percent-decoding; an invalid ``%`` stays literal; ``+`` only if asked (8.3)."""
    if plus_is_space and b"+" in b:
        b = b.replace(b"+", b" ")
    if b"%" not in b:
        return b
    return unquote_to_bytes(b)


def split_bytes(b: bytes, sep: bytes) -> List[bytes]:
    return b.split(sep)


def lone_surrogate(s: str) -> bool:
    """True if the str holds a surrogate code point (it has no UTF-8 encoding)."""
    for ch in s:
        if "\ud800" <= ch <= "\udfff":
            return True
    return False
