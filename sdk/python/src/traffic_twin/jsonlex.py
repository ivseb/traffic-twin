"""Lexeme-preserving strict JSON tokenizer (sanitizer.md 9.2), canonical numbers (10.2)
and the tt-cjson writer (10.1).

The standard ``json`` module cannot be used for sanitizing: it recurses (deep documents
must still be validated), accepts NaN/Infinity, loses number lexemes and merges duplicate
keys. This parser is iterative, validates the whole input, rejects a leading BOM,
invalid UTF-8, control characters and everything outside RFC 8259, and keeps the number
lexeme as written.

Parsed tree: ``JObj`` (ordered ``(key, key_bad, value)`` members, duplicates kept),
``list`` for arrays, ``str`` for strings, ``Num`` for numbers, ``bool`` and ``None``.
A string that contains a lone surrogate (from an unpaired ``\\uD800``-``\\uDFFF`` escape)
is kept as a Python str holding that surrogate; ``lone_surrogate`` detects it.
"""

from __future__ import annotations

import re
from typing import Any, List, Optional, Tuple

from .textutil import lone_surrogate


class JsonError(Exception):
    pass


class Num:
    """A JSON number as written (the lexeme)."""

    __slots__ = ("lex",)

    def __init__(self, lex: str) -> None:
        self.lex = lex

    def __repr__(self) -> str:  # pragma: no cover
        return "Num(%s)" % self.lex


class JObj:
    """Object members in document order, duplicates included."""

    __slots__ = ("m",)

    def __init__(self) -> None:
        self.m: List[Tuple[str, bool, Any]] = []


_WS = re.compile(rb"[ \t\n\r]*")
_NUM = re.compile(rb"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
# A run of string bytes that needs no special handling.
_STR_RUN = re.compile(rb'[^"\\\x00-\x1f]*')
_HEX4 = re.compile(rb"[0-9A-Fa-f]{4}")
# A complete string without escapes, and a complete "key": prefix without escapes (the common cases).
_SIMPLE_STR = re.compile(rb'"([^"\\\x00-\x1f]*)"')
_SIMPLE_KEY = re.compile(rb'"([^"\\\x00-\x1f]*)"[ \t\n\r]*:[ \t\n\r]*')

_SIMPLE_ESC = {
    0x22: '"', 0x5C: "\\", 0x2F: "/", 0x62: "\b", 0x66: "\f", 0x6E: "\n", 0x72: "\r", 0x74: "\t",
}


def parse_json(buf: bytes) -> Any:
    """Parses a complete JSON document; raises JsonError on any deviation from RFC 8259."""
    n = len(buf)
    if buf[:3] == b"\xef\xbb\xbf":
        raise JsonError("bom")
    ws = _WS.match
    num_match = _NUM.match
    run_match = _STR_RUN.match
    pos = 0

    def read_string(i: int) -> Tuple[str, int]:
        # buf[i] == '"'
        i += 1
        out: List[str] = []
        while True:
            m = run_match(buf, i)
            j = m.end()
            if j > i:
                chunk = buf[i:j]
                try:
                    out.append(chunk.decode("utf-8"))
                except UnicodeDecodeError:
                    raise JsonError("invalid utf-8") from None
                i = j
            if i >= n:
                raise JsonError("unterminated string")
            c = buf[i]
            if c == 0x22:
                i += 1
                break
            if c < 0x20:
                raise JsonError("control character in string")
            # backslash
            e = buf[i + 1] if i + 1 < n else -1
            simple = _SIMPLE_ESC.get(e)
            if simple is not None:
                out.append(simple)
                i += 2
            elif e == 0x75:
                h = _HEX4.match(buf, i + 2)
                if not h:
                    raise JsonError("bad unicode escape")
                cp = int(buf[i + 2:i + 6], 16)
                i += 6
                if 0xD800 <= cp <= 0xDBFF and buf[i:i + 2] == b"\\u":
                    h2 = _HEX4.match(buf, i + 2)
                    if h2:
                        lo = int(buf[i + 2:i + 6], 16)
                        if 0xDC00 <= lo <= 0xDFFF:
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                            i += 6
                out.append(chr(cp))
            else:
                raise JsonError("bad escape")
        return "".join(out), i

    simple_str = _SIMPLE_STR.match
    simple_key = _SIMPLE_KEY.match

    def read_key(i: int) -> Tuple[str, int]:
        m = simple_key(buf, i)
        if m:
            try:
                return m.group(1).decode("utf-8"), m.end()
            except UnicodeDecodeError:
                raise JsonError("invalid utf-8") from None
        if i >= n or buf[i] != 0x22:
            raise JsonError("expected key")
        k, i = read_string(i)
        i = ws(buf, i).end()
        if i >= n or buf[i] != 0x3A:
            raise JsonError("expected colon")
        i = ws(buf, i + 1).end()
        return k, i

    # stack frames: [container, pending_key]
    stack: List[list] = []
    i = ws(buf, 0).end()
    while True:
        if i >= n:
            raise JsonError("unexpected end")
        c = buf[i]
        if c == 0x7B:  # {
            i = ws(buf, i + 1).end()
            o = JObj()
            if i < n and buf[i] == 0x7D:
                i += 1
                v: Any = o
            else:
                k, i = read_key(i)
                stack.append([o, k])
                continue
        elif c == 0x5B:  # [
            i = ws(buf, i + 1).end()
            a: list = []
            if i < n and buf[i] == 0x5D:
                i += 1
                v = a
            else:
                stack.append([a, None])
                continue
        elif c == 0x22:
            m = simple_str(buf, i)
            if m:
                try:
                    v, i = m.group(1).decode("utf-8"), m.end()
                except UnicodeDecodeError:
                    raise JsonError("invalid utf-8") from None
            else:
                v, i = read_string(i)
        elif c == 0x2D or 0x30 <= c <= 0x39:
            m = num_match(buf, i)
            if not m:
                raise JsonError("bad number")
            v = Num(m.group().decode("ascii"))
            i = m.end()
            # "01", "1.", "-" and similar leave a stray character the separator check rejects.
        elif buf.startswith(b"true", i):
            v, i = True, i + 4
        elif buf.startswith(b"false", i):
            v, i = False, i + 5
        elif buf.startswith(b"null", i):
            v, i = None, i + 4
        else:
            raise JsonError("unexpected character")
        # attach v to its parent, closing containers as needed
        while True:
            if not stack:
                i = ws(buf, i).end()
                if i != n:
                    raise JsonError("trailing data")
                return v
            f = stack[-1]
            cont = f[0]
            if isinstance(cont, JObj):
                k = f[1]
                cont.m.append((k, lone_surrogate(k), v))
            else:
                cont.append(v)
            i = ws(buf, i).end()
            d = buf[i] if i < n else -1
            if d == 0x2C:
                i = ws(buf, i + 1).end()
                if isinstance(cont, JObj):
                    f[1], i = read_key(i)
                break
            if (isinstance(cont, JObj) and d == 0x7D) or (isinstance(cont, list) and d == 0x5D):
                i += 1
                stack.pop()
                v = cont
                continue
            raise JsonError("expected separator")


# ---------------------------------------------------------------------------------
# Canonical numbers (10.2)

_INT_LEX = re.compile(r"-?(?:0|[1-9][0-9]*)")


def is_int_lexeme(lex: str) -> bool:
    return _INT_LEX.fullmatch(lex) is not None


def lexeme_within_limits(lex: str) -> bool:
    """5.3: lexeme of at most 64 bytes and |written exponent| <= 9999."""
    if len(lex) > 64:
        return False
    e = lex.find("e")
    if e < 0:
        e = lex.find("E")
    if e < 0:
        return True
    d = lex[e + 1:]
    if d[:1] in ("+", "-"):
        d = d[1:]
    d = d.lstrip("0")
    return len(d) <= 4


_NUM_PARTS = re.compile(r"(-?)([0-9]*)(?:\.([0-9]*))?(?:[eE]([+-]?[0-9]+))?")


def canonical_number(lex: str) -> str:
    """Canonical form of a valid JSON number lexeme, computed in exact decimal arithmetic."""
    m = _NUM_PARTS.fullmatch(lex)
    if not m:
        raise ValueError("not a number lexeme")
    neg = m.group(1) == "-"
    intp = m.group(2)
    frac = m.group(3) or ""
    exp = int(m.group(4)) if m.group(4) else 0
    digits = intp + frac
    exp -= len(frac)
    stripped = digits.lstrip("0")
    digits = stripped
    t = digits.rstrip("0")
    exp += len(digits) - len(t)
    digits = t
    if not digits:
        return "0"
    nd = len(digits)
    e = exp + nd
    if -6 < e <= 21:
        if e <= 0:
            out = "0." + "0" * (-e) + digits
        elif e >= nd:
            out = digits + "0" * (e - nd)
        else:
            out = digits[:e] + "." + digits[e:]
    else:
        k = e - 1
        out = digits[0] + ("." + digits[1:] if nd > 1 else "") + "e" + ("+" if k >= 0 else "-") + str(abs(k))
    return ("-" if neg else "") + out


# ---------------------------------------------------------------------------------
# tt-cjson writer (10.1)

class CNum:
    """A number already in canonical form (an output value)."""

    __slots__ = ("canon",)

    def __init__(self, canon: str) -> None:
        self.canon = canon


_NEEDS_ESCAPE = re.compile(r'["\\\x00-\x1f\x7f-\U0010ffff]')


def _esc(m: "re.Match[str]") -> str:
    ch = m.group()
    if ch == '"':
        return '\\"'
    if ch == "\\":
        return "\\\\"
    cp = ord(ch)
    if cp > 0xFFFF:
        cp -= 0x10000
        return "\\u%04x\\u%04x" % (0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF))
    return "\\u%04x" % cp


def write_string(s: str) -> str:
    if not _NEEDS_ESCAPE.search(s):
        return '"' + s + '"'
    return '"' + _NEEDS_ESCAPE.sub(_esc, s) + '"'


def write_canonical(v: Any) -> str:
    """Serializes an output tree (str, bool, None, CNum, list, dict) as tt-cjson."""
    if isinstance(v, str):
        return write_string(v)
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, CNum):
        return v.canon
    if isinstance(v, list):
        return "[" + ",".join([write_canonical(x) for x in v]) + "]"
    return "{" + ",".join([write_string(k) + ":" + write_canonical(v[k]) for k in sorted(v)]) + "}"


def to_out(node: Any) -> Any:
    """Parsed document to an output tree (numbers canonicalized)."""
    if isinstance(node, JObj):
        return {k: to_out(v) for k, _bad, v in node.m}
    if isinstance(node, list):
        return [to_out(x) for x in node]
    if isinstance(node, Num):
        return CNum(canonical_number(node.lex))
    return node


class StrictPlainError(JsonError):
    pass


def to_plain(node: Any, strict: bool = True) -> Any:
    """Parsed document to plain dict/list/str/bool/None with ``Num`` for numbers.

    ``strict`` (policy bodies and envelopes: fail closed) rejects duplicate keys and
    lone surrogates.
    """
    if isinstance(node, JObj):
        o: dict = {}
        for k, bad, v in node.m:
            if strict and (bad or k in o):
                raise StrictPlainError("duplicate or invalid key")
            o[k] = to_plain(v, strict)
        return o
    if isinstance(node, list):
        return [to_plain(x, strict) for x in node]
    if isinstance(node, str) and strict and lone_surrogate(node):
        raise StrictPlainError("lone surrogate")
    return node


def parse_plain(buf: bytes, strict: bool = True) -> Any:
    return to_plain(parse_json(buf), strict)
