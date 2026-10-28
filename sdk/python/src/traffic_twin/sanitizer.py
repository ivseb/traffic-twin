"""The sanitizer, docs/spec/sanitizer.md (v1.19: code(alnum), XML and SOAP, multipart,
base64 documents and large bodies, section 20).

Input: one normalized exchange (section 1), a verified compiled policy, the local HMAC
key and the clock. Output: the canonical object of section 2, or ``not_sampled``.

Guiding rule: in doubt, drop. Any exception escaping from here is an internal error for
the caller (no event, ``sanitizer_errors`` + 1).
"""

from __future__ import annotations

import base64
import hmac as _hmac
import random as _random
import re
import zlib
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from . import bodies as B
from . import gqlshape
from .formats import (
    AUTO_WORD_RE, CODE_ALNUM_RE, CODE_RE, PATH_TOKEN_RE, RE_DATE, RE_DATETIME, detect_format, header_out_name,
    is_literal_name, is_printable_ascii, len_class, str_shape,
)
from .jsonlex import (
    CNum, JObj, JsonError, Num, canonical_number, is_int_lexeme, lexeme_within_limits, parse_json, write_canonical,
    write_string,
)
from .hostpat import host_pattern, parse_ipv6
from .policy import Action, BodyRule, Op, Part, Policy, Service, TemplateSeg, b64url_decode_strict
from .textutil import (
    ascii_lower, ascii_upper, decode_utf8, lone_surrogate, pct_decode, trim_ows, utf8_len,
)

MAX_EVENT_BYTES = 524288
MAX_SEGMENTS = 32
MAX_NAMES = 64
MAX_DISC = 4096
GQL_INTROSPECTION_MAX_ARRAY = 4096  # 5.7.2: response body array limit with the gate open
SUBJECT_MAX = 8192

_MISSING = object()

NET_ERRORS = ("timeout", "reset", "refused", "dns", "tls", "other")


class Exchange:
    """Normalized exchange (sanitizer.md 1). Header lists hold ``(name: str, value: bytes)``."""

    __slots__ = (
        "dir", "service_name", "url_base", "method", "raw_path", "raw_query", "framework", "framework_route",
        "trace_id", "inherited", "req_headers", "req_body", "req_body_total", "req_body_consumed",
        "req_body_decoded", "status", "net_error", "resp_headers", "resp_body", "resp_body_total",
        "resp_body_consumed", "resp_body_decoded",
    )

    def __init__(self, dir: str = "inbound", method: str = "", raw_path: bytes = b"") -> None:
        self.dir = dir
        self.service_name: Optional[str] = None
        self.url_base: Optional[str] = None
        self.method = method
        self.raw_path = raw_path
        self.raw_query: Optional[bytes] = None  # None = the URL had no "?"
        self.framework: Optional[str] = None
        self.framework_route: Optional[str] = None
        self.trace_id: Optional[str] = None
        self.inherited: Optional[bool] = None
        self.req_headers: List[Tuple[str, bytes]] = []
        self.req_body: bytes = b""
        self.req_body_total: Union[int, str, None] = None  # int | "unknown" | None (= len(req_body))
        self.req_body_consumed: Optional[bool] = None
        self.req_body_decoded: Optional[bool] = None
        self.status: Optional[int] = None
        self.net_error: Optional[str] = None
        self.resp_headers: List[Tuple[str, bytes]] = []
        self.resp_body: bytes = b""
        self.resp_body_total: Union[int, str, None] = None
        self.resp_body_consumed: Optional[bool] = None
        self.resp_body_decoded: Optional[bool] = None


class Decision:
    __slots__ = ("sampled", "by")

    def __init__(self, sampled: bool, by: str) -> None:
        self.sampled = sampled
        self.by = by


class Result:
    """``outcome`` is ``event``, ``not_sampled`` or ``too_large`` (10.3 step 4)."""

    __slots__ = ("outcome", "sampled_by", "out", "parts", "canonical")

    def __init__(self, outcome: str, sampled_by: str, out: Optional[dict] = None,
                 parts: Optional[Dict[str, str]] = None, canonical: str = "") -> None:
        self.outcome = outcome
        self.sampled_by = sampled_by
        self.out = out
        self.parts = parts
        self.canonical = canonical


# ---------------------------------------------------------------------------------
# Header normalization (8.0)


class _HdrEntry:
    __slots__ = ("out", "values", "origs")

    def __init__(self, out: str) -> None:
        self.out = out
        self.values: List[bytes] = []
        self.origs: Set[str] = set()


class Headers:
    __slots__ = ("order", "map")

    def __init__(self) -> None:
        self.order: List[str] = []
        self.map: Dict[str, _HdrEntry] = {}


def _name_str(n: Any) -> str:
    return n.decode("latin-1") if isinstance(n, (bytes, bytearray)) else n


def normalize_headers(items: Optional[List[Tuple[Any, bytes]]]) -> Headers:
    h = Headers()
    for name, value in items or ():
        name = _name_str(name)
        if name[:1] == ":":
            continue
        lower = ascii_lower(name)
        out = header_out_name(lower)
        e = h.map.get(out)
        if e is None:
            e = _HdrEntry(out)
            h.map[out] = e
            h.order.append(out)
        e.values.append(trim_ows(bytes(value)))
        e.origs.add(lower)
    return h


def _joined(e: _HdrEntry) -> bytes:
    if len(e.values) == 1:
        return e.values[0]
    return (b"; " if e.out == "cookie" else b", ").join(e.values)


def header_value(items: Optional[List[Tuple[Any, bytes]]], lower: str) -> Optional[bytes]:
    """Joined value of one exact lowercase header name (subject, baggage)."""
    vals = []
    for n, v in items or ():
        n = _name_str(n)
        if n[:1] == ":":
            continue
        if ascii_lower(n) == lower:
            vals.append(trim_ows(bytes(v)))
    if not vals:
        return None
    if len(vals) == 1:
        return vals[0]
    return (b"; " if lower == "cookie" else b", ").join(vals)


_CT_RE = re.compile(r"[a-z0-9.+-]{1,64}/[a-z0-9.+-]{1,64}")


def content_type(h: Headers) -> Optional[str]:
    """8.1.5"""
    e = h.map.get("content-type")
    if e is None:
        return None
    v = _joined(e)
    semi = v.find(b";")
    if semi >= 0:
        v = v[:semi]
    s = ascii_lower(trim_ows(v).decode("latin-1"))
    return s if _CT_RE.fullmatch(s) else "invalid"


def content_encoding(h: Headers) -> Optional[str]:
    e = h.map.get("content-encoding")
    if e is None:
        return None
    return ascii_lower(trim_ows(_joined(e)).decode("latin-1"))


# ---------------------------------------------------------------------------------
# Path (4.1) and routing (3)


def decompose_path(raw: bytes) -> Tuple[List[Optional[str]], bool]:
    """Returns (decoded segments, truncated); a segment is None when not valid UTF-8."""
    segs: List[Optional[str]] = []
    truncated = False
    for s in raw.split(b"/"):
        if not s:
            continue
        if len(segs) == MAX_SEGMENTS:
            truncated = True
            break
        segs.append(decode_utf8(pct_decode(s, False)))
    return segs, truncated


_URL_BASE = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*)://(.*)", re.S)
_BAD_REST = re.compile(r"[@/?#]")
_PORT = re.compile(r"[0-9]{1,5}")
_HOST = re.compile(r"[a-z0-9.-]{1,253}")


class UrlBase:
    """``host`` is the normalized host without port (an IPv6 literal keeps its lowercase text, without
    brackets); ``port`` is None when absent or the scheme default; ``ip6`` holds the 16 bytes of a
    bracketed IPv6 literal (3.1 point 5, spec v1.5), else None."""

    __slots__ = ("invalid", "origin", "hostport", "host", "port", "ip6")

    def __init__(self, invalid: bool, origin: str = "", hostport: str = "", host: str = "",
                 port: Optional[str] = None, ip6: Optional[bytes] = None) -> None:
        self.invalid = invalid
        self.origin = origin
        self.hostport = hostport
        self.host = host
        self.port = port
        self.ip6 = ip6


_BAD_URL = UrlBase(True)


def normalize_url_base(u: Optional[str]) -> UrlBase:
    """3.1 normalization of ``url_base``."""
    if not isinstance(u, str):
        return _BAD_URL
    m = _URL_BASE.fullmatch(u)
    if not m:
        return _BAD_URL
    scheme = ascii_lower(m.group(1))
    rest = m.group(2)
    if _BAD_REST.search(rest):
        return _BAD_URL
    port_text: Optional[str] = None
    ip6: Optional[bytes] = None
    if rest.startswith("["):
        # IPv6 literal: "]" required, then the end or ":port".
        end = rest.find("]")
        if end < 0:
            return _BAD_URL
        host = ascii_lower(rest[1:end])
        ip6 = parse_ipv6(host)
        if ip6 is None:
            return _BAD_URL
        tail = rest[end + 1:]
        if tail.startswith(":"):
            port_text = tail[1:]
        elif tail != "":
            return _BAD_URL
        shown = "[" + host + "]"
    else:
        host = rest
        c = rest.rfind(":")
        if c >= 0:
            host = rest[:c]
            port_text = rest[c + 1:]
        host = ascii_lower(host)
        if not _HOST.fullmatch(host):
            return _BAD_URL
        shown = host
    port: Optional[str] = None
    if port_text is not None:
        if not _PORT.fullmatch(port_text):
            return _BAD_URL
        pn = int(port_text)
        if pn < 1 or pn > 65535:
            return _BAD_URL
        port = str(pn)  # A-PORT-ZEROS
        if (scheme == "http" and pn == 80) or (scheme == "https" and pn == 443):
            port = None
    hostport = shown + ":" + port if port else shown
    return UrlBase(False, scheme + "://" + hostport, hostport, host, port, ip6)


FRAMEWORKS = frozenset([
    "express", "koa", "fastify", "flask", "fastapi", "django", "spring", "jaxrs",
    "aspnetcore", "gin", "chi", "nethttp", "laravel", "symfony",
])

_N = r"[A-Za-z_][A-Za-z0-9_]{0,63}"
_RE_COLON = re.compile(r":(" + _N + r")")
_RE_COLON_REGEX = re.compile(r":(" + _N + r")\((.*)\)", re.S)
_RE_ANGLE = re.compile(r"<(?:([A-Za-z_][A-Za-z0-9_]*):)?(" + _N + r")>")
_RE_BRACE = re.compile(r"\{(" + _N + r")\}")
_RE_BRACE_CONV = re.compile(r"\{(" + _N + r"):(.+)\}", re.S)
_RE_BRACE_SYMFONY = re.compile(r"\{(" + _N + r")<(.+)>\}", re.S)
_RE_PNAME = re.compile(_N)
_RE_ESC_PAIR = re.compile(r"\\.", re.S)
_RE_PARAM_IN_REGEX = re.compile(r":[A-Za-z_]")


def _framework_param(fw: str, s: str) -> Optional[str]:
    """The parameter name of one framework-route segment, or None when it is not a
    parameter syntax of that framework."""
    if fw in ("express", "koa", "fastify"):
        m = _RE_COLON.fullmatch(s)
        if m:
            return m.group(1)
        m = _RE_COLON_REGEX.fullmatch(s)
        if m and not _RE_PARAM_IN_REGEX.search(_RE_ESC_PAIR.sub("", m.group(2))):
            return m.group(1)
        return None
    if fw == "gin":
        m = _RE_COLON.fullmatch(s)
        return m.group(1) if m else None
    if fw in ("flask", "django"):
        m = _RE_ANGLE.fullmatch(s)
        return m.group(2) if m and m.group(1) != "path" else None
    if fw == "fastapi":
        m = _RE_BRACE.fullmatch(s)
        if m:
            return m.group(1)
        m = _RE_BRACE_CONV.fullmatch(s)
        return m.group(1) if m and m.group(2) != "path" else None
    if fw in ("spring", "chi"):
        m = _RE_BRACE.fullmatch(s)
        if m:
            return m.group(1)
        m = _RE_BRACE_CONV.fullmatch(s)
        return m.group(1) if m else None
    if fw == "jaxrs":
        if not (s.startswith("{") and s.endswith("}")):
            return None
        inner = s[1:-1]
        c = inner.find(":")
        name = (inner if c < 0 else inner[:c]).strip(" \t\n\r\f\v")
        if not _RE_PNAME.fullmatch(name):
            return None
        if c >= 0 and inner[c + 1:].strip(" \t\n\r\f\v") == "":
            return None
        return name
    if fw == "aspnetcore":
        m = _RE_BRACE.fullmatch(s)
        if m:
            return m.group(1)
        m = _RE_BRACE_CONV.fullmatch(s)
        if m and not m.group(2).endswith("?") and "=" not in m.group(2):
            return m.group(1)
        return None
    if fw in ("nethttp", "laravel"):
        m = _RE_BRACE.fullmatch(s)
        return m.group(1) if m else None
    if fw == "symfony":
        m = _RE_BRACE.fullmatch(s)
        if m:
            return m.group(1)
        m = _RE_BRACE_SYMFONY.fullmatch(s)
        return m.group(1) if m else None
    return None


def normalize_framework_route(route: str, framework: str) -> Optional[List[TemplateSeg]]:
    """3.4 with A-FRAMEWORK-ID: every segment must be a parameter syntax of that framework
    or a literal of the operation-key grammar; anything else fails."""
    if framework not in FRAMEWORKS:
        return None
    raw = [s for s in route.split("/") if s != ""]
    out: List[TemplateSeg] = []
    for i, s in enumerate(raw):
        if framework == "nethttp" and s == "{$}" and i == len(raw) - 1:
            continue
        p = _framework_param(framework, s)
        if p is not None:
            out.append(TemplateSeg(param=p))
        elif PATH_TOKEN_RE.fullmatch(s):
            out.append(TemplateSeg(lit=s))
        else:
            return None
    return None if len(out) > MAX_SEGMENTS else out


# ---------------------------------------------------------------------------------
# Buckets (5.5)

_DIM = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _days_from_civil(y: int, m: int, d: int) -> int:
    y -= 1 if m <= 2 else 0
    era = y // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _civil_from_days(z: int) -> Tuple[int, int, int]:
    z += 719468
    era = z // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + (3 if mp < 10 else -9)
    return (y + 1 if m <= 2 else y), m, d


_TIME_PARSE = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})(?:[Tt ]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]{1,9})?(?:[Zz]|([+-])([0-9]{2}):([0-9]{2})))?"
)


def bucket_time(s: str, unit: str) -> Optional[str]:
    if not is_printable_ascii(s) or not (RE_DATETIME.fullmatch(s) or RE_DATE.fullmatch(s)):
        return None
    m = _TIME_PARSE.fullmatch(s)
    if not m:
        return None
    y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
    h = int(m.group(4)) if m.group(4) else 0
    mi = int(m.group(5)) if m.group(5) else 0
    se = int(m.group(6)) if m.group(6) else 0
    if y < 1 or y > 9999 or mo < 1 or mo > 12 or d < 1:
        return None
    leap = (y % 4 == 0 and y % 100 != 0) or y % 400 == 0
    dim = 29 if (mo == 2 and leap) else _DIM[mo - 1]
    if d > dim or h > 23 or mi > 59 or se > 59:
        return None
    off = 0
    if m.group(7):
        oh, om = int(m.group(8)), int(m.group(9))
        if oh > 23 or om > 59:
            return None
        off = (oh * 60 + om) * (1 if m.group(7) == "+" else -1)
    total = _days_from_civil(y, mo, d) * 1440 + h * 60 + mi - off
    days = total // 1440
    hour = (total - days * 1440) // 60
    uy, um, ud = _civil_from_days(days)
    if uy < 1 or uy > 9999:
        return None
    ys = "%04d" % uy
    if unit == "year":
        return "time:" + ys
    if unit == "month":
        return "time:%s-%02d" % (ys, um)
    if unit == "day":
        return "time:%s-%02d-%02d" % (ys, um, ud)
    if unit == "hour":
        return "time:%s-%02d-%02dT%02d" % (ys, um, ud, hour)
    return None


def bucket_num(lex: str, a: Action) -> str:
    b = a.bounds
    v = float(lex)
    if v < b[0].d:
        return "num:<" + b[0].canon
    for i in range(len(b) - 1):
        if b[i].d <= v < b[i + 1].d:
            return "num:" + b[i].canon + "-" + b[i + 1].canon
    return "num:>=" + b[-1].canon


# ---------------------------------------------------------------------------------
# Body decoding (9.0)


def decode_body(data: bytes, zlib_format: bool, cap: int):
    """One level of gzip/deflate with an output cap (A-GZIP-STRICT). Returns the decoded
    bytes, ``'cap'`` when the output reaches ``cap`` bytes, or None on any error
    (truncated stream, bytes after the end of the stream, corrupt data)."""
    try:
        d = zlib.decompressobj(zlib.MAX_WBITS if zlib_format else 16 + zlib.MAX_WBITS)
        out = d.decompress(data, cap)
        if len(out) >= cap:
            return "cap"
        if not d.eof or d.unused_data or d.unconsumed_tail:
            return None
        return out
    except (zlib.error, ValueError):
        return None


# ---------------------------------------------------------------------------------
# Sanitizer


class _Named:
    """``token``: a ready output token (a multipart file part, 22.3), else None."""

    __slots__ = ("orig", "out", "value", "no_eq", "token")

    def __init__(self, orig: Optional[str], out: str, value: bytes, no_eq: bool, token: Optional[str] = None) -> None:
        self.orig = orig
        self.out = out
        self.value = value
        self.no_eq = no_eq
        self.token = token


def xml_key_is_literal(k: str) -> bool:
    """22.2 point 8: keys of an XML tree (#text, @ + attribute name, element name)."""
    if k == "#text":
        return True
    if k[:1] == "@":
        return is_literal_name(k[1:])
    return is_literal_name(k)


_BEARER = re.compile(r"bearer[ \t]+", re.I | re.A)
_TRAILING_PAD = re.compile(r"={1,2}\Z")
_STR_ACTIONS = ("keep", "code", "hmac", "bucket")


_B64_ANY = re.compile(r"[A-Za-z0-9_+/-]*")


def _b64_any(s: str) -> Optional[bytes]:
    """Standard or URL-safe base64 (never mixed), with or without padding (at most two '=' at the end, then a
    length that is a multiple of 4). None on any other character or an impossible length."""
    body = s
    k = 0
    while k < 2 and body.endswith("="):
        body = body[:-1]
        k += 1
    if body == "" or (len(s) != len(body) and len(s) % 4 != 0):
        return None
    if _B64_ANY.fullmatch(body) is None or len(body) % 4 == 1:
        return None
    std = "+" in body or "/" in body
    if std and ("-" in body or "_" in body):
        return None
    padded = body + "=" * (-len(body) % 4)
    try:
        return base64.b64decode(padded, validate=True) if std else base64.urlsafe_b64decode(padded)
    except Exception:  # noqa: BLE001
        return None


def _json_member(s: str, path: str) -> Optional[bytes]:
    """Spec v1.18 (sanitizer.md 11, step 4 bis): the subject is a member of a header whose value is a JSON object,
    or base64/base64url of one. No bearer prefix is stripped; the dot always separates members."""
    s = s.strip(" \t")
    if s == "":
        return None
    if s[0] == "{":
        data: Optional[bytes] = s.encode("utf-8")
    else:
        data = _b64_any(s)
    if data is None:
        return None
    try:
        v: Any = parse_json(data)
    except JsonError:
        return None
    for name in path.split("."):
        if not isinstance(v, JObj):
            return None
        found: Any = _MISSING
        for k, bad, val in v.m:
            if not bad and k == name:
                found = val
        if found is _MISSING:
            return None
        v = found
    if isinstance(v, str):
        return v.encode("utf-8") if v != "" and not lone_surrogate(v) else None
    if isinstance(v, Num):
        return canonical_number(v.lex).encode("ascii") if lexeme_within_limits(v.lex) else None
    return None


class Sanitizer:
    def __init__(self, policy: Policy, kid: str, key: bytes, rand: Optional[Callable[[], float]] = None,
                 rate_override_bp: Optional[int] = None) -> None:
        self.policy = policy
        self.kid = kid
        self.key = key
        self.rand = rand or _random.random
        self.rate_override_bp = rate_override_bp
        self._epoch = policy.epoch.encode("latin-1")

    # --- HMAC -----------------------------------------------------------------------

    def mac(self, domain: str, value: bytes) -> bytes:
        return _hmac.digest(self.key, self._epoch + b"\x00" + domain.encode("latin-1") + b"\x00" + value, "sha256")

    def token(self, domain: str, value: bytes) -> str:
        return "tk1:" + self.kid + ":" + base64.urlsafe_b64encode(self.mac(domain, value)[:16]).rstrip(b"=").decode("ascii")

    def rate_bp(self) -> int:
        o = self.rate_override_bp
        return min(o, self.policy.rate_bp) if isinstance(o, int) else self.policy.rate_bp

    # --- subject (11) ---------------------------------------------------------------

    def subject_value(self, req_headers: Optional[List[Tuple[Any, bytes]]]) -> Optional[bytes]:
        spec = self.policy.subject
        if spec is None:
            return None
        raw: Optional[bytes] = None
        if spec.frm == "header":
            raw = header_value(req_headers, ascii_lower(spec.name))
        else:
            cookie = header_value(req_headers, "cookie")
            if cookie:
                for p in cookie.split(b";"):
                    piece = trim_ows(p)
                    eq = piece.find(b"=")
                    if eq < 0:
                        continue
                    if decode_utf8(piece[:eq]) == spec.name:
                        raw = piece[eq + 1:]
                        break
        if raw is None or len(raw) == 0 or len(raw) > SUBJECT_MAX:
            return None
        s = decode_utf8(raw)
        if s is None or s == "":
            return None
        if spec.frm == "header" and spec.json_path is not None:
            return _json_member(s, spec.json_path)
        if spec.frm == "header":
            m = _BEARER.match(s)
            if m:
                s = s[m.end():]
                if s == "":
                    return None
        if spec.jwt_claim is None:
            return s.encode("utf-8")
        parts = s.split(".")
        if len(parts) != 3:
            return None
        payload = _TRAILING_PAD.sub("", parts[1])
        data = b64url_decode_strict(payload)
        if data is None:
            return None
        try:
            doc = parse_json(data)
        except JsonError:
            return None
        if not isinstance(doc, JObj):
            return None
        v: Any = _MISSING
        for k, bad, val in doc.m:
            if not bad and k == spec.jwt_claim:
                v = val
        if v is _MISSING:
            return None
        if isinstance(v, str):
            return v.encode("utf-8") if v != "" and not lone_surrogate(v) else None
        if isinstance(v, Num):
            return canonical_number(v.lex).encode("ascii") if lexeme_within_limits(v.lex) else None
        return None

    # --- sampling (12) --------------------------------------------------------------

    def _hash_sample(self, domain: str, value: bytes) -> bool:
        return int.from_bytes(self.mac(domain, value)[:4], "big") % 10000 < self.rate_bp()

    def _random_sample(self) -> bool:
        rate = self.rate_bp()
        if rate <= 0:
            return False
        if rate >= 10000:
            return True
        return int(self.rand() * 10000) < rate

    def decide(self, ex: Exchange, subject: Any = None) -> Decision:
        """Sampling decision for an exchange (needs only the request line and headers).
        ``subject`` may be passed when already computed (``None`` = no subject)."""
        return self.decide_parts(ex.dir, ex.service_name, ex.req_headers, ex.trace_id, ex.inherited,
                                 _MISSING if subject is None else subject)

    def decide_parts(self, dir: str, service_name: Optional[str], req_headers: Optional[List[Tuple[Any, bytes]]],
                     trace_id: Optional[str], inherited: Optional[bool], subject: Any = _MISSING) -> Decision:
        """Same as ``decide`` without building an ``Exchange`` (hot path). ``subject`` is
        ``_MISSING`` (compute it), ``None`` (no subject) or the subject bytes."""
        if dir == "inbound":
            svc = self.policy.inbound.get(service_name) if service_name is not None else None
            if self.policy.trust_baggage and svc is not None and svc.internal:
                bag = header_value(req_headers, "baggage")
                s = decode_utf8(bag) if bag else None
                if s is not None:
                    for member in s.split(","):
                        kv = member.split(";", 1)[0].strip(" \t")
                        eq = kv.find("=")
                        if eq < 0:
                            continue
                        k = kv[:eq].strip(" \t")
                        v = kv[eq + 1:].strip(" \t")
                        if k == "tt.s" and v in ("0", "1"):
                            return Decision(v == "1", "baggage")
            subj = self.subject_value(req_headers) if subject is _MISSING else subject
            if subj:
                return Decision(self._hash_sample("sample", subj), "subject")
        elif isinstance(inherited, bool):
            return Decision(inherited, "inherited")
        if trace_id:
            return Decision(self._hash_sample("sample-trace", ascii_lower(trace_id).encode("latin-1")), "trace")
        return Decision(self._random_sample(), "random")

    # --- whole exchange -------------------------------------------------------------

    def run(self, ex: Exchange, now: Optional[float], decision: Optional[Decision] = None) -> Result:
        subject = self.subject_value(ex.req_headers)
        d = decision if decision is not None else self.decide_parts(
            ex.dir, ex.service_name, ex.req_headers, ex.trace_id, ex.inherited, subject)
        if not d.sampled:
            return Result("not_sampled", d.by)
        out = _Run(self, ex, now).build(d.by, subject)
        parts = {k: write_canonical(v) for k, v in out.items()}
        canonical = compose_canonical(parts)
        if len(canonical) > MAX_EVENT_BYTES:  # 10.3 on the sanitizer output (A-EVENT-SIZE-BASE)
            for key in ("req", "resp", "disc"):
                if key == "disc":
                    changed = out.pop("disc", None) is not None
                else:
                    side = out.get(key)
                    changed = isinstance(side, dict) and "body" in side
                    if changed:
                        side["body"] = "trunc:size"
                if not changed:
                    continue
                if key in out:
                    parts[key] = write_canonical(out[key])
                else:
                    parts.pop(key, None)
                canonical = compose_canonical(parts)
                if len(canonical) <= MAX_EVENT_BYTES:
                    break
            if len(canonical) > MAX_EVENT_BYTES:
                return Result("too_large", d.by)
        return Result("event", d.by, out, parts, canonical)



def compose_canonical(parts: Dict[str, str]) -> str:
    """tt-cjson object from already serialized members (keys sorted by bytes)."""
    return "{" + ",".join([write_string(k) + ":" + parts[k] for k in sorted(parts)]) + "}"


class _Run:
    """Per-exchange state."""

    def __init__(self, s: Sanitizer, ex: Exchange, now: Optional[float]) -> None:
        self.s = s
        self.ex = ex
        self.p = s.policy
        self.disc: Optional[Dict[str, bytes]] = {} if self.p.discovery_active(now) else None
        self.auto_words = self.p.auto_words_active(now)
        self.svc: Optional[Service] = None
        self.op: Optional[Op] = None
        self.docs = self.p.bodies.docs
        # Per body being walked (22.2, 22.5): XML key rule, large-body array caps.
        self.xml_keys = False
        self.large = False
        self.max_array = self.p.limits.max_array
        # 5.7 (spec v1.14): resp is set while the response is sanitized; gql_seen and
        # gql_nonintro record the request values with a graphql rule (introspection gate).
        self.resp = False
        self.gql_seen = False
        self.gql_nonintro = False

    def build(self, by: str, subject: Optional[bytes]) -> dict:
        ex, p = self.ex, self.p
        method = ascii_upper(ex.method or "")
        if not re.fullmatch(r"[A-Z]{1,16}", method):
            method = "OTHER"
        segs, truncated = decompose_path(ex.raw_path or b"")

        # 3.1 service
        base_count = 0
        if ex.dir == "inbound":
            service = ex.service_name or ""
            self.svc = p.inbound.get(service)
        else:
            ub = normalize_url_base(ex.url_base)
            best: Optional[Service] = None
            if not ub.invalid:
                for svc in p.services:
                    if svc.base_origin is None or svc.base_origin != ub.origin:
                        continue
                    bs = svc.base_segs
                    if len(bs) > len(segs):
                        continue
                    if all(segs[i] == bs[i] for i in range(len(bs))) and (best is None or len(bs) > len(best.base_segs)):
                        best = svc
            if best is not None:
                self.svc = best
                service = best.name
                base_count = len(best.base_segs)
            elif ub.invalid:
                service = "host:invalid"
            elif ub.ip6 is None and ub.hostport in p.hosts_allow:
                service = "host:" + ub.hostport
            elif p.hosts_auto or self.disc is not None:
                # v1.5: the host leaves as a pattern, never in clear (3.5). An empty label is invalid.
                pat = host_pattern(ub.host, ub.port, ub.ip6)
                service = "host:invalid" if pat is None else "host:" + pat
            else:
                service = "host:unlisted"

        # 3.3 template
        op_segs = segs[base_count:]
        route_source = "raw"
        if self.svc is not None and method != "OTHER" and not truncated:
            if ex.dir == "inbound" and isinstance(ex.framework_route, str) and isinstance(ex.framework, str):
                fr = normalize_framework_route(ex.framework_route, ex.framework)
                if fr is not None and len(fr) == len(op_segs):
                    for op in self.svc.ops:
                        if op.method != method or len(op.segs) != len(fr):
                            continue
                        if all((fr[i].lit == t.lit) if t.lit is not None else (fr[i].param is not None)
                               for i, t in enumerate(op.segs)):
                            self.op = op
                            route_source = "framework"
                            break
            if self.op is None:
                best_op: Optional[Op] = None
                for op in self.svc.ops:
                    if op.method != method or len(op.segs) != len(op_segs):
                        continue
                    ok = True
                    for i, t in enumerate(op.segs):
                        sd = op_segs[i]
                        if t.lit is not None:
                            if sd != t.lit:
                                ok = False
                                break
                        elif sd is None:
                            ok = False
                            break
                    if not ok:
                        continue
                    if (best_op is None or op.literals > best_op.literals
                            or (op.literals == best_op.literals and op.key.encode("utf-8") < best_op.key.encode("utf-8"))):
                        best_op = op
                if best_op is not None:
                    self.op = best_op
                    route_source = "policy"

        # 4.2 path
        out_segs: List[str] = []
        for i, dec in enumerate(segs):
            if dec is None:
                out_segs.append("{drop:bytes}")
                continue
            if i < base_count:
                out_segs.append(dec)
                continue
            if self.op is not None:
                t = self.op.segs[i - base_count]
                if t.lit is not None:
                    out_segs.append(t.lit)
                    continue
                action = self.op.request.path.get(t.param) if self.op.request else None
                out_segs.append("{" + self._str_action(dec, action, True, "req.path.%d" % i) + "}")
                continue
            if dec in p.allow or (self.auto_words and AUTO_WORD_RE.fullmatch(dec) and utf8_len(dec) <= 40):
                out_segs.append(dec)
                continue
            out_segs.append("{" + self._str_action(dec, None, True, "req.path.%d" % i) + "}")
        if truncated:
            out_segs.append("{trunc}")
        path = "/" + "/".join(out_segs)
        op_str = self.op.key if self.op is not None else method + " /" + "/".join(out_segs[base_count:])

        out: dict = {"service": service, "op": op_str, "route_source": route_source, "sampled_by": by}

        req: dict = {"path": path}
        req_groups = self._groups("req", None)
        if ex.raw_query is not None:
            q = self._named_map(parse_urlencoded(ex.raw_query), req_groups, "query", "req.query")
            if q:
                req["query"] = q
        rh = normalize_headers(ex.req_headers)
        self._side(req, "req", rh, req_groups, ex.req_body, ex.req_body_total, ex.req_body_consumed, ex.req_body_decoded)
        out["req"] = req

        self.resp = True
        if ex.net_error is None:
            resp: dict = {}
            resp_groups = self._groups("resp", ex.status)
            sh = normalize_headers(ex.resp_headers)
            self._side(resp, "resp", sh, resp_groups, ex.resp_body, ex.resp_body_total, ex.resp_body_consumed, ex.resp_body_decoded)
            out["resp"] = resp
        if subject:
            out["subject"] = self.s.token("subject", subject)
        if self.disc:
            d: dict = {}
            for k in sorted(self.disc)[:MAX_DISC]:
                mac = self.s.mac("discovery", k.encode("utf-8") + b"\x00" + self.disc[k])
                d[k] = "tkd:" + base64.urlsafe_b64encode(mac[:4]).rstrip(b"=").decode("ascii")
            out["disc"] = d
        return out

    def _groups(self, side: str, status: Optional[int]) -> List[Optional[Part]]:
        err = side == "resp" and isinstance(status, int) and status >= 400
        p, op, svc = self.p, self.op, self.svc
        if side == "req":
            return [op.request if op else None, None, None, svc.request if svc else None, p.g_request]
        return [
            op.response if op else None,
            svc.errors if err and svc else None,
            p.g_errors if err else None,
            svc.response if svc else None,
            p.g_response,
        ]

    def _side(self, dst: dict, side: str, h: Headers, groups: List[Optional[Part]], body: Optional[bytes],
              total: Union[int, str, None], consumed: Optional[bool], decoded: Optional[bool]) -> None:
        # 8.1 headers (cookie / set-cookie never appear)
        entries: List[_Named] = []
        for name in h.order:
            if name == "cookie" or name == "set-cookie":
                continue
            e = h.map[name]
            orig = next(iter(e.origs)) if len(e.origs) == 1 else None
            entries.append(_Named(orig, name, _joined(e), False))
        hm = self._named_map(entries, groups, "headers", side + ".headers")
        if hm:
            dst["headers"] = hm

        # 8.2 cookies
        ck: List[_Named] = []
        if side == "req":
            e = h.map.get("cookie")
            if e is not None:
                for piece in _joined(e).split(b";"):
                    _cookie_part(trim_ows(piece), ck)
        else:
            e = h.map.get("set-cookie")
            if e is not None:
                for v in e.values:
                    semi = v.find(b";")
                    _cookie_part(trim_ows(v[:semi] if semi >= 0 else v), ck)
        cm = self._named_map(ck, groups, "cookies", side + ".cookies")
        if cm:
            dst["cookies"] = cm

        ct = content_type(h)
        if ct is not None:
            dst["ct"] = ct
        kind = self._treatment(ct)
        if side == "req" and kind == "xml":
            self._soap_action(dst, h)
        saved = self.max_array
        if self.resp and self._gql_gate():
            # 5.7.2: an introspection result keeps its arrays (response body only).
            self.max_array = max(saved, GQL_INTROSPECTION_MAX_ARRAY)
        try:
            self._body(dst, side, kind, ct, h, content_encoding(h), groups, body or b"", total, consumed, decoded)
        finally:
            self.max_array = saved
        if "body" in dst and kind in ("xml", "multipart") and "fmt" not in dst:
            dst["fmt"] = kind  # 22.1: whenever a body leaves under the XML or multipart treatment

    def _treatment(self, ct: Optional[str]) -> Optional[str]:
        """9.1 and 22.1: json, form, xml, multipart or None (not parsed)."""
        if ct is None:
            return None
        if ct == "application/json" or ct.endswith("+json"):
            return "json"
        if ct == "application/x-www-form-urlencoded":
            return "form"
        bd = self.p.bodies
        if bd.xml and (ct == "application/xml" or ct == "text/xml" or ct.endswith("+xml")):
            return "xml"
        if bd.multipart and ct == "multipart/form-data":
            return "multipart"
        return None

    @staticmethod
    def _soap_action(dst: dict, h: Headers) -> None:
        """22.2 point 11: SOAPAction header (SOAP 1.1), else the content-type action parameter (SOAP 1.2)."""
        e = h.map.get("soapaction")
        if e is None:
            cte = h.map.get("content-type")
            raw = B.media_params(_joined(cte) if cte is not None else None).get("action")
        else:
            raw = decode_utf8(_joined(e))
            if raw is None:
                raw = "{*}"
        if raw is None:
            return
        name = "{*}" if raw == "{*}" else B.soap_action_name(raw, is_literal_name)
        if name is not None:
            dst["soap_action"] = name

    # --- body (9) -------------------------------------------------------------------

    def _body(self, dst: dict, side: str, kind: Optional[str], ct: Optional[str], h: Headers, ce: Optional[str],
              groups: List[Optional[Part]], data: bytes, total: Union[int, str, None], consumed: Optional[bool],
              decoded: Optional[bool]) -> None:
        mx = self.p.limits.max_body_bytes
        large_max = self.p.bodies.max_large_body_bytes
        tot: Union[int, str] = len(data) if total is None else total
        if consumed is False or tot == "unknown":
            dst["body"] = "trunc:size"
            dst["size"] = "lmax"
            return
        if tot == 0:
            dst["size"] = "l8"
            return
        if ce is not None and ce != "identity":
            if ce not in ("gzip", "x-gzip", "deflate"):
                dst["body"] = "drop:bytes"
                return
            if decoded is not True:
                # 22.5: the decoding cap includes the large-body limit.
                r = decode_body(data, ce == "deflate", max(mx, large_max) + 1)
                if r == "cap":
                    dst["body"] = "trunc:size"
                    dst["size"] = "lmax"
                    return
                if r is None:
                    dst["body"] = "drop:bytes"
                    return
                data = r
                tot = len(data)
        large = False
        if tot > mx:
            if kind is None or tot > large_max:
                dst["body"] = "trunc:size"
                dst["size"] = "lmax"
                return
            large = True  # 22.5
        dst["size"] = len_class(tot)
        if ct == "application/graphql" and len(data) == tot:  # a prefix is never parsed
            # 9.1 (spec v1.14): under a graphql rule on $ the whole body is one string leaf.
            a = _best_rule([(g.body if g is not None else []) for g in groups], 0)
            if a is not None and a.action == "graphql":
                s = decode_utf8(data)
                if s is None:
                    self._gql_unusable(a)
                    dst["body"] = "drop:str:invalid"
                else:
                    dst["body"] = self._str_action(s, a, False, None)
                return
        if kind is None:
            dst["body"] = "drop:bytes:" + len_class(tot)
            return
        if len(data) < tot:
            dst["body"] = "trunc:size"  # 9.1: only a prefix of a parsed body, it cannot be analysed
            return
        dpath = side + ".body" if self.disc is not None else None
        if kind == "json":
            try:
                root = parse_json(data)
            except JsonError:
                dst["body"] = "trunc:invalid-json"
                return
            dst["body"] = self._walk_body(root, groups, dpath, False, large)
            return
        if kind == "form":
            dst["body"] = self._named_map(parse_urlencoded(data), groups, "form", side + ".body")
            return
        if kind == "xml":
            try:
                xroot = B.parse_xml(data)
            except B.InvalidXML:
                dst["body"] = "trunc:invalid-xml"
                return
            tree, entries, fmt = B.xml_tree(xroot, is_literal_name, self.p.limits.max_depth)
            dst["fmt"] = fmt
            dst["body"] = self._walk_body(tree, groups, dpath, True, large)
            if entries:
                xmlns = dict(entries[:B.NS_MAX_ENTRIES])
                if len(entries) > B.NS_MAX_ENTRIES:
                    xmlns["{trunc}"] = "trunc:keys:" + len_class(len(entries))
                dst["xmlns"] = xmlns
            return
        # multipart (22.3)
        cte = h.map.get("content-type")
        boundary = B.media_params(_joined(cte) if cte is not None else None).get("boundary")
        try:
            parts = B.parse_multipart(data, boundary)
        except B.InvalidMultipart:
            dst["body"] = "trunc:invalid-multipart"
            return
        named: List[_Named] = []
        for pt in parts:
            out = pt.name if is_literal_name(pt.name) else "{*}"
            if pt.is_file:
                named.append(_Named(pt.name, out, b"", False, B.file_token(pt.content, pt.ct)))
            else:
                named.append(_Named(pt.name, out, pt.content, False))
        dst["body"] = self._named_map(named, groups, "form", side + ".body")

    def _walk_body(self, root: Any, groups: List[Optional[Part]], dpath: Optional[str], xml: bool, large: bool) -> Any:
        alive = [(g.body if g is not None else []) for g in groups]
        self.xml_keys, self.large = xml, large
        try:
            return self._walk(root, 0, alive, dpath, 0)
        finally:
            self.xml_keys, self.large = False, False

    def _walk(self, node: Any, pos: int, alive: List[List[BodyRule]], dpath: Optional[str], arrs: int) -> Any:
        """``arrs``: number of arrays among the ancestors (22.5 large-body caps)."""
        lim = self.p.limits
        if isinstance(node, (JObj, list)):
            if pos + 1 > lim.max_depth:
                return "trunc:depth"
            # 5.0 explicit drop on a container
            for g, rules in enumerate(alive):
                if not any(len(r.steps) == pos and r.action.action == "drop" for r in rules):
                    continue
                reach = False
                for h in range(g + 1):
                    if any(len(r.steps) > pos for r in alive[h]):
                        reach = True
                        break
                if not reach:
                    if isinstance(node, list):
                        return "drop:arr:" + len_class(len(node))
                    return "drop:obj:" + len_class(len(_dedupe(node.m)))
                break
            any_alive = any(alive)
            if isinstance(node, list):
                res: list = []
                cap = self.max_array
                if self.large:  # 22.5
                    bd = self.p.bodies
                    cap = bd.large_array if arrs == 0 else bd.large_nested_array
                n = min(len(node), cap)
                if any_alive:
                    child = [[r for r in rs if len(r.steps) > pos and r.steps[pos].t == "idx"] for rs in alive]
                else:
                    child = alive
                cd = None if dpath is None else dpath + "[*]"
                for i in range(n):
                    res.append(self._walk(node[i], pos + 1, child, cd, arrs + 1))
                if len(node) > cap:
                    res.append("trunc:n:" + len_class(len(node)))
                return res
            members = _dedupe(node.m)
            resd: dict = {}
            dyn: list = []
            kept = members[:lim.max_keys] if len(members) > lim.max_keys else members
            lit = xml_key_is_literal if self.xml_keys else is_literal_name
            for k, bad, v in kept:
                literal = not bad and lit(k)
                if any_alive:
                    child = []
                    for rs in alive:
                        sel = []
                        for r in rs:
                            if len(r.steps) <= pos:
                                continue
                            st = r.steps[pos]
                            if st.t == "any" or (st.t == "name" and not bad and st.name == k):
                                sel.append(r)
                        child.append(sel)
                else:
                    child = alive
                cd = None if dpath is None else dpath + ("." + k if literal else ".*")
                o = self._walk(v, pos + 1, child, cd, arrs)
                if literal:
                    resd[k] = o
                else:
                    dyn.append(o)
            if dyn:
                dyn.sort(key=write_canonical)
                resd["{*}"] = dyn
            if len(members) > lim.max_keys:
                resd["{trunc}"] = "trunc:keys:" + len_class(len(members))
            return resd
        # leaf
        a = _best_rule(alive, pos)
        if a is not None:
            return self._leaf(node, a, None)
        return self._leaf(node, None, dpath)

    def _leaf(self, node: Any, a: Optional[Action], dpath: Optional[str]) -> Any:
        if a is not None and a.action == "graphql" and not isinstance(node, str):
            self._gql_unusable(a)  # 5.7.1: a number, boolean or null leaves as its shape
        if node is None:
            if a is not None and a.action == "keep":
                return None
            if a is None and dpath is not None:
                self._disc_add(dpath, b"null")
            return "drop:null"
        if node is True or node is False:
            if a is not None and a.action == "keep":
                return node
            if a is None and dpath is not None:
                self._disc_add(dpath, b"true" if node else b"false")
            return "drop:bool"
        if isinstance(node, Num):
            within = lexeme_within_limits(node.lex)
            shape = "drop:int" if is_int_lexeme(node.lex) else "drop:dec"
            if a is None:
                if dpath is not None and within:
                    self._disc_add(dpath, canonical_number(node.lex).encode("ascii"))
                return shape
            if not within:
                return shape
            if a.action == "keep":
                return CNum(canonical_number(node.lex))
            if a.action == "hmac":
                return self.s.token(a.domain or "id", canonical_number(node.lex).encode("ascii"))
            if a.action == "bucket" and a.kind == "num":
                return bucket_num(node.lex, a)
            return shape
        if isinstance(node, str):
            if lone_surrogate(node):
                self._gql_unusable(a)
                return "drop:str:invalid"
            return self._str_action(node, a, False, dpath)
        return "drop:null"

    def _str_action(self, s: Optional[str], a: Optional[Action], path_param: bool, dpath: Optional[str]) -> str:
        """Action on a string value. ``None`` = not UTF-8."""
        if s is None:
            self._gql_unusable(a)
            return "drop:bytes"
        if a is None:
            if dpath is not None and self.disc is not None:
                self._disc_add(dpath, s.encode("utf-8"))
            return self._shape(s)
        if a.action == "keep":
            if utf8_len(s) <= self.p.limits.keep_max_bytes and (not path_param or PATH_TOKEN_RE.fullmatch(s)):
                return "keep:" + s
            return self._shape(s)
        if a.action == "code":
            # 5.6 (spec v1.11): only a code-shaped string within keep_max_bytes leaves.
            # v1.19: the shape alnum allows digits and dots, 1 to 16 bytes. Both are ASCII-only.
            rx = CODE_ALNUM_RE if a.shape == "alnum" else CODE_RE
            if rx.fullmatch(s) and len(s) <= self.p.limits.keep_max_bytes:
                return "keep:" + s
            return self._shape(s)
        if a.action == "graphql":
            return self._graphql(s)
        if a.action == "hmac":
            return self.s.token(a.domain or "id", s.encode("utf-8"))
        if a.action == "bucket":
            if a.kind == "time" and (not path_param or PATH_TOKEN_RE.fullmatch(s)):
                r = bucket_time(s, a.unit or "")
                return r if r is not None else self._shape(s)
            return self._shape(s)
        return self._shape(s)

    def _shape(self, s: str) -> str:
        """6.2 shape of a well-formed string, with the document shape of 22.4 when bodies.docs is on."""
        if not self.docs:
            return str_shape(s)
        f = detect_format(s)
        if f is not None:
            return "drop:str:" + f
        d = B.base64_doc(s)
        if d is not None:
            return d
        return "drop:str:" + len_class(utf8_len(s))

    # --- graphql (5.7, spec v1.14) -----------------------------------------------------

    def _graphql(self, s: str) -> str:
        """Request: the shape of an executable document as gql:, recorded for the gate.
        Response: with the gate open, a safe GraphQL name as gql:. Otherwise the shape."""
        if not self.resp:
            self.gql_seen = True
            r = gqlshape.shape(s)
            if r is None:
                self.gql_nonintro = True
                return str_shape(s)
            if not r[1]:
                self.gql_nonintro = True
            return "gql:" + r[0]
        if self._gql_gate() and gqlshape.is_name(s) and gqlshape.name_safe(s):
            return "gql:" + s
        return str_shape(s)

    def _gql_gate(self) -> bool:
        """5.7.2: open iff the request had a graphql value and every one was introspection only."""
        return self.gql_seen and not self.gql_nonintro

    def _gql_unusable(self, a: Optional[Action]) -> None:
        """A request value under a graphql rule without usable text closes the gate."""
        if a is not None and a.action == "graphql" and not self.resp:
            self.gql_seen = self.gql_nonintro = True

    def _disc_add(self, path: str, value: bytes) -> None:
        d = self.disc
        if d is None:
            return
        prev = d.get(path)
        if prev is None or value < prev:
            d[path] = value

    # --- named parts (8.1-8.3, 9.1 form) ---------------------------------------------

    @staticmethod
    def _named_rule(groups: List[Optional[Part]], section: str, name: Optional[str]) -> Optional[Action]:
        if name is None:
            return None
        for g in groups:
            if g is None:
                continue
            if section == "form":
                best: Optional[BodyRule] = None
                for r in g.body:
                    if len(r.steps) != 1:
                        continue
                    st = r.steps[0]
                    if not (st.t == "any" or (st.t == "name" and st.name == name)):
                        continue
                    if best is None or r.names > best.names or (r.names == best.names and r.path < best.path):
                        best = r
                if best is not None:
                    return best.action
                continue
            a = getattr(g, section).get(name)
            if a is not None:
                return a
        return None

    def _named_map(self, entries: List[_Named], groups: List[Optional[Part]], section: str, disc: str) -> dict:
        order: List[str] = []
        by_name: Dict[str, List[_Named]] = {}
        for e in entries:
            lst = by_name.get(e.out)
            if lst is None:
                lst = by_name[e.out] = []
                order.append(e.out)
            lst.append(e)
        res: dict = {}
        # After 8.0 every header name has exactly one value: max_array applies to cookies,
        # query and form values only (8.2, 8.3).
        max_arr = (1 << 62) if section == "headers" else self.max_array
        for name in order[:MAX_NAMES]:
            lst = by_name[name]
            vals: list = []
            dpath = None
            if self.disc is not None:
                dpath = disc + "." + ("*" if (section == "form" and name == "{*}") else name)
            for e in lst[:max_arr]:
                if e.token is not None:
                    vals.append(e.token)
                    continue
                a = None if e.no_eq else self._named_rule(groups, section, e.orig)
                vals.append(self._str_action(decode_utf8(e.value), a, False, dpath))
            if len(lst) > max_arr:
                vals.append("trunc:n:" + len_class(len(lst)))
            res[name] = vals
        if len(order) > MAX_NAMES:
            res["{trunc}"] = ["trunc:keys:" + len_class(len(order))]
        return res


def _best_rule(alive: List[List[BodyRule]], pos: int) -> Optional[Action]:
    """5.0: the first group with a rule ending at ``pos``; inside it, more name steps,
    then the smaller path."""
    for rs in alive:
        best: Optional[BodyRule] = None
        for r in rs:
            if len(r.steps) != pos:
                continue
            if best is None or r.names > best.names or (r.names == best.names and r.path < best.path):
                best = r
        if best is not None:
            return best.action
    return None


def _dedupe(m: List[Tuple[str, bool, Any]]) -> List[Tuple[str, bool, Any]]:
    """9.3.1: only the last occurrence of a key counts, at the position of that occurrence."""
    if len(m) < 2:
        return m
    last = {k: i for i, (k, _b, _v) in enumerate(m)}
    if len(last) == len(m):
        return m
    return [t for i, t in enumerate(m) if last[t[0]] == i]


def _cookie_part(piece: bytes, out: List[_Named]) -> None:
    eq = piece.find(b"=")
    if eq < 0:
        return
    name = decode_utf8(piece[:eq])
    out.append(_Named(name, name if name is not None and is_literal_name(name) else "{*}", piece[eq + 1:], False))


def parse_urlencoded(raw: bytes) -> List[_Named]:
    """8.3 / 9.1: query string or form body into named entries."""
    out: List[_Named] = []
    for part in raw.split(b"&"):
        if not part:
            continue
        eq = part.find(b"=")
        if eq < 0:
            out.append(_Named(None, "{*}", pct_decode(part, True), True))
            continue
        name = decode_utf8(pct_decode(part[:eq], True))
        out.append(_Named(name, name if name is not None and is_literal_name(name) else "{*}",
                          pct_decode(part[eq + 1:], True), False))
    return out
