"""Compiled policy model (policy.md 2), body validation (policy.md 4, schema
policy-compiled.v1), signed envelope verification (policy.md 3) and HMAC key parsing
(sanitizer.md 7.1).

Fail closed: anything that is not exactly what the schema allows is a rejection.
"""

from __future__ import annotations

import base64
import calendar
import hashlib
import re
from typing import Any, Callable, Dict, List, Mapping, Optional, Set, Tuple

from . import ed25519
from .jsonlex import JsonError, Num, canonical_number, parse_json, to_plain
from .textutil import ascii_lower

REFUSAL_CODES = ("no_policy", "policy_rejected", "expired_policy", "key_missing", "key_mismatch")


class Refused(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code + (": " + detail if detail else ""))
        self.code = code
        self.detail = detail


RESERVED_DOMAINS = frozenset(["subject", "sample", "sample-trace", "discovery"])
BODY_FORMAT = "tt.policy.body/v1"
ENVELOPE_FORMAT = "tt.policy.compiled/v1"
SIGNATURE_PREFIX = b"tt.policy.body/v1\x00"
DAY = 86400.0

# ---------------------------------------------------------------------------------
# Model


class Bound:
    __slots__ = ("canon", "d")

    def __init__(self, canon: str, d: float) -> None:
        self.canon = canon
        self.d = d


class Action:
    """``shape`` is ``"alnum"`` for ``code(alnum)`` (sanitizer.md 5.6, spec v1.19), else None."""

    __slots__ = ("action", "domain", "kind", "bounds", "unit", "shape")

    def __init__(self, action: str, domain: Optional[str] = None, kind: Optional[str] = None,
                 bounds: Optional[List[Bound]] = None, unit: Optional[str] = None,
                 shape: Optional[str] = None) -> None:
        self.action = action
        self.domain = domain
        self.kind = kind
        self.bounds = bounds
        self.unit = unit
        self.shape = shape


class Step:
    """A tt-path step: kind 'name', 'any' (.*) or 'idx' ([*]). The name of the v1.19 steps
    ``.@name`` and ``.#text`` keeps its ``@`` / ``#`` (it selects that key of the tree)."""

    __slots__ = ("t", "name")

    def __init__(self, t: str, name: str = "") -> None:
        self.t = t
        self.name = name


class BodyRule:
    __slots__ = ("path", "steps", "names", "action")

    def __init__(self, path: str, steps: List[Step], action: Action) -> None:
        self.path = path
        self.steps = steps
        self.names = sum(1 for s in steps if s.t == "name")
        self.action = action


class Part:
    __slots__ = ("query", "headers", "cookies", "path", "body")

    def __init__(self) -> None:
        self.query: Dict[str, Action] = {}
        self.headers: Dict[str, Action] = {}
        self.cookies: Dict[str, Action] = {}
        self.path: Dict[str, Action] = {}
        self.body: List[BodyRule] = []


class TemplateSeg:
    __slots__ = ("lit", "param")

    def __init__(self, lit: Optional[str] = None, param: Optional[str] = None) -> None:
        self.lit = lit
        self.param = param


class Op:
    __slots__ = ("key", "method", "segs", "literals", "request", "response")

    def __init__(self, key: str, method: str, segs: List[TemplateSeg], literals: int) -> None:
        self.key = key
        self.method = method
        self.segs = segs
        self.literals = literals
        self.request: Optional[Part] = None
        self.response: Optional[Part] = None


class Service:
    __slots__ = ("name", "inbound", "internal", "base_origin", "base_segs", "request", "response", "errors", "ops")

    def __init__(self, name: str, inbound: bool, internal: bool) -> None:
        self.name = name
        self.inbound = inbound
        self.internal = internal
        self.base_origin: Optional[str] = None
        self.base_segs: List[str] = []
        self.request: Optional[Part] = None
        self.response: Optional[Part] = None
        self.errors: Optional[Part] = None
        self.ops: List[Op] = []


class Limits:
    __slots__ = ("max_body_bytes", "max_depth", "max_array", "max_keys", "keep_max_bytes")

    def __init__(self, mb: int = 1048576, md: int = 32, ma: int = 32, mk: int = 256, kb: int = 64) -> None:
        self.max_body_bytes = mb
        self.max_depth = md
        self.max_array = ma
        self.max_keys = mk
        self.keep_max_bytes = kb


class Bodies:
    """``bodies`` of the compiled body (sanitizer.md 22.1, spec v1.19); absent = all off."""

    __slots__ = ("xml", "multipart", "docs", "max_large_body_bytes", "large_array", "large_nested_array")

    def __init__(self, xml: bool = False, multipart: bool = False, docs: bool = False, large: int = 0,
                 large_array: int = 0, large_nested_array: int = 0) -> None:
        self.xml = xml
        self.multipart = multipart
        self.docs = docs
        self.max_large_body_bytes = large
        self.large_array = large_array
        self.large_nested_array = large_nested_array


class SubjectSpec:
    __slots__ = ("frm", "name", "jwt_claim", "json_path")

    def __init__(self, frm: str, name: str, jwt_claim: Optional[str], json_path: Optional[str] = None) -> None:
        self.frm = frm
        self.name = name
        self.jwt_claim = jwt_claim
        # Spec v1.18: dotted path of members inside a header whose value is a JSON object (sanitizer.md 11, step 4 bis).
        self.json_path = json_path


def _obj(v: Any) -> Optional[dict]:
    return v if isinstance(v, dict) else None


def _arr(v: Any) -> list:
    return v if isinstance(v, list) else []


def _str(v: Any, d: str) -> str:
    return v if isinstance(v, str) else d


def _int(v: Any, d: int) -> int:
    if isinstance(v, Num):
        try:
            return int(v.lex)
        except ValueError:
            try:
                return int(float(v.lex))
            except (ValueError, OverflowError):
                return d
    return d


_RFC3339 = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?([Zz]|([+-])([0-9]{2}):([0-9]{2}))"
)
NAN = float("nan")


def parse_time(v: Any) -> float:
    """RFC 3339 timestamp to epoch seconds; NaN when absent or malformed."""
    if not isinstance(v, str):
        return NAN
    m = _RFC3339.fullmatch(v)
    if not m:
        return NAN
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    if mo < 1 or mo > 12 or d < 1 or d > 31 or h > 23 or mi > 59 or s > 60 or y < 1:
        return NAN
    t = float(calendar.timegm((y, mo, 1, h, mi, s, 0, 0, 0))) + (d - 1) * DAY
    if m.group(7):
        t += float("0" + m.group(7))
    if m.group(9):
        off = (int(m.group(10)) * 60 + int(m.group(11))) * 60
        t += -off if m.group(9) == "+" else off
    return t


def _parse_action(v: Any) -> Optional[Action]:
    o = _obj(v)
    if o is None:
        return None
    a = o.get("action")
    if a == "code" and o.get("shape") == "alnum":
        return Action("code", shape="alnum")
    if a in ("drop", "keep", "code", "graphql"):
        return Action(a)
    if a == "hmac":
        return Action("hmac", domain=_str(o.get("domain"), "id"))
    if a == "bucket" and o.get("kind") == "num":
        bounds = []
        for x in _arr(o.get("bounds")):
            lex = x.lex if isinstance(x, Num) else str(x)
            bounds.append(Bound(canonical_number(lex), float(lex)))
        return Action("bucket", kind="num", bounds=bounds)
    if a == "bucket" and o.get("kind") == "time":
        return Action("bucket", kind="time", unit=_str(o.get("unit"), "day"))
    return Action("drop")


def _name_map(v: Any) -> Dict[str, Action]:
    m: Dict[str, Action] = {}
    o = _obj(v)
    if o is None:
        return m
    for k, raw in o.items():
        a = _parse_action(raw)
        if a is not None:
            m[k] = a
    return m


_TT_NAME = re.compile(r"@?[A-Za-z_][A-Za-z0-9_-]{0,63}|#text")


def parse_tt_path(p: str) -> Optional[List[Step]]:
    """Parses a tt-path; None if it does not follow the grammar (5.0)."""
    if not p.startswith("$"):
        return None
    steps: List[Step] = []
    i = 1
    while i < len(p):
        if p.startswith(".*", i):
            steps.append(Step("any"))
            i += 2
        elif p.startswith("[*]", i):
            steps.append(Step("idx"))
            i += 3
        elif p[i] == ".":
            m = _TT_NAME.match(p, i + 1)
            if not m:
                return None
            steps.append(Step("name", m.group()))
            i += 1 + len(m.group())
        else:
            return None
    return steps


def _part(v: Any) -> Optional[Part]:
    o = _obj(v)
    if o is None:
        return None
    p = Part()
    for r in _arr(o.get("body")):
        ro = _obj(r)
        if ro is None:
            continue
        path = _str(ro.get("path"), "")
        steps = parse_tt_path(path)
        action = _parse_action(ro.get("action"))
        if steps is None or action is None:
            continue
        p.body.append(BodyRule(path, steps, action))
    p.query = _name_map(o.get("query"))
    p.headers = _name_map(o.get("headers"))
    p.cookies = _name_map(o.get("cookies"))
    p.path = _name_map(o.get("path"))
    return p


def parse_op_key(key: str) -> Optional[Op]:
    sp = key.find(" ")
    if sp <= 0:
        return None
    method, tmpl = key[:sp], key[sp + 1:]
    if not tmpl.startswith("/"):
        return None
    segs: List[TemplateSeg] = []
    literals = 0
    for s in tmpl.split("/"):
        if s == "":
            continue
        if s[0] == "{" and s[-1] == "}":
            segs.append(TemplateSeg(param=s[1:-1]))
        else:
            segs.append(TemplateSeg(lit=s))
            literals += 1
    return Op(key, method, segs, literals)


_BASE_SPLIT = re.compile(r"([a-z][a-z0-9+.-]*://[^/]*)(/.*)?", re.S)


def split_base(base: str) -> Tuple[str, List[str]]:
    m = _BASE_SPLIT.fullmatch(base)
    if not m:
        return base, []
    return m.group(1), [s for s in (m.group(2) or "").split("/") if s != ""]


class Policy:
    """Ready-to-use compiled policy."""

    def __init__(self, body: Mapping[str, Any]) -> None:
        b = body
        self.body = body
        self.policy_id = _str(b.get("policy_id"), "")
        self.version = _int(b.get("version"), 0)
        self.issued_seq = _int(b.get("issued_seq"), 0)
        self.created_at = parse_time(b.get("created_at"))
        self.not_after = parse_time(b.get("not_after"))
        targets = _obj(b.get("targets")) or {}
        self.groups = [_str(g, "") for g in _arr(targets.get("groups"))]
        hm = _obj(b.get("hmac")) or {}
        self.kid = _str(hm.get("kid"), "")
        self.accept_kids = [_str(k, "") for k in _arr(hm.get("accept_kids"))]
        self.epoch = _str(hm.get("epoch"), "")
        self.subject: Optional[SubjectSpec] = None
        subj = _obj((_obj(b.get("identity")) or {}).get("subject"))
        if subj is not None:
            jc = subj.get("jwt_claim")
            jp = subj.get("json_path")
            self.subject = SubjectSpec(_str(subj.get("from"), "header"), _str(subj.get("name"), ""),
                                       jc if isinstance(jc, str) else None, jp if isinstance(jp, str) else None)
        sampling = _obj(b.get("sampling")) or {}
        self.rate_bp = _int(sampling.get("rate_bp"), 0)
        self.trust_baggage = sampling.get("trust_baggage") is True
        self.propagate_to: Set[str] = {_str(h, "") for h in _arr(sampling.get("propagate_to"))}
        seg = _obj(b.get("segments")) or {}
        self.auto_words = seg.get("auto_words") is True
        self.auto_words_expires_at = parse_time(seg.get("auto_words_expires_at"))
        self.allow: Set[str] = {_str(x, "") for x in _arr(seg.get("allow"))}
        self.hosts_allow: Set[str] = {_str(x, "") for x in _arr(seg.get("hosts_allow"))}
        # Spec v1.5 `hosts.discovery`: True = auto (default, also when `hosts` is absent), False = off (strict mode).
        self.hosts_auto = (_obj(b.get("hosts")) or {}).get("discovery") != "off"
        lim = _obj(b.get("limits")) or {}
        d = Limits()
        self.limits = Limits(
            _int(lim.get("max_body_bytes"), d.max_body_bytes), _int(lim.get("max_depth"), d.max_depth),
            _int(lim.get("max_array"), d.max_array), _int(lim.get("max_keys"), d.max_keys),
            _int(lim.get("keep_max_bytes"), d.keep_max_bytes),
        )
        bd = _obj(b.get("bodies"))
        self.bodies = Bodies() if bd is None else Bodies(
            bd.get("xml") is True, bd.get("multipart") is True, bd.get("docs") is True,
            max(0, _int(bd.get("max_large_body_bytes"), 0)), max(0, _int(bd.get("large_array"), 0)),
            max(0, _int(bd.get("large_nested_array"), 0)),
        )
        # 9.0 / 22.5: how many bytes of a body a source keeps (the tee prefix).
        self.capture_limit = max(self.limits.max_body_bytes, self.bodies.max_large_body_bytes) + 1
        disc = _obj(b.get("discovery")) or {}
        self.discovery_enabled = disc.get("enabled") is True
        self.discovery_expires_at = parse_time(disc.get("expires_at"))
        g = _obj(b.get("global")) or {}
        self.g_request = _part(g.get("request"))
        self.g_response = _part(g.get("response"))
        self.g_errors = _part(g.get("errors"))
        self.services: List[Service] = []
        self.inbound: Dict[str, Service] = {}
        self.base_hosts: Set[str] = set()
        for s in _arr(b.get("services")):
            so = _obj(s)
            if so is None:
                continue
            m = _obj(so.get("match")) or {}
            svc = Service(_str(so.get("name"), ""), m.get("inbound") is True, m.get("internal") is True)
            svc.request = _part(so.get("request"))
            svc.response = _part(so.get("response"))
            svc.errors = _part(so.get("errors"))
            if isinstance(m.get("base"), str):
                svc.base_origin, svc.base_segs = split_base(m["base"])
                auth = re.sub(r"^[a-z]+://", "", svc.base_origin)
                self.base_hosts.add(auth)
                self.base_hosts.add(re.sub(r":[0-9]+$", "", auth))
            for o in _arr(so.get("ops")):
                oo = _obj(o)
                if oo is None:
                    continue
                op = parse_op_key(_str(oo.get("op"), ""))
                if op is None:
                    continue
                op.request = _part(oo.get("request"))
                op.response = _part(oo.get("response"))
                svc.ops.append(op)
            self.services.append(svc)
            if svc.inbound and svc.name not in self.inbound:
                self.inbound[svc.name] = svc
        self.hash = ""

    def auto_words_active(self, now: Optional[float]) -> bool:
        """4.3"""
        return (self.auto_words and now is not None and now < self.auto_words_expires_at
                and now < self.created_at + 7 * DAY)

    def discovery_active(self, now: Optional[float]) -> bool:
        """15"""
        return (self.discovery_enabled and now is not None and now < self.discovery_expires_at
                and now < self.created_at + 7 * DAY)


# ---------------------------------------------------------------------------------
# Body checks


def _iter_actions(body: Mapping[str, Any]):
    parts: List[dict] = []

    def collect(scope: Any, keys: Tuple[str, ...]) -> None:
        s = _obj(scope)
        if s is None:
            return
        for k in keys:
            p = _obj(s.get(k))
            if p is not None:
                parts.append(p)

    collect(body.get("global"), ("request", "response", "errors"))
    for svc in _arr(body.get("services")):
        collect(svc, ("request", "response", "errors"))
        so = _obj(svc)
        for op in _arr(so.get("ops") if so else None):
            collect(op, ("request", "response"))
    for p in parts:
        for sec in ("query", "headers", "cookies", "path"):
            m = _obj(p.get(sec))
            if m:
                for k in m:
                    a = _obj(m[k])
                    if a is not None:
                        yield a
        for r in _arr(p.get("body")):
            a = _obj((_obj(r) or {}).get("action"))
            if a is not None:
                yield a


UNSAFE_DETAIL = "unsafe"
"""Detail prefix of a Refused raised by the v1.3 safety subset; the agent reports it as `policy_unsafe`."""

_CREDENTIAL_HEADERS = frozenset(["authorization", "cookie", "set-cookie", "proxy-authorization"])


def check_unsafe(b: Mapping[str, Any]) -> None:
    """Source-side safety subset (hardening.md 2.1, v1.3), applied to every signed body:

    H1 keep or hmac on authorization, cookie, set-cookie, proxy-authorization (header rules of
       request, response and errors; global, services and operations);
    H2 keep or hmac on a tt-path with any wildcard step (`.*` or `[*]`) in the global body rules;
    H3 discovery or auto_words expiring later than created_at + 7 days.
    Properties of the body: neither the clock nor the group matter.
    """
    def unsafe(why: str) -> Refused:
        return Refused("policy_rejected", UNSAFE_DETAIL + ": " + why)

    g = _obj(b.get("global"))
    parts: List[dict] = []

    def collect(scope: Any, keys: Tuple[str, ...]) -> None:
        s = _obj(scope)
        if s is None:
            return
        for k in keys:
            p = _obj(s.get(k))
            if p is not None:
                parts.append(p)

    collect(g, ("request", "response", "errors"))
    for svc in _arr(b.get("services")):
        collect(svc, ("request", "response", "errors"))
        so = _obj(svc)
        for op in _arr(so.get("ops") if so else None):
            collect(op, ("request", "response"))
    for p in parts:
        headers = _obj(p.get("headers"))
        for name in headers or ():
            act = (_obj(headers[name]) or {}).get("action")
            if name in _CREDENTIAL_HEADERS and act in ("keep", "code", "hmac"):
                raise unsafe("%s on header %s" % (act, name))
    if g is not None:
        for k in ("request", "response", "errors"):
            for r in _arr((_obj(g.get(k)) or {}).get("body")):
                ro = _obj(r) or {}
                act = (_obj(ro.get("action")) or {}).get("action")
                path = ro.get("path")
                if act in ("keep", "code", "hmac") and isinstance(path, str) and (".*" in path or "[*]" in path):
                    raise unsafe("%s on %s in a global rule" % (act, path))
    limit = parse_time(b.get("created_at")) + 7 * DAY
    seg = _obj(b.get("segments"))
    if seg is not None and seg.get("auto_words") is True and parse_time(seg.get("auto_words_expires_at")) > limit:
        raise unsafe("auto_words expires beyond created_at + 7 days")
    d = _obj(b.get("discovery"))
    if d is not None and d.get("enabled") is True and parse_time(d.get("expires_at")) > limit:
        raise unsafe("discovery expires beyond created_at + 7 days")


def check_body_minimal(body: Any) -> dict:
    """Minimal checks of the conformance runner (format.md, step 1), plus the v1.3 safety subset."""
    b = _obj(body)
    if b is None or b.get("format") != BODY_FORMAT:
        raise Refused("policy_rejected", "body format")
    for a in _iter_actions(b):
        if a.get("action") == "hmac" and isinstance(a.get("domain"), str) and a["domain"] in RESERVED_DOMAINS:
            raise Refused("policy_rejected", "reserved domain")
    check_unsafe(b)
    return b


# --- full schema validation (schemas/policy-compiled.v1.schema.json#/$defs/body) ---


class SchemaError(Exception):
    pass


V = Callable[[Any, str], None]


def _fail(at: str, why: str):
    raise SchemaError(at + ": " + why)


def _v_str(rx: "re.Pattern[str]") -> V:
    def f(v: Any, at: str) -> None:
        if not isinstance(v, str) or rx.fullmatch(v) is None:
            _fail(at, "string")
    return f


def _v_int(lo: int, hi: int = 2 ** 53 - 1) -> V:
    def f(v: Any, at: str) -> None:
        if not isinstance(v, Num) or not re.fullmatch(r"-?(?:0|[1-9][0-9]*)", v.lex):
            _fail(at, "integer")
        n = int(v.lex)
        if n < lo or n > hi:
            _fail(at, "range")
    return f


def _v_bool(v: Any, at: str) -> None:
    if not isinstance(v, bool):
        _fail(at, "boolean")


def _v_time(v: Any, at: str) -> None:
    t = parse_time(v)
    if t != t:
        _fail(at, "date-time")


def _v_const(c: Any) -> V:
    def f(v: Any, at: str) -> None:
        if v != c or type(v) is not type(c):
            _fail(at, "const")
    return f


def _v_any(v: Any, at: str) -> None:
    return None


def _v_arr(item: V, maxn: int, unique: bool, minn: int = 0) -> V:
    def f(v: Any, at: str) -> None:
        if not isinstance(v, list) or len(v) > maxn or len(v) < minn:
            _fail(at, "array")
        seen: Set[str] = set()
        for i, x in enumerate(v):
            item(x, "%s[%d]" % (at, i))
            if unique:
                k = repr(x.lex if isinstance(x, Num) else x)
                if k in seen:
                    _fail(at, "unique")
                seen.add(k)
    return f


def _v_enum(values: List[str]) -> V:
    def f(v: Any, at: str) -> None:
        if not isinstance(v, str) or v not in values:
            _fail(at, "enum")
    return f


def _v_obj(props: Dict[str, V], required: List[str]) -> V:
    def f(v: Any, at: str) -> None:
        if not isinstance(v, dict):
            _fail(at, "object")
        for k, val in v.items():
            p = props.get(k)
            if p is None:
                _fail(at + "." + k, "unexpected")
            p(val, at + "." + k)
        for r in required:
            if r not in v:
                _fail(at + "." + r, "required")
    return f


def _v_map(name: "re.Pattern[str]", val: V, maxn: int) -> V:
    def f(v: Any, at: str) -> None:
        if not isinstance(v, dict):
            _fail(at, "object")
        if len(v) > maxn:
            _fail(at, "maxProperties")
        for k, x in v.items():
            if name.fullmatch(k) is None:
                _fail(at + "." + k, "name")
            val(x, at + "." + k)
    return f


_RE_POLICY_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
_RE_DOMAIN = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_RE_KID = re.compile(r"[a-z0-9]{1,8}")
_RE_HOSTPORT = re.compile(r"[a-z0-9.-]{1,253}(:[0-9]{1,5})?")
_RE_KEYNAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}")
_RE_HEADERNAME = re.compile(r"[a-z0-9!#$%&'*+.^_`|~-]{1,64}")
_RE_PARAMNAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_RE_TTPATH = re.compile(r"\$(\.@?[A-Za-z_][A-Za-z0-9_-]{0,63}|\.#text|\.\*|\[\*\]){0,64}")
_RE_OPKEY = re.compile(
    r"[A-Z]{1,16} /([A-Za-z0-9._~-]{1,64}|\{[A-Za-z_][A-Za-z0-9_]{0,63}\})?"
    r"(/([A-Za-z0-9._~-]{1,64}|\{[A-Za-z_][A-Za-z0-9_]{0,63}\})){0,31}"
)
_RE_BASE = re.compile(r"https?://[a-z0-9.-]{1,253}(:[0-9]{1,5})?(/[A-Za-z0-9._~-]{1,64})*")


def _v_action(v: Any, at: str) -> None:
    if not isinstance(v, dict):
        _fail(at, "action")
    a = v.get("action")
    if a == "code" and "shape" in v:
        # Spec v1.19 (sanitizer.md 5.6): the only shape is alnum, and only on code.
        return _v_obj({"action": _v_any, "shape": _v_const("alnum")}, ["action", "shape"])(v, at)
    if a in ("drop", "keep", "code", "graphql"):
        return _v_obj({"action": _v_any}, ["action"])(v, at)
    if a == "hmac":
        _v_obj({"action": _v_any, "domain": _v_str(_RE_DOMAIN)}, ["action", "domain"])(v, at)
        if v["domain"] in RESERVED_DOMAINS:
            _fail(at, "reserved domain")
        return None
    if a == "bucket" and v.get("kind") == "num":
        def bound(x: Any, a2: str) -> None:
            if not isinstance(x, Num):
                _fail(a2, "number")
            if len(x.lex) > 64:
                _fail(a2, "lexeme")

        _v_obj({"action": _v_any, "kind": _v_any, "bounds": _v_arr(bound, 32, False, 1)}, ["action", "kind", "bounds"])(v, at)
        ds = [float(x.lex) for x in v["bounds"]]
        for i in range(1, len(ds)):
            if not ds[i - 1] < ds[i]:
                _fail(at, "bounds not increasing")
        return None
    if a == "bucket" and v.get("kind") == "time":
        return _v_obj({"action": _v_any, "kind": _v_any, "unit": _v_str(re.compile(r"year|month|day|hour"))},
                      ["action", "kind", "unit"])(v, at)
    return _fail(at, "action")


_v_body_rules = _v_arr(_v_obj({"path": _v_str(_RE_TTPATH), "action": _v_action}, ["path", "action"]), 1024, False)
_v_part = _v_obj({
    "query": _v_map(_RE_KEYNAME, _v_action, 256), "headers": _v_map(_RE_HEADERNAME, _v_action, 256),
    "cookies": _v_map(_RE_KEYNAME, _v_action, 256), "body": _v_body_rules,
}, [])
_v_op_part = _v_obj({
    "path": _v_map(_RE_PARAMNAME, _v_action, 32), "query": _v_map(_RE_KEYNAME, _v_action, 256),
    "headers": _v_map(_RE_HEADERNAME, _v_action, 256), "cookies": _v_map(_RE_KEYNAME, _v_action, 256),
    "body": _v_body_rules,
}, [])
_v_scope = _v_obj({"request": _v_part, "response": _v_part, "errors": _v_part}, [])


def _v_match(v: Any, at: str) -> None:
    if not isinstance(v, dict):
        _fail(at, "match")
    if "base" in v:
        return _v_obj({"base": _v_str(_RE_BASE)}, ["base"])(v, at)
    return _v_obj({"inbound": _v_const(True), "internal": _v_bool}, ["inbound", "internal"])(v, at)


_v_service = _v_obj({
    "name": _v_str(re.compile(r"[a-z0-9][a-z0-9._-]{0,62}")), "match": _v_match,
    "request": _v_part, "response": _v_part, "errors": _v_part,
    "ops": _v_arr(_v_obj({"op": _v_str(_RE_OPKEY), "request": _v_op_part, "response": _v_op_part}, ["op"]), 4096, False),
}, ["name", "match", "ops"])


def _v_segments(v: Any, at: str) -> None:
    _v_obj({
        "auto_words": _v_bool, "auto_words_expires_at": _v_time,
        "allow": _v_arr(_v_str(re.compile(r"[A-Za-z0-9._~-]{1,64}")), 1024, True),
        "hosts_allow": _v_arr(_v_str(_RE_HOSTPORT), 1024, True),
    }, ["auto_words", "allow", "hosts_allow"])(v, at)
    if v.get("auto_words") is True and "auto_words_expires_at" not in v:
        _fail(at, "auto_words_expires_at required")


_RE_JSON_PATH = re.compile(r"[A-Za-z0-9_-]{1,64}(\.[A-Za-z0-9_-]{1,64}){0,7}")


def _v_subject(v: Any, at: str) -> None:
    _v_obj({
        "from": _v_str(re.compile(r"header|cookie")),
        "name": _v_str(re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}")),
        "jwt_claim": _v_str(_RE_KEYNAME),
        "json_path": _v_str(_RE_JSON_PATH),
    }, ["from", "name"])(v, at)
    # Spec v1.18: json_path reads a header only and excludes jwt_claim.
    if "json_path" in v and ("jwt_claim" in v or v.get("from") != "header"):
        _fail(at + ".json_path", "header only, excludes jwt_claim")


_v_body = _v_obj({
    "format": _v_const(BODY_FORMAT), "policy_id": _v_str(_RE_POLICY_ID), "version": _v_int(1), "issued_seq": _v_int(1),
    "created_at": _v_time, "not_after": _v_time,
    "targets": _v_obj({"groups": _v_arr(_v_str(_RE_POLICY_ID), 256, True, 1)}, ["groups"]),
    "hmac": _v_obj({"kid": _v_str(_RE_KID), "accept_kids": _v_arr(_v_str(_RE_KID), 4, True),
                    "epoch": _v_str(re.compile(r"[A-Za-z0-9._-]{1,32}"))}, ["kid", "epoch", "accept_kids"]),
    "identity": _v_obj({"subject": _v_subject}, []),
    "sampling": _v_obj({"rate_bp": _v_int(0, 10000), "trust_baggage": _v_bool,
                        "propagate_to": _v_arr(_v_str(_RE_HOSTPORT), 256, True)}, ["rate_bp", "trust_baggage", "propagate_to"]),
    "segments": _v_segments,
    "limits": _v_obj({
        "max_body_bytes": _v_int(0, 16777216), "max_depth": _v_int(1, 128), "max_array": _v_int(0, 1024),
        "max_keys": _v_int(1, 4096), "keep_max_bytes": _v_int(0, 1024),
    }, ["max_body_bytes", "max_depth", "max_array", "max_keys", "keep_max_bytes"]),
    # Spec v1.19 (sanitizer.md 22.1): XML and SOAP, multipart, base64 documents, large bodies. Absent = all off.
    "bodies": _v_obj({
        "xml": _v_bool, "multipart": _v_bool, "docs": _v_bool, "max_large_body_bytes": _v_int(0, 67108864),
        "large_array": _v_int(0, 1024), "large_nested_array": _v_int(0, 1024),
    }, ["xml", "multipart", "docs", "max_large_body_bytes", "large_array", "large_nested_array"]),
    "discovery": _v_obj({"enabled": _v_bool, "expires_at": _v_time}, ["enabled", "expires_at"]),
    # Spec v1.5 (sanitizer.md 3.5): how hosts without a matching base leave. Absent = auto.
    "hosts": _v_obj({"discovery": _v_enum(["auto", "off"])}, ["discovery"]),
    "global": _v_scope,
    "services": _v_arr(_v_service, 1024, False),
}, ["format", "policy_id", "version", "issued_seq", "created_at", "not_after", "targets", "hmac", "sampling",
    "segments", "limits", "global", "services"])


def validate_body_schema(body: Any) -> dict:
    """Full schema validation of a policy body, plus reserved domains, double bounds and the v1.3 safety subset."""
    try:
        _v_body(body, "$")
    except SchemaError as e:
        raise Refused("policy_rejected", "schema " + str(e)) from None
    check_unsafe(body)
    return body


# ---------------------------------------------------------------------------------
# Base64url and envelope

_B64URL = re.compile(r"[A-Za-z0-9_-]*")


def b64url_decode_strict(s: str) -> Optional[bytes]:
    """Strict base64url without padding; None on any other character or impossible length."""
    if not isinstance(s, str) or _B64URL.fullmatch(s) is None or len(s) % 4 == 1:
        return None
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def ed25519_public_key(raw_b64url: str) -> Optional[bytes]:
    raw = b64url_decode_strict(raw_b64url)
    if raw is None or len(raw) != 32:
        return None
    return raw


class VerifiedPolicy:
    __slots__ = ("body_bytes", "body", "hash", "kid")

    def __init__(self, body_bytes: bytes, body: dict, h: str, kid: str) -> None:
        self.body_bytes = body_bytes
        self.body = body
        self.hash = h
        self.kid = kid


def _same(a: Any, b: Any) -> bool:
    if isinstance(a, Num) and isinstance(b, Num):
        return a.lex == b.lex
    return a == b and type(a) is type(b)


def verify_envelope(env: Any, keys: Mapping[str, bytes], strict: bool) -> VerifiedPolicy:
    """Verifies a ``tt.policy.compiled/v1`` envelope (policy.md 3-4, conditions 1-2).

    ``keys`` maps a pinned, non-revoked signature kid to its raw 32-byte public key.
    ``strict`` applies the full body schema (production); otherwise only the minimal
    body checks of the conformance runner.
    """
    def reject(why: str):
        raise Refused("policy_rejected", why)

    e = _obj(env)
    if e is None:
        reject("envelope")
    if strict:
        allowed = {"format", "policy_id", "version", "issued_seq", "hash", "body_b64", "signature"}
        if any(k not in allowed for k in e):
            reject("envelope field")
    if e.get("format") != ENVELOPE_FORMAT:
        reject("envelope format")
    sig = _obj(e.get("signature"))
    if sig is None or sig.get("alg") != "Ed25519" or not isinstance(sig.get("kid"), str) or not isinstance(sig.get("sig"), str):
        reject("signature")
    pub = keys.get(sig["kid"])
    if pub is None:
        reject("unknown kid")
    if not isinstance(e.get("body_b64"), str):
        reject("body_b64")
    body_bytes = b64url_decode_strict(e["body_b64"])
    if not body_bytes:
        reject("body_b64")
    h = "sha256:" + hashlib.sha256(body_bytes).hexdigest()
    if e.get("hash") != h:
        reject("hash")
    sig_bytes = b64url_decode_strict(sig["sig"])
    if sig_bytes is None or len(sig_bytes) != 64:
        reject("signature encoding")
    if not ed25519.verify(pub, SIGNATURE_PREFIX + body_bytes, sig_bytes):
        reject("signature")
    try:
        plain = to_plain(parse_json(body_bytes), True)
    except JsonError:
        reject("body json")
    body = validate_body_schema(plain) if strict else check_body_minimal(plain)
    if not _same(e.get("policy_id"), body.get("policy_id")):
        reject("policy_id mismatch")
    if not _same(e.get("version"), body.get("version")):
        reject("version mismatch")
    if (strict or e.get("issued_seq") is not None or body.get("issued_seq") is not None) and not _same(e.get("issued_seq"), body.get("issued_seq")):
        reject("issued_seq mismatch")
    if strict and body.get("format") != BODY_FORMAT:
        reject("body format")
    check_body_minimal(body)
    return VerifiedPolicy(body_bytes, body, h, sig["kid"])


def check_acceptance(p: Policy, group: str, now: float, last_issued_seq: int, min_issued_seq: int,
                     allow_equal_seq: bool = False) -> None:
    """policy.md 4, conditions 3-5. ``allow_equal_seq`` lets a source re-verify the very
    policy it already accepted (cache at start-up)."""
    if group not in p.groups:
        raise Refused("policy_rejected", "group")
    if not (now < p.not_after):
        raise Refused("expired_policy")
    fresh = p.issued_seq >= last_issued_seq if allow_equal_seq else p.issued_seq > last_issued_seq
    if not fresh:
        raise Refused("policy_rejected", "issued_seq replay")
    if p.issued_seq < min_issued_seq:
        raise Refused("policy_rejected", "issued_seq below minimum")


# ---------------------------------------------------------------------------------
# HMAC key (7.1)


class KeyRing:
    __slots__ = ("keys", "order")

    def __init__(self) -> None:
        self.keys: Dict[str, bytes] = {}
        self.order: List[str] = []


def parse_key_ring(text: Optional[str]) -> KeyRing:
    """Parses TT_HMAC_KEY / TT_HMAC_KEY_FILE. Raises ``Refused('key_missing')``."""
    if text is None:
        raise Refused("key_missing", "absent")
    ring = KeyRing()
    for line in text.split("\n"):
        if line.endswith("\r"):
            line = line[:-1]
        if line == "":
            continue
        c = line.find(":")
        if c < 0:
            raise Refused("key_missing", "malformed")
        kid = line[:c]
        if _RE_KID.fullmatch(kid) is None:
            raise Refused("key_missing", "kid")
        raw = b64url_decode_strict(line[c + 1:])
        if raw is None or len(raw) < 32:
            raise Refused("key_missing", "key bytes")
        if kid not in ring.keys:
            ring.keys[kid] = raw
            ring.order.append(kid)
    if not ring.keys:
        raise Refused("key_missing", "empty")
    return ring


def select_key(ring: KeyRing, policy: Policy) -> Tuple[str, bytes]:
    """7.1: ``hmac.kid`` first, then ``accept_kids`` in order."""
    k = ring.keys.get(policy.kid)
    if k is not None:
        return policy.kid, k
    for kid in policy.accept_kids:
        a = ring.keys.get(kid)
        if a is not None:
            return kid, a
    raise Refused("key_mismatch")
