"""Executes one conformance vector (conformance/format.md, "Executing a vector").

This is the test function every source exposes (sanitizer.md 16). Nothing here needs
the network, the real clock or randomness.
"""

from __future__ import annotations

import base64
import os
from typing import Any, Dict, Optional

from .jsonlex import Num, parse_plain
from .policy import (
    Policy, Refused, check_acceptance, ed25519_public_key, parse_key_ring, parse_time, select_key,
    validate_body_schema, verify_envelope,
)
from .sanitizer import Exchange, Sanitizer


def _bytes(v: Any) -> bytes:
    if v is None:
        return b""
    if isinstance(v, str):
        return v.encode("utf-8")
    if isinstance(v, dict) and isinstance(v.get("b64"), str):
        return base64.b64decode(v["b64"])
    raise ValueError("bad bytes value")


def _num(v: Any) -> Optional[int]:
    return int(v.lex) if isinstance(v, Num) else None


def _headers(v: Any):
    if not isinstance(v, list):
        return []
    return [(p[0], _bytes(p[1])) for p in v]


def _total(v: Any):
    if v == "unknown":
        return "unknown"
    return _num(v)


def _bool(v: Any) -> Optional[bool]:
    return v if isinstance(v, bool) else None


def vector_exchange(inp: Dict[str, Any]) -> Exchange:
    """Converts the ``input`` object of a vector into a sanitizer exchange."""
    ex = Exchange(inp.get("dir", "inbound"), inp.get("method") or "", _bytes(inp.get("raw_path")))
    ex.raw_query = _bytes(inp["raw_query"]) if "raw_query" in inp else None
    ex.req_headers = _headers(inp.get("req_headers"))
    ex.req_body = _bytes(inp.get("req_body"))
    ex.req_body_total = _total(inp.get("req_body_total"))
    ex.req_body_consumed = _bool(inp.get("req_body_consumed"))
    ex.req_body_decoded = _bool(inp.get("req_body_decoded"))
    ex.resp_headers = _headers(inp.get("resp_headers"))
    ex.resp_body = _bytes(inp.get("resp_body"))
    ex.resp_body_total = _total(inp.get("resp_body_total"))
    ex.resp_body_consumed = _bool(inp.get("resp_body_consumed"))
    ex.resp_body_decoded = _bool(inp.get("resp_body_decoded"))
    for k in ("service_name", "url_base", "framework_route", "framework", "trace_id", "net_error"):
        if isinstance(inp.get(k), str):
            setattr(ex, k, inp[k])
    if isinstance(inp.get("inherited"), bool):
        ex.inherited = inp["inherited"]
    st = _num(inp.get("status"))
    if st is not None:
        ex.status = st
    return ex


def parse_vector(data: bytes) -> Dict[str, Any]:
    return parse_plain(data, strict=False)


def run_vector(vec: Dict[str, Any], root: str) -> Dict[str, str]:
    """Runs one parsed vector. ``root`` is the ``conformance/`` directory (for ``policy_ref``).

    Returns ``{"outcome": "event", "canonical": ...}``, ``{"outcome": "not_sampled",
    "sampled_by": ...}`` or ``{"outcome": "refused", "code": ...}``.
    """
    now = parse_time(vec["now"]) if isinstance(vec.get("now"), str) else None
    try:
        if "policy_envelope" in vec:
            keys = {}
            for kid, v in (vec.get("fleet_keys") or {}).items():
                k = ed25519_public_key(v)
                if k is not None:
                    keys[kid] = k
            body = verify_envelope(vec["policy_envelope"], keys, True).body
        elif isinstance(vec.get("policy_ref"), str):
            with open(os.path.join(root, vec["policy_ref"]), "rb") as f:
                body = validate_body_schema(parse_plain(f.read(), strict=True))
        elif "policy" in vec:
            body = validate_body_schema(vec["policy"])
        else:
            raise Refused("no_policy")
        policy = Policy(body)
        check_acceptance(
            policy,
            vec["source_group"] if isinstance(vec.get("source_group"), str) else "",
            now if now is not None else float("nan"),
            _num(vec.get("last_issued_seq")) or 0,
            _num(vec.get("min_issued_seq")) or 0,
        )
        ring = parse_key_ring(vec["hmac_key"] if isinstance(vec.get("hmac_key"), str) else None)
        kid, key = select_key(ring, policy)
        sanitizer = Sanitizer(policy, kid, key)
    except Refused as e:
        return {"outcome": "refused", "code": e.code}
    r = sanitizer.run(vector_exchange(vec["input"]), now)
    if r.outcome == "not_sampled":
        return {"outcome": "not_sampled", "sampled_by": r.sampled_by}
    if r.outcome == "too_large":
        return {"outcome": "refused", "code": "event_too_large"}
    return {"outcome": "event", "canonical": r.canonical}


def expected_matches(vec: Dict[str, Any], res: Dict[str, str]) -> bool:
    exp = vec["expected"]
    if exp["outcome"] != res["outcome"]:
        return False
    if exp["outcome"] == "event":
        return res["canonical"].encode("utf-8") == exp["canonical"].encode("utf-8")
    if exp["outcome"] == "not_sampled":
        return exp["sampled_by"] == res["sampled_by"]
    return exp["code"] == res["code"]
