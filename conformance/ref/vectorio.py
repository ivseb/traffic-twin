"""Load and execute conformance vectors with the reference implementation.

This is also the executable description of what every runner must do (see
conformance/format.md, "Executing a vector").
"""

import base64
import os

import policyload as PL
import ttjson as J
from sanitizer import Sanitizer, rfc3339_seconds

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def decode_bytes(v):
    """`bytes` type of the vector format: a JSON string (its UTF-8 bytes) or {"b64": ...}."""
    if isinstance(v, str):
        if not J.is_valid_str(v):
            raise ValueError('string bytes must not contain lone surrogates')
        return v.encode('utf-8')
    raw = base64.b64decode(v['b64'], validate=True)
    if 'text' in v and v['text'].encode('utf-8') != raw:
        raise ValueError('informative text does not match b64')
    return raw


def load_input(inp):
    out = dict(inp)
    for f in ('raw_path', 'raw_query', 'req_body', 'resp_body'):
        if f in inp:
            out[f] = decode_bytes(inp[f])
    out.setdefault('raw_path', b'')
    for f in ('req_headers', 'resp_headers'):
        out[f] = [(n, decode_bytes(v)) for n, v in inp.get(f, [])]
    for f in ('req_body_total', 'resp_body_total', 'status'):
        if isinstance(inp.get(f), J.Num):
            out[f] = int(inp[f].lexeme)
    return out


def load_file(path):
    with open(path, 'rb') as fh:
        return J.to_py(J.parse(fh.read()))


def resolve_policy(vec, root=ROOT, refs=None):
    """Policy body after verification and body checks; raises PL.Refused (policy.md 4, condition 1-2)."""
    if 'policy_envelope' in vec:
        return PL.verify_envelope(vec['policy_envelope'], vec.get('fleet_keys') or {})
    if 'policy_ref' in vec:
        if refs is not None:
            return PL.check_body(J.to_py(J.parse(refs[vec['policy_ref']])))
        return PL.check_body(load_file(os.path.join(root, vec['policy_ref'])))
    if 'policy' in vec:
        return PL.check_body(vec['policy'])
    raise PL.Refused('no_policy')


def execute(vec, root=ROOT, refs=None):
    """Run one vector; returns the `expected`-shaped result. Order of checks: sanitizer.md 1."""
    num = lambda f: int(vec[f].lexeme) if f in vec else 0  # noqa: E731
    try:
        policy = resolve_policy(vec, root, refs)
        PL.check_acceptance(policy, vec.get('source_group'), rfc3339_seconds(vec['now']),
                            num('last_issued_seq'), num('min_issued_seq'))
        kid, key = PL.select_key(PL.parse_keys(vec.get('hmac_key')), policy)
    except PL.Refused as r:
        return {'outcome': 'refused', 'code': r.code}
    return Sanitizer(policy, kid, key, vec['now']).run(load_input(vec['input']))
