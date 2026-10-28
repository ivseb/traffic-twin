"""Source-side policy and key loading (fail-closed), spec revision 1.1.

Spec: docs/spec/policy.md sections 3-4, docs/spec/sanitizer.md sections 1 and 7.1.
Every failure maps to a heartbeat state of api/fleet-api.v1.openapi.yaml:
no_policy, policy_rejected, expired_policy, key_missing, key_mismatch.
"""

import base64
import hashlib
import os
import re

import ed25519
import minischema
import ttjson as J

RESERVED_DOMAINS = {'subject', 'sample', 'sample-trace', 'discovery'}
KID_RE = re.compile(r'[a-z0-9]{1,8}')
B64URL_RE = re.compile(r'[A-Za-z0-9_-]*')
SIG_PREFIX = b'tt.policy.body/v1\x00'
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SCHEMA = None


class Refused(Exception):
    def __init__(self, code, detail=''):
        Exception.__init__(self, code)
        self.code = code
        self.detail = detail


def b64url_decode_nopad(s):
    """Strict base64url without padding. Returns bytes or None."""
    if not isinstance(s, str) or not B64URL_RE.fullmatch(s) or len(s) % 4 == 1:
        return None
    try:
        return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
    except Exception:  # noqa: BLE001
        return None


def b64url_nopad(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')


def parse_keys(material):
    """TT_HMAC_KEY content: one or more `<kid>:<base64url-nopad>` lines (7.1) -> {kid: key}."""
    if material is None:
        raise Refused('key_missing', 'no key')
    keys = {}
    for line in material.split('\n'):
        if line.endswith('\r'):
            line = line[:-1]
        if line == '':
            continue
        if ':' not in line:
            raise Refused('key_missing', 'malformed line')
        kid, enc = line.split(':', 1)
        key = b64url_decode_nopad(enc)
        if not KID_RE.fullmatch(kid) or key is None:
            raise Refused('key_missing', 'malformed line')
        if len(key) < 32:
            raise Refused('key_missing', 'key shorter than 32 bytes')
        if kid not in keys:  # A-KEY-DUPLICATE: first line wins
            keys[kid] = key
    if not keys:
        raise Refused('key_missing', 'no key line')
    return keys


def select_key(keys, policy):
    """7.1: hmac.kid, else the first of hmac.accept_kids the source holds."""
    h = policy['hmac']
    for kid in [h['kid']] + list(h.get('accept_kids') or []):
        if kid in keys:
            return kid, keys[kid]
    raise Refused('key_mismatch')


def body_schema():
    global _SCHEMA
    if _SCHEMA is None:
        with open(os.path.join(REPO, 'schemas', 'policy-compiled.v1.schema.json'), 'rb') as fh:
            root = J.to_py(J.parse(fh.read()))
        _SCHEMA = (minischema.Validator(root), root)
    return _SCHEMA


def _actions(part):
    for section in ('path', 'query', 'headers', 'cookies'):
        for a in (part.get(section) or {}).values():
            yield a
    for r in part.get('body') or []:
        yield r['action']


def _scopes(body):
    g = body.get('global') or {}
    for name in ('request', 'response', 'errors'):
        if name in g:
            yield g[name]
    for svc in body.get('services') or []:
        for name in ('request', 'response', 'errors'):
            if name in svc:
                yield svc[name]
        for op in svc.get('ops') or []:
            for name in ('request', 'response'):
                if name in op:
                    yield op[name]


CREDENTIAL_HEADERS = {'authorization', 'cookie', 'set-cookie', 'proxy-authorization'}
OPEN_WINDOW_S = 7 * 86400


def check_unsafe(body):
    """hardening.md 2.1 (v1.3), the fixed safety subset every source applies to a signed body:

    H1 keep, code (v1.11) or hmac on authorization, cookie, set-cookie, proxy-authorization (request, response and
       errors header rules; global, services and operations);
    H2 keep, code (v1.11) or hmac on a tt-path with any wildcard step (".*" or "[*]") in the global body rules;
    H3 discovery or auto_words expiring later than created_at + 7 days.
    Refusal is policy_rejected (heartbeat state); sources report the last_errors code policy_unsafe.
    """
    import sanitizer
    unsafe = lambda why: Refused('policy_rejected', 'unsafe: ' + why)  # noqa: E731
    for part in _scopes(body):
        for name, a in (part.get('headers') or {}).items():
            if name in CREDENTIAL_HEADERS and a.get('action') in ('keep', 'code', 'hmac'):
                raise unsafe('%s on header %s' % (a['action'], name))
    g = body.get('global') or {}
    for name in ('request', 'response', 'errors'):
        for r in (g.get(name) or {}).get('body') or []:
            if r['action'].get('action') in ('keep', 'code', 'hmac') and ('.*' in r['path'] or '[*]' in r['path']):
                raise unsafe('%s on %s in a global rule' % (r['action']['action'], r['path']))
    limit = sanitizer.rfc3339_seconds(body['created_at']) + OPEN_WINDOW_S
    seg = body.get('segments') or {}
    if seg.get('auto_words') is True and 'auto_words_expires_at' in seg \
            and sanitizer.rfc3339_seconds(seg['auto_words_expires_at']) > limit:
        raise unsafe('auto_words expires beyond created_at + 7 days')
    d = body.get('discovery')
    if d and d.get('enabled') is True and sanitizer.rfc3339_seconds(d['expires_at']) > limit:
        raise unsafe('discovery expires beyond created_at + 7 days')


def check_body(body):
    """policy.md 4, condition 1 and hardening.md 2.1: schema-valid body, no reserved HMAC domains, safe."""
    if not isinstance(body, dict) or body.get('format') != 'tt.policy.body/v1':
        raise Refused('policy_rejected', 'unknown body format')
    val, root = body_schema()
    errs = val.errors(body, root['$defs']['body'])
    if errs:
        raise Refused('policy_rejected', 'schema: ' + errs[0])
    for part in _scopes(body):
        for a in _actions(part):
            if a.get('action') == 'hmac' and a.get('domain') in RESERVED_DOMAINS:
                raise Refused('policy_rejected', 'reserved hmac domain')
    check_unsafe(body)
    return body


def check_acceptance(body, source_group, now_s, last_seq, min_seq):
    """policy.md 4, conditions 3-5."""
    import sanitizer
    if source_group not in body['targets']['groups']:
        raise Refused('policy_rejected', 'group not targeted')
    if not now_s < sanitizer.rfc3339_seconds(body['not_after']):
        raise Refused('expired_policy', 'not_after reached')
    seq = int(body['issued_seq'].lexeme)
    if seq <= last_seq or seq < min_seq:
        raise Refused('policy_rejected', 'issued_seq not increasing')


def _same_int(a, b):
    return isinstance(a, J.Num) and isinstance(b, J.Num) and J.canon_num(a.lexeme) == J.canon_num(b.lexeme)


def verify_envelope(env, fleet_keys):
    """tt.policy.compiled/v1 envelope -> body dict. policy.md 3 and 4, conditions 1-2."""
    if not isinstance(env, dict) or env.get('format') != 'tt.policy.compiled/v1':
        raise Refused('policy_rejected', 'unknown envelope format')
    sig = env.get('signature') or {}
    if sig.get('alg') != 'Ed25519':
        raise Refused('policy_rejected', 'unsupported signature algorithm')
    pub_enc = fleet_keys.get(sig.get('kid'))
    if pub_enc is None:
        raise Refused('policy_rejected', 'unknown signing kid')
    body_bytes = b64url_decode_nopad(env.get('body_b64'))
    if body_bytes is None:
        raise Refused('policy_rejected', 'body_b64 is not base64url without padding')
    if env.get('hash') != 'sha256:' + hashlib.sha256(body_bytes).hexdigest():
        raise Refused('policy_rejected', 'hash mismatch')
    sig_bytes = b64url_decode_nopad(sig.get('sig'))
    pub = b64url_decode_nopad(pub_enc)
    if sig_bytes is None or pub is None or not ed25519.verify(pub, SIG_PREFIX + body_bytes, sig_bytes):
        raise Refused('policy_rejected', 'bad signature')
    try:
        body = J.to_py(J.parse(body_bytes))
    except J.InvalidJSON:
        raise Refused('policy_rejected', 'body is not JSON')
    check_body(body)
    if body.get('policy_id') != env.get('policy_id') or not _same_int(body.get('version'), env.get('version')) \
            or not _same_int(body.get('issued_seq'), env.get('issued_seq')):
        raise Refused('policy_rejected', 'policy_id, version or issued_seq mismatch')
    return body


def make_envelope(body_bytes, seed, sign_kid, policy_id, version, issued_seq, prefix=SIG_PREFIX):
    """Build a signed envelope (generator side)."""
    return {
        'format': 'tt.policy.compiled/v1',
        'policy_id': policy_id,
        'version': version,
        'issued_seq': issued_seq,
        'hash': 'sha256:' + hashlib.sha256(body_bytes).hexdigest(),
        'body_b64': b64url_nopad(body_bytes),
        'signature': {'alg': 'Ed25519', 'kid': sign_kid,
                      'sig': b64url_nopad(ed25519.sign(seed, prefix + body_bytes))},
    }
