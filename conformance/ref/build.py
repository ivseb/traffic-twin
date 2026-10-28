"""Builders shared by the vector definitions (gen_vectors.py).

All data is invented: e-commerce and carrier examples, *.example hosts.
"""

import base64

import ttjson as J
from policyload import b64url_nopad

N = lambda x: J.Num(str(x))  # noqa: E731

# Reference HMAC key of sanitizer.md 7.3: kid k1, 32 bytes 0x00..0x1f.
KEY_BYTES = bytes(range(32))
KEY = 'k1:' + b64url_nopad(KEY_BYTES)
EPOCH = '2026-10'

# Fleet signing key for envelope vectors (test only): seed 0x40..0x5f.
FLEET_SEED = bytes(range(0x40, 0x60))
FLEET_KID = 'fleet-test-1'

KEEP = {'action': 'keep'}
DROP = {'action': 'drop'}


def HMAC(domain='id'):
    return {'action': 'hmac', 'domain': domain}


def BNUM(*bounds):
    return {'action': 'bucket', 'kind': 'num', 'bounds': [J.Num(str(b)) for b in bounds]}


def BTIME(unit):
    return {'action': 'bucket', 'kind': 'time', 'unit': unit}


def part(path=None, query=None, headers=None, cookies=None, body=None):
    """A policy `part`; body is a dict tt-path -> action, compiled into a sorted list."""
    out = {}
    for name, m in (('path', path), ('query', query), ('headers', headers), ('cookies', cookies)):
        if m:
            out[name] = dict(m)
    if body:
        out['body'] = [{'path': p, 'action': body[p]} for p in sorted(body, key=lambda s: s.encode())]
    return out


def scope(request=None, response=None, errors=None):
    out = {}
    if request:
        out['request'] = request
    if response:
        out['response'] = response
    if errors:
        out['errors'] = errors
    return out


def service(name, inbound=True, base=None, ops=None, request=None, response=None, errors=None, internal=False):
    s = {'name': name, 'match': {'base': base} if base else {'inbound': True, 'internal': internal}}
    if request:
        s['request'] = request
    if response:
        s['response'] = response
    if errors:
        s['errors'] = errors
    oplist = []
    for key in sorted(ops or {}, key=lambda s: s.encode()):
        o = {'op': key}
        o.update(ops[key])
        oplist.append(o)
    s['ops'] = oplist
    return s


def op(request=None, response=None):
    out = {}
    if request:
        out['request'] = request
    if response:
        out['response'] = response
    return out


CREATED_AT = '2026-10-20T08:00:00Z'
NOT_AFTER = '2026-11-19T08:00:00Z'
NOW = '2026-10-23T10:00:00Z'
MODE_EXPIRES = '2026-10-26T10:00:00Z'
GROUP = 'shop'


def policy(global_=None, services=(), auto_words=False, allow=(), hosts_allow=(), limits=None, discovery=None,
           identity=None, rate_bp=10000, kid='k1', accept_kids=(), epoch=EPOCH, fmt='tt.policy.body/v1',
           trust_baggage=False, propagate_to=(), issued_seq=1, version=1, created_at=CREATED_AT,
           not_after=NOT_AFTER, groups=(GROUP,), auto_words_expires_at=MODE_EXPIRES, extra=None, hosts=None):
    """A tt.policy.body/v1 document (policy.md 2). discovery = (enabled, expires_at); hosts = 'auto' | 'off'
    (hosts.discovery, spec v1.5; None = absent, which means auto)."""
    lim = {'max_body_bytes': 1048576, 'max_depth': 32, 'max_array': 32, 'max_keys': 256, 'keep_max_bytes': 64}
    lim.update(limits or {})
    seg = {'auto_words': auto_words, 'allow': sorted(allow), 'hosts_allow': sorted(hosts_allow)}
    if auto_words and auto_words_expires_at:
        seg['auto_words_expires_at'] = auto_words_expires_at
    body = {
        'format': fmt,
        'policy_id': 'p-conformance',
        'version': N(version),
        'issued_seq': N(issued_seq),
        'created_at': created_at,
        'not_after': not_after,
        'targets': {'groups': list(groups)},
        'hmac': {'kid': kid, 'accept_kids': list(accept_kids), 'epoch': epoch},
        'sampling': {'rate_bp': N(rate_bp), 'trust_baggage': trust_baggage, 'propagate_to': sorted(propagate_to)},
        'segments': seg,
        'limits': {k: N(v) for k, v in lim.items()},
        'global': global_ or {},
        'services': sorted(services, key=lambda s: s['name'].encode()),
    }
    if identity:
        body['identity'] = {'subject': identity}
    if discovery:
        body['discovery'] = {'enabled': discovery[0], 'expires_at': discovery[1]}
    if hosts is not None:
        body['hosts'] = {'discovery': hosts}
    if extra:
        body.update(extra)
    return body


def as_bytes_field(v, force_b64=False):
    if isinstance(v, str):
        v = v.encode('utf-8')
    try:
        text = v.decode('utf-8')
        ok = True
    except UnicodeDecodeError:
        ok = False
    if ok and not force_b64:
        return text
    out = {'b64': base64.b64encode(v).decode('ascii')}
    if ok and len(v) <= 4096:
        out['text'] = text  # informative copy, omitted for large bodies
    return out


CT_JSON = ('Content-Type', 'application/json')


def X(method='GET', path='/', query=None, h=(), body=None, status=200, rh=(), rbody=None,
      dir='inbound', service='shop-api', url_base=None, framework_route=None, framework=None, trace_id=None,
      inherited=None, net_error=None, req_total=None, resp_total=None, req_consumed=None, resp_consumed=None,
      req_decoded=None, resp_decoded=None):
    """Build the `input` object of a vector."""
    inp = {'dir': dir}
    if dir == 'inbound':
        inp['service_name'] = service
    else:
        inp['url_base'] = url_base
    inp['method'] = method
    inp['raw_path'] = as_bytes_field(path)
    if query is not None:
        inp['raw_query'] = as_bytes_field(query)
    if framework_route is not None:
        inp['framework'] = framework
        inp['framework_route'] = framework_route
    if trace_id is not None:
        inp['trace_id'] = trace_id
    if inherited is not None:
        inp['inherited'] = inherited
    inp['req_headers'] = [[n, as_bytes_field(v)] for n, v in h]
    if body is not None:
        inp['req_body'] = as_bytes_field(body, force_b64=True)
    if req_total is not None:
        inp['req_body_total'] = req_total if req_total == 'unknown' else N(req_total)
    if req_consumed is not None:
        inp['req_body_consumed'] = req_consumed
    if req_decoded is not None:
        inp['req_body_decoded'] = req_decoded
    if net_error is not None:
        inp['net_error'] = net_error
    else:
        inp['status'] = N(status)
        inp['resp_headers'] = [[n, as_bytes_field(v)] for n, v in rh]
        if rbody is not None:
            inp['resp_body'] = as_bytes_field(rbody, force_b64=True)
        if resp_total is not None:
            inp['resp_body_total'] = resp_total if resp_total == 'unknown' else N(resp_total)
        if resp_consumed is not None:
            inp['resp_body_consumed'] = resp_consumed
        if resp_decoded is not None:
            inp['resp_body_decoded'] = resp_decoded
    return inp


FIXTURES = __import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), 'fixtures')


def gzip_bytes(data, deflate=False):
    """gzip (mtime 0) or zlib stream of `data`.

    Compressor output can differ between zlib builds, so each stream is created once and
    kept in ref/fixtures/ (named by the SHA-256 of the plaintext and the mode); later runs
    reuse it after checking that it still decompresses to the same plaintext.
    """
    import gzip
    import hashlib
    import os
    import zlib
    if isinstance(data, str):
        data = data.encode('utf-8')
    name = hashlib.sha256((b'zlib:' if deflate else b'gzip:') + data).hexdigest()[:24] + '.bin'
    path = os.path.join(FIXTURES, name)
    if os.path.exists(path):
        with open(path, 'rb') as fh:
            comp = fh.read()
        plain = zlib.decompress(comp) if deflate else gzip.decompress(comp)
        assert plain == data, path
        return comp
    comp = zlib.compress(data, 9) if deflate else gzip.compress(data, compresslevel=9, mtime=0)
    os.makedirs(FIXTURES, exist_ok=True)
    with open(path, 'wb') as fh:
        fh.write(comp)
    return comp


def jpost(body, path='/orders', **kw):
    """Inbound POST with a JSON request body."""
    h = kw.pop('h', ())
    return X('POST', path, h=[CT_JSON] + list(h), body=body, **kw)


def jresp(rbody, path='/orders/1', status=200, **kw):
    """Inbound GET with a JSON response body."""
    rh = kw.pop('rh', ())
    return X('GET', path, status=status, rh=[CT_JSON] + list(rh), rbody=rbody, **kw)
