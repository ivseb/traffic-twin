"""Reference sanitizer (tt.sanitizer/v1, revision 1.1 + host patterns of spec v1.5), second implementation used to
compute the expected outputs of the conformance vectors.

Written from docs/spec/sanitizer.md only. Section numbers in comments refer to it.
Readings chosen where the text still allows more than one answer are tagged A-xxx and
listed in conformance/AMBIGUITIES.md; their switches live in specprofile.py.
"""

import hashlib
import hmac as _hmac
import re
import zlib
from fractions import Fraction

import bodies as B
import gqlshape
import specprofile as P
import ttjson as J
from policyload import b64url_nopad

# ------------------------------------------------------------------ grammar (0.1, 6.3)
# Every regex is used with fullmatch (whole input, 0.1) and explicit ASCII classes.

FORMATS = [
    ('uuid', r'[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}'),
    ('jwt', r'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'),
    ('email', r'[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+'),
    ('datetime', r'[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt ][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?([Zz]|[+-][0-9]{2}:[0-9]{2})'),
    ('date', r'[0-9]{4}-[0-9]{2}-[0-9]{2}'),
    ('url', r'[A-Za-z][A-Za-z0-9+.-]{0,15}://[!-~]+'),
    ('ipv4', r'(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}'),
    ('phone', r'\+[1-9][0-9]{6,14}'),
    ('digits', r'-?[0-9]{1,19}'),
    ('hex', r'[0-9A-Fa-f]{16,}'),
]
FORMATS = [(n, re.compile(r)) for n, r in FORMATS]
FORMAT_RE = dict(FORMATS)
PRINTABLE_RE = re.compile(r'[\x20-\x7e]*')
INT_LEXEME_RE = re.compile(r'-?(0|[1-9][0-9]*)')
KEY_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}')
SIX_DIGITS_RE = re.compile(r'[0-9]{6}')
NAME_FORMATS = ('uuid', 'email', 'hex', 'digits', 'jwt')
HEADER_NAME_RE = re.compile(r"[a-z0-9!#$%&'*+.^_`|~-]{1,64}")
CT_RE = re.compile(r'[a-z0-9.+-]{1,64}/[a-z0-9.+-]{1,64}')
AUTO_WORD_RE = re.compile(r'([a-z]+([-_][a-z]+)*|v[0-9]{1,3})')
METHOD_RE = re.compile(r'[A-Z]{1,16}')
SAFE_SEGMENT_RE = re.compile(r'[A-Za-z0-9._~-]{1,64}')
CODE_RE = re.compile(r'[A-Za-z_-]{2,32}', re.ASCII)  # 5.6, used with fullmatch
CODE_ALNUM_RE = re.compile(r'[A-Za-z0-9_.-]{1,16}', re.ASCII)  # 5.6, shape alnum (v1.19)
PARAM_NAME_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,63}')
DT_RE = re.compile(r'([0-9]{4})-([0-9]{2})-([0-9]{2})(?:[Tt ]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]{1,9})?'
                   r'(?:[Zz]|([+-])([0-9]{2}):([0-9]{2})))?')
TTPATH_STEP_RE = re.compile(r'\.(@?[A-Za-z_][A-Za-z0-9_-]{0,63}|#text)|\.\*|\[\*\]')
HOST_RE = re.compile(r'[a-z0-9.-]{1,253}')
SAFE_LABEL_RE = re.compile(r'[a-z][a-z0-9-]{0,62}')    # 3.5 rule a
HEX12_RE = re.compile(r'[0-9a-f]{12}')                 # 3.5 rule c
HEXGROUP_RE = re.compile(r'[0-9a-f]{1,4}')             # 3.1 IPv6 groups
OWS = b' \t'


def len_class(n):
    for bound, name in P.LEN_CLASSES:
        if bound is None or n <= bound:
            return name
    raise AssertionError


def ascii_lower(s):
    return ''.join(chr(ord(c) + 32) if 'A' <= c <= 'Z' else c for c in s)


def ascii_upper(s):
    return ''.join(chr(ord(c) - 32) if 'a' <= c <= 'z' else c for c in s)


def detect_format(s):
    """6.3: only printable ASCII strings; first match wins."""
    if not PRINTABLE_RE.fullmatch(s):
        return None
    for name, rx in FORMATS:
        if rx.fullmatch(s):
            return name
    return None


def str_shape(s):
    if not J.is_valid_str(s):
        return 'drop:str:invalid'
    f = detect_format(s)
    if f:
        return 'drop:str:' + f
    return 'drop:str:' + len_class(len(s.encode('utf-8')))


def shape(kind, v):
    """6.2 for a leaf. kind in str, num, bool, null."""
    if kind == 'null':
        return 'drop:null'
    if kind == 'bool':
        return 'drop:bool'
    if kind == 'num':
        return 'drop:int' if INT_LEXEME_RE.fullmatch(v.lexeme) else 'drop:dec'
    return str_shape(v)


def violates_name_formats(name):
    """9.3 point 3, second half: recognized formats or six consecutive digits."""
    return any(FORMAT_RE[f].fullmatch(name) for f in NAME_FORMATS) or SIX_DIGITS_RE.search(name) is not None


def name_is_literal(k):
    """9.3 point 3: rule of names for JSON keys, query, cookie and form names."""
    if k is None or not J.is_valid_str(k) or not KEY_RE.fullmatch(k):
        return False
    return not violates_name_formats(k)


def xml_key_is_literal(k):
    """22.2 point 8: keys of an XML tree: #text, @ + attribute name, element name."""
    if k == '#text':
        return True
    if k.startswith('@'):
        return name_is_literal(k[1:])
    return name_is_literal(k)


def header_name_out(lname):
    """8.0 point 2."""
    if HEADER_NAME_RE.fullmatch(lname) and not violates_name_formats(lname):
        return lname
    return '{*}'


def leaf_kind(v):
    if v is None:
        return 'null'
    if v is True or v is False:
        return 'bool'
    if isinstance(v, J.Num):
        return 'num'
    return 'str'


def lexeme_ok(lexeme):
    """5.3 limits on number lexemes: at most 64 bytes, |written exponent| <= 9999."""
    if len(lexeme) > P.LEXEME_MAX_BYTES:
        return False
    m = re.search(r'[eE]([+-]?)([0-9]+)$', lexeme)
    return m is None or int(m.group(2)) <= P.EXPONENT_MAX


def value_bytes(kind, v):
    """7.2 / 15: canonical value bytes, or None when the leaf has no usable value."""
    if kind == 'str':
        return v.encode('utf-8') if J.is_valid_str(v) else None
    if kind == 'num':
        return J.canon_num(v.lexeme).encode('ascii') if lexeme_ok(v.lexeme) else None
    if kind == 'bool':
        return b'true' if v else b'false'
    return b'null'


# ------------------------------------------------------------------ time (5.5)

def _days_in_month(y, m):
    if m == 2:
        leap = (y % 4 == 0 and y % 100 != 0) or y % 400 == 0
        return 29 if leap else 28
    return 30 if m in (4, 6, 9, 11) else 31


def _days_from_civil(y, m, d):
    y -= m <= 2
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _civil_from_days(z):
    z += 719468
    era = (z if z >= 0 else z - 146096) // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + (3 if mp < 10 else -9)
    return y + (m <= 2), m, d


def parse_time_utc(s):
    """5.5: datetime/date -> (y, m, d, hour) in UTC, or None."""
    if not (FORMAT_RE['datetime'].fullmatch(s) or FORMAT_RE['date'].fullmatch(s)):
        return None
    m = DT_RE.fullmatch(s)
    y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
    hh = int(m.group(4)) if m.group(4) else 0
    mi = int(m.group(5)) if m.group(5) else 0
    ss = int(m.group(6)) if m.group(6) else 0
    if not (1 <= y <= 9999 and 1 <= mo <= 12 and 1 <= d <= _days_in_month(y, mo)
            and hh <= 23 and mi <= 59 and ss <= 59):
        return None
    off = 0
    if m.group(7):
        oh, om = int(m.group(8)), int(m.group(9))
        if oh > 23 or om > 59:
            return None
        off = (oh * 60 + om) * (1 if m.group(7) == '+' else -1)
    minutes = _days_from_civil(y, mo, d) * 1440 + hh * 60 + mi - off
    days, rem = divmod(minutes, 1440)
    y2, mo2, d2 = _civil_from_days(days)
    if not 1 <= y2 <= 9999:
        return None
    return y2, mo2, d2, rem // 60


def bucket_time(s, unit):
    t = parse_time_utc(s)
    if t is None:
        return None
    y, mo, d, h = t
    return {'year': 'time:%04d' % y, 'month': 'time:%04d-%02d' % (y, mo),
            'day': 'time:%04d-%02d-%02d' % (y, mo, d), 'hour': 'time:%04d-%02d-%02dT%02d' % (y, mo, d, h)}[unit]


def bucket_num(lexeme, bounds):
    v = float(lexeme)  # correctly rounded, overflow -> inf, underflow -> +-0
    bvals = [float(b.lexeme) for b in bounds]
    bs = [J.canon_num(b.lexeme) for b in bounds]
    if v < bvals[0]:
        return 'num:<' + bs[0]
    for i in range(len(bvals) - 1):
        if bvals[i] <= v < bvals[i + 1]:
            return 'num:%s-%s' % (bs[i], bs[i + 1])
    return 'num:>=' + bs[-1]


# ------------------------------------------------------------------ bytes helpers

def pct_decode(b, plus_is_space=False):
    """4.1.2 / 8.3.3: %XY -> byte; a % not followed by two hex digits stays literal."""
    if plus_is_space:
        b = b.replace(b'+', b' ')
    out = bytearray()
    i = 0
    hexd = b'0123456789abcdefABCDEF'
    while i < len(b):
        c = b[i]
        if c == 0x25 and i + 2 < len(b) and b[i + 1] in hexd and b[i + 2] in hexd:
            out.append(int(b[i + 1:i + 3], 16))
            i += 3
        else:
            out.append(c)
            i += 1
    return bytes(out)


def utf8_or_none(b):
    try:
        return b.decode('utf-8')  # strict RFC 3629 (0.2)
    except UnicodeDecodeError:
        return None


def rfc3339_seconds(s):
    m = re.fullmatch(r'([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?'
                     r'([Zz]|([+-])([0-9]{2}):([0-9]{2}))', s)
    if not m:
        raise ValueError('bad RFC 3339 time %r' % s)
    days = _days_from_civil(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    sec = days * 86400 + int(m.group(4)) * 3600 + int(m.group(5)) * 60 + int(m.group(6))
    frac = Fraction(int(m.group(7)[1:]), 10 ** (len(m.group(7)) - 1)) if m.group(7) else 0
    if m.group(9):
        off = (int(m.group(10)) * 60 + int(m.group(11))) * 60
        sec -= off if m.group(9) == '+' else -off
    return sec + frac


# ------------------------------------------------------------------ header normalization (8.0)

def normalize_headers(pairs):
    """-> ordered list of (output name, [original lowercase names], value bytes or list for set-cookie)."""
    groups = {}
    order = []
    for name, val in pairs:
        if name.startswith(':'):
            continue
        lname = ascii_lower(name)
        oname = header_name_out(lname)
        if oname not in groups:
            groups[oname] = ([], [])
            order.append(oname)
        groups[oname][0].append(lname)
        groups[oname][1].append(val.strip(OWS))
    out = []
    for oname in order:
        names, vals = groups[oname]
        if oname == 'set-cookie':
            out.append((oname, names, vals))
        elif oname == 'cookie':
            out.append((oname, names, b'; '.join(vals)))
        else:
            out.append((oname, names, b', '.join(vals)))
    return out


def header_value(norm, name):
    for oname, _, v in norm:
        if oname == name:
            return v
    return None


def media_value(norm, name):
    """8.1.5-6: part before the first ';', OWS stripped, lowercase; None if no header."""
    v = header_value(norm, name)
    if v is None:
        return None
    s = utf8_or_none(v)
    if s is None:
        return 'invalid' if name == 'content-type' else '\x00invalid'
    mt = ascii_lower(s.split(';', 1)[0].strip(' \t'))
    if name == 'content-type':
        return mt if CT_RE.fullmatch(mt) else 'invalid'
    return mt


# ------------------------------------------------------------------ framework routes (3.4)

FRAMEWORKS = ('express', 'koa', 'fastify', 'flask', 'fastapi', 'django', 'spring', 'jaxrs',
              'aspnetcore', 'gin', 'chi', 'nethttp', 'laravel', 'symfony')
_N = r'([A-Za-z_][A-Za-z0-9_]*)'
FRAMEWORK_PARAMS = {
    # framework: list of (regex, group index of the name, optional predicate on the match)
    'express': [(r':' + _N + r'(\([^/]*\))?', 1, None)],
    'flask': [(r'<' + _N + r'>', 1, None), (r'<([a-z_]+):' + _N + r'>', 2, lambda m: m.group(1) != 'path')],
    'fastapi': [(r'\{' + _N + r'\}', 1, None), (r'\{' + _N + r':([a-z_]+)\}', 1, lambda m: m.group(2) != 'path')],
    'spring': [(r'\{' + _N + r'\}', 1, None), (r'\{' + _N + r':[^{}/]+\}', 1, None)],
    'jaxrs': [(r'\{[ \t]*' + _N + r'[ \t]*\}', 1, None), (r'\{[ \t]*' + _N + r'[ \t]*:[^/]*\}', 1, None)],
    'aspnetcore': [(r'\{' + _N + r'\}', 1, None), (r'\{' + _N + r'(:[^{}?=*/]+)+\}', 1, None)],
    'gin': [(r':' + _N, 1, None)],
    'chi': [(r'\{' + _N + r'\}', 1, None), (r'\{' + _N + r':[^/]+\}', 1, None)],
    'nethttp': [(r'\{' + _N + r'\}', 1, None)],
    'laravel': [(r'\{' + _N + r'\}', 1, None)],
    'symfony': [(r'\{' + _N + r'\}', 1, None), (r'\{' + _N + r'<[^>/]+>\}', 1, None)],
}
FRAMEWORK_PARAMS['koa'] = FRAMEWORK_PARAMS['express']
FRAMEWORK_PARAMS['fastify'] = FRAMEWORK_PARAMS['express']
FRAMEWORK_PARAMS['django'] = FRAMEWORK_PARAMS['flask']


def normalize_framework_route(framework, route):
    """3.4 -> list of ('l', literal) / ('p', name), or None if the route cannot be normalized.

    Every segment that is not a recognized parameter syntax must be a literal of the
    operation key grammar, so the "not normalizable" cases of the table (wildcards,
    optional or catch-all parameters, mixed segments, regex routes) all fail here.
    """
    if framework not in FRAMEWORK_PARAMS:
        return None
    raw = [s for s in route.split('/') if s]
    if framework == 'nethttp' and raw and raw[-1] == '{$}':
        raw = raw[:-1]
    segs = []
    for s in raw:
        for rx, gi, pred in FRAMEWORK_PARAMS[framework]:
            m = re.fullmatch(rx, s)
            if m and (pred is None or pred(m)):
                name = m.group(gi)
                if not PARAM_NAME_RE.fullmatch(name):
                    return None
                segs.append(('p', name))
                break
        else:
            if not SAFE_SEGMENT_RE.fullmatch(s):
                return None
            segs.append(('l', s))
    if len(segs) > P.MAX_PATH_SEGMENTS:
        return None
    return segs


# ------------------------------------------------------------------ the sanitizer

class Sanitizer:
    def __init__(self, policy, kid, key, now):
        self.p = policy
        self.kid = kid
        self.key = key
        self.epoch = policy['hmac']['epoch'].encode('ascii')
        lim = policy['limits']
        self.max_body = int(lim['max_body_bytes'].lexeme)
        self.max_depth = int(lim['max_depth'].lexeme)
        self.max_array = int(lim['max_array'].lexeme)
        self.max_keys = int(lim['max_keys'].lexeme)
        self.keep_max = int(lim['keep_max_bytes'].lexeme)
        bd = policy.get('bodies')  # 20 (v1.19); absent = every switch off
        self.xml = bool(bd and bd['xml'])
        self.multipart = bool(bd and bd['multipart'])
        self.docs = bool(bd and bd['docs'])
        self.large_max = int(bd['max_large_body_bytes'].lexeme) if bd else 0
        self.large_array = int(bd['large_array'].lexeme) if bd else 0
        self.large_nested = int(bd['large_nested_array'].lexeme) if bd else 0
        seg = policy['segments']
        now_s = rfc3339_seconds(now)
        mode_end = rfc3339_seconds(policy['created_at']) + P.MODE_MAX_SECONDS
        self.auto_words = bool(seg['auto_words'] and now_s < rfc3339_seconds(seg['auto_words_expires_at'])
                               and now_s < mode_end)  # 4.3
        self.allow = set(seg['allow'])
        self.hosts_allow = set(seg['hosts_allow'])
        self.hosts_auto = (policy.get('hosts') or {}).get('discovery', 'auto') == 'auto'  # 3.1, 3.5 (v1.5)
        dsc = policy.get('discovery')
        self.disc = {} if (dsc and dsc['enabled'] and now_s < rfc3339_seconds(dsc['expires_at'])
                           and now_s < mode_end) else None  # 15
        self.svc = None
        self.op = None
        self.resp = False  # 5.7: set while the response is sanitized
        self.gql_seen = False
        self.gql_nonintro = False

    # ---------------------------------------------------------- HMAC (7.2)

    def mac(self, domain, value):
        return _hmac.new(self.key, self.epoch + b'\x00' + domain.encode('ascii') + b'\x00' + value,
                         hashlib.sha256).digest()

    def token(self, domain, value):
        return 'tk1:' + self.kid + ':' + b64url_nopad(self.mac(domain, value)[:16])

    def disc_add(self, path, vb):
        if self.disc is None or vb is None:
            return
        cur = self.disc.get(path)
        if cur is None or vb < cur:
            self.disc[path] = vb

    def disc_out(self):
        paths = sorted(self.disc, key=lambda p: p.encode('utf-8'))[:P.DISC_MAX_PATHS]
        return {p: 'tkd:' + b64url_nopad(self.mac('discovery', p.encode('utf-8') + b'\x00' + self.disc[p])[:4])
                for p in paths}

    # ---------------------------------------------------------- actions (5)

    def shape(self, kind, v):
        """6.2, with the document shape of 22.4 when bodies.docs is on."""
        if self.docs and kind == 'str' and J.is_valid_str(v) and not detect_format(v):
            d = B.base64_doc(v)
            if d is not None:
                return d
        return shape(kind, v)

    def apply(self, action, kind, v, disc_path=None):
        """Apply an action (dict, or None = default drop) to a leaf."""
        if kind == 'str' and not J.is_valid_str(v):
            self.gql_unusable(action)
            return 'drop:str:invalid'
        if action is None:
            if disc_path is not None:
                self.disc_add(disc_path, value_bytes(kind, v))
            return self.shape(kind, v)
        a = action['action']
        if a == 'keep':
            if kind == 'str':
                return 'keep:' + v if len(v.encode('utf-8')) <= self.keep_max else self.shape(kind, v)
            if kind == 'num':
                return J.Num(J.canon_num(v.lexeme)) if lexeme_ok(v.lexeme) else self.shape(kind, v)
            return v
        if a == 'code':
            # 5.6 (spec v1.11): a code-shaped string within keep_max_bytes leaves as keep:.
            # v1.19: the shape alnum allows digits and dots, 1 to 16 bytes.
            rx = CODE_ALNUM_RE if action.get('shape') == 'alnum' else CODE_RE
            if kind == 'str' and rx.fullmatch(v) and len(v.encode('utf-8')) <= self.keep_max:
                return 'keep:' + v
            return self.shape(kind, v)
        if a == 'graphql':
            return self.graphql_leaf(kind, v)
        if a == 'hmac':
            vb = value_bytes(kind, v) if kind in ('str', 'num') else None
            return self.token(action['domain'], vb) if vb is not None else self.shape(kind, v)
        if a == 'bucket':
            if action['kind'] == 'num':
                if kind == 'num' and lexeme_ok(v.lexeme):
                    return bucket_num(v.lexeme, action['bounds'])
                return self.shape(kind, v)
            if kind == 'str':
                r = bucket_time(v, action['unit'])
                if r is not None:
                    return r
            return self.shape(kind, v)
        return self.shape(kind, v)  # explicit drop

    # ---------------------------------------------------------- graphql (5.7, spec v1.14)

    def gql_gate(self):
        return self.gql_seen and not self.gql_nonintro

    def gql_unusable(self, action):
        """A request value under a graphql rule without usable text closes the gate."""
        if action is not None and action.get('action') == 'graphql' and not self.resp:
            self.gql_seen = self.gql_nonintro = True

    def graphql_leaf(self, kind, v):
        if not self.resp:
            self.gql_seen = True
            r = gqlshape.shape(v) if kind == 'str' else None
            if r is None:
                self.gql_nonintro = True
                return shape(kind, v)
            if not r[1]:
                self.gql_nonintro = True
            return 'gql:' + r[0]
        if kind == 'str' and self.gql_gate() and gqlshape.is_name(v) and gqlshape.name_safe(v):
            return 'gql:' + v
        return shape(kind, v)

    # ---------------------------------------------------------- rule groups (5.0)

    def groups(self, part, status=None):
        """Groups 1, 2a, 2b, 3, 4 (5.0) as a list of policy parts."""
        g = self.p.get('global') or {}
        out = []
        if self.op is not None:
            out.append(self.op.get(part) or {})
        if part == 'response' and status is not None and status >= 400:
            if self.svc is not None:
                out.append(self.svc.get('errors') or {})
            out.append(g.get('errors') or {})
        if self.svc is not None:
            out.append(self.svc.get(part) or {})
        out.append(g.get(part) or {})
        return out

    @staticmethod
    def named_rule(groups, section, name):
        if name is None:
            return None
        for grp in groups:
            m = grp.get(section) or {}
            if name in m:
                return m[name]
        return None

    @staticmethod
    def leaf_rule(groups, steps):
        """First group with a matching rule; inside it, more .name steps, then smaller bytes."""
        for grp in groups:
            best = None
            for r in grp.get('body') or []:
                rs = parse_ttpath(r['path'])
                if ttpath_matches(rs, steps):
                    k = (-sum(1 for s in rs if s[0] == 'n'), r['path'].encode('utf-8'))
                    if best is None or k < best[0]:
                        best = (k, r['action'])
            if best is not None:
                return best[1]
        return None

    @staticmethod
    def container_drop(groups, steps):
        """5.0 "Contenitori": True if an explicit drop collapses the container at `steps`."""
        for gi, grp in enumerate(groups):
            hit = None
            for r in grp.get('body') or []:
                if ttpath_matches(parse_ttpath(r['path']), steps):
                    if r['action']['action'] == 'drop':
                        hit = 'drop'
                    elif P.CONTAINER_NON_DROP_SHADOWS and hit is None:
                        hit = 'other'
            if hit == 'other':
                return False
            if hit == 'drop':
                for g in groups[:gi + 1]:
                    for r in g.get('body') or []:
                        rs = parse_ttpath(r['path'])
                        if len(rs) > len(steps) and ttpath_matches(rs[:len(steps)], steps):
                            return False
                return True
        return False

    # ---------------------------------------------------------- service and template (3)

    def select_service(self, inp, segs):
        """3.1 -> (service, number of base segments)."""
        services = self.p.get('services') or []
        if inp['dir'] == 'inbound':
            for s in services:
                if s['match'].get('inbound') is True and s['name'] == inp['service_name']:
                    self.svc = s
            return inp['service_name'], 0
        origin, host = normalize_url_base(inp['url_base'])
        if origin is None:
            return 'host:invalid', 0
        best = None
        for s in services:
            base = s['match'].get('base')
            if base is None:
                continue
            borigin, bsegs = split_base(base)
            if borigin != origin or len(bsegs) > len(segs):
                continue
            if any(segs[i][1] != bsegs[i] for i in range(len(bsegs))):
                continue
            if best is None or len(bsegs) > best[1]:
                best = (s, len(bsegs))
        if best is not None:
            self.svc = best[0]
            return best[0]['name'], best[1]
        hp, hparts = host
        if hp in self.hosts_allow:
            return 'host:' + hp, 0
        if self.hosts_auto or self.disc is not None:
            pat = host_pattern(*hparts)
            return ('host:' + pat if pat is not None else 'host:invalid'), 0
        return 'host:unlisted', 0

    def select_template(self, method, opsegs, truncated, framework, framework_route):
        if method == 'OTHER' or truncated:
            return None, None, 'raw'
        parsed = []
        for op in (self.svc or {}).get('ops') or []:
            m, tmpl = parse_op_key(op['op'])
            if m == method:
                parsed.append((op, tmpl))
        if framework_route is not None:
            fr = normalize_framework_route(framework, framework_route)
            if fr is not None and len(fr) == len(opsegs):
                for op, tmpl in parsed:
                    if len(tmpl) == len(fr) and all((a[0] == 'p' and b[0] == 'p') or a == b
                                                    for a, b in zip(tmpl, fr)):
                        return op, tmpl, 'framework'
        best = None
        for op, tmpl in parsed:
            if len(tmpl) != len(opsegs):
                continue
            ok, lits = True, 0
            for (kind, val), (_, dec) in zip(tmpl, opsegs):
                if dec is None or (kind == 'l' and dec != val):
                    ok = False
                    break
                lits += kind == 'l'
            if ok:
                k = (-lits, op['op'].encode('utf-8'))
                if best is None or k < best[0]:
                    best = (k, op, tmpl)
        if best is not None:
            return best[1], best[2], 'policy'
        return None, None, 'raw'

    # ---------------------------------------------------------- path (4)

    def path_segment(self, i, dec, tmpl_seg, groups):
        if dec is None:
            return '{drop:bytes}'
        if tmpl_seg is not None:
            kind, val = tmpl_seg
            if kind == 'l':
                return val
            rule = self.named_rule(groups, 'path', val)
            if rule is not None and not SAFE_SEGMENT_RE.fullmatch(dec):
                if rule['action'] == 'keep' or (rule['action'] == 'bucket' and rule.get('kind') == 'time'
                                                and P.PATH_TIME_NEEDS_SAFE_VALUE):
                    rule = {'action': 'drop'}
            return '{' + self.apply(rule, 'str', dec, 'req.path.%d' % i) + '}'
        if dec in self.allow or (self.auto_words and len(dec.encode('utf-8')) <= P.AUTO_WORD_MAX_BYTES
                                 and AUTO_WORD_RE.fullmatch(dec)):
            return dec
        return '{' + self.apply(None, 'str', dec, 'req.path.%d' % i) + '}'

    # ---------------------------------------------------------- named parts (8)

    def name_map(self, entries, rule_for, disc_prefix, collapsed_disc, trunc_as_array=True):
        """entries: (output name, original name or None, value str or None for bytes, forced_drop).

        Applies the 64-name limit (8.1.4) and the per-name max_array limit (8.2)."""
        values = {}
        order = []
        for oname, orig, val, forced in entries:
            if oname not in values:
                values[oname] = []
                order.append(oname)
            values[oname].append((orig, val, forced))
        out = {}
        for oname in order[:P.NAME_LIMIT]:
            vals = values[oname]
            toks = []
            dpath = disc_prefix + (collapsed_disc if oname == '{*}' else '.' + oname)
            for orig, val, forced in vals[:self.max_array]:
                if val is None:
                    if not forced:
                        self.gql_unusable(rule_for(orig))
                    toks.append('drop:bytes')
                elif isinstance(val, tuple):  # a ready token (multipart file part, 22.3)
                    toks.append(val[1])
                elif forced:
                    toks.append(self.apply(None, 'str', val, dpath if P.NOEQ_PARTS_IN_DISCOVERY else None))
                else:
                    toks.append(self.apply(rule_for(orig), 'str', val, dpath))
            if len(vals) > self.max_array:
                toks.append('trunc:n:' + len_class(len(vals)))
            out[oname] = toks
        if len(order) > P.NAME_LIMIT:
            t = 'trunc:keys:' + len_class(len(order))
            out['{trunc}'] = [t] if trunc_as_array else t
        return out

    def headers(self, side, norm, part, status):
        groups = self.groups(part, status)
        out = {}
        names = [(o, ns, v) for o, ns, v in norm if o not in ('cookie', 'set-cookie')]
        for oname, origs, val in names[:P.NAME_LIMIT]:
            if oname != '{*}':
                rule = self.named_rule(groups, 'headers', oname)
            elif not P.COLLAPSED_HEADER_RULE_SINGLE_NAME or len(set(origs)) == 1:
                rule = self.named_rule(groups, 'headers', origs[0])
            else:
                rule = None
            s = utf8_or_none(val)
            if s is None:
                self.gql_unusable(rule)
                out[oname] = ['drop:bytes']
                continue
            out[oname] = [self.apply(rule, 'str', s, '%s.headers.%s' % (side, oname))]
        if len(names) > P.NAME_LIMIT:
            out['{trunc}'] = ['trunc:keys:' + len_class(len(names))]
        return out

    def cookies(self, side, norm, part, status):
        groups = self.groups(part, status)
        pairs = []
        if part == 'request':
            v = header_value(norm, 'cookie')
            for piece in (v.split(b';') if v is not None else []):
                piece = piece.strip(OWS)
                if b'=' in piece:
                    pairs.append(piece.split(b'=', 1))
        else:
            for v in header_value(norm, 'set-cookie') or []:
                piece = v.split(b';', 1)[0].strip(OWS)
                if b'=' in piece:
                    pairs.append(piece.split(b'=', 1))
        entries = []
        for nb, vb in pairs:
            name = utf8_or_none(nb)
            oname = name if name_is_literal(name) else '{*}'
            entries.append((oname, name, utf8_or_none(vb), False))
        return self.name_map(entries, lambda n: self.named_rule(groups, 'cookies', n),
                             side + '.cookies', '.{*}')

    def urlencoded_entries(self, raw):
        """8.3 points 1-4 -> name_map entries."""
        entries = []
        for part in raw.split(b'&'):
            if not part:
                continue
            if b'=' not in part:
                entries.append(('{*}', None, utf8_or_none(pct_decode(part, True)), True))
                continue
            nb, vb = part.split(b'=', 1)
            name = utf8_or_none(pct_decode(nb, True))
            oname = name if name_is_literal(name) else '{*}'
            entries.append((oname, name, utf8_or_none(pct_decode(vb, True)), False))
        return entries

    # ---------------------------------------------------------- body (9)

    def treatment(self, ct):
        """9.1 and 22.1: json, form, xml, multipart or None (not parsed)."""
        if ct is None:
            return None
        if ct == 'application/json' or ct.endswith('+json'):
            return 'json'
        if ct == 'application/x-www-form-urlencoded':
            return 'form'
        if self.xml and (ct in ('application/xml', 'text/xml') or ct.endswith('+xml')):
            return 'xml'
        if self.multipart and ct == 'multipart/form-data':
            return 'multipart'
        return None

    def body(self, side, part, norm, data, total, consumed, decoded, status):
        """9.0, 9.1 and 20 -> dict with size, body and, for XML and multipart, fmt and xmlns."""
        kind = self.treatment(media_value(norm, 'content-type'))
        res = self.body_inner(side, part, norm, data, total, consumed, decoded, status, kind)
        if 'body' in res and kind in ('xml', 'multipart') and 'fmt' not in res:
            res['fmt'] = kind  # 22.1: fmt whenever a body leaves under the XML or multipart treatment
        return res

    def body_inner(self, side, part, norm, data, total, consumed, decoded, status, kind):
        groups = self.groups(part, status)
        res = {}
        if total is None:
            total = len(data)
        if not consumed or total == 'unknown':
            res.update({'size': 'lmax', 'body': 'trunc:size'})
            return res
        if total == 0:
            res['size'] = len_class(0)
            return res
        cap = max(self.max_body, self.large_max)  # 22.5: the decoding cap includes the large limit
        enc = media_value(norm, 'content-encoding')
        if enc in (None, 'identity'):
            length = total
        elif enc in ('gzip', 'x-gzip', 'deflate'):
            if decoded:
                length = total
            else:
                data = inflate(data, 31 if enc != 'deflate' else 15, cap + 1)
                if data is None:
                    res['body'] = 'drop:bytes'
                    return res
                length = len(data)
        else:
            res['body'] = 'drop:bytes'
            return res
        large = False
        if length > self.max_body:
            if kind is None or length > self.large_max:
                res.update({'size': 'lmax', 'body': 'trunc:size'})
                return res
            large = True  # 22.5
        res['size'] = len_class(length)
        ct = media_value(norm, 'content-type')
        if ct == 'application/graphql' and len(data) == length:  # a prefix is never parsed
            rule = self.leaf_rule(groups, [])
            if rule is not None and rule['action'] == 'graphql':  # 9.1, 5.7 (spec v1.14)
                s = utf8_or_none(data)
                if s is None or not J.is_valid_str(s):
                    self.gql_unusable(rule)
                    res['body'] = 'drop:str:invalid'
                else:
                    res['body'] = self.apply(rule, 'str', s)
                return res
        if kind is not None and len(data) < length:
            res['body'] = 'trunc:size'  # only a prefix of a parsed body: it cannot be analysed
            return res
        if kind == 'json':
            try:
                tree = J.parse(data, self.max_depth)
            except J.InvalidJSON:
                res['body'] = 'trunc:invalid-json'
                return res
            res['body'] = self.walk(tree, [], groups, side + '.body', large=large)
        elif kind == 'form':
            res['body'] = self.name_map(self.urlencoded_entries(data), self.form_rule(groups), side + '.body', '.*',
                                        trunc_as_array=P.FORM_TRUNC_AS_ARRAY)
        elif kind == 'xml':
            try:
                root = B.parse_xml(data)
            except B.InvalidXML:
                res['body'] = 'trunc:invalid-xml'
                return res
            tree, entries, fmt = B.xml_tree(root, name_is_literal, self.max_depth)
            res['fmt'] = fmt
            res['body'] = self.walk(trunc_depth(tree, 1, self.max_depth), [], groups, side + '.body',
                                    xml=True, large=large)
            if entries:
                xmlns = dict(entries[:P.NAME_LIMIT])
                if len(entries) > P.NAME_LIMIT:
                    xmlns['{trunc}'] = 'trunc:keys:' + len_class(len(entries))
                res['xmlns'] = xmlns
        elif kind == 'multipart':
            boundary = B.media_params(header_value(norm, 'content-type')).get('boundary')
            try:
                parts = B.parse_multipart(data, boundary)
            except B.InvalidMultipart:
                res['body'] = 'trunc:invalid-multipart'
                return res
            entries = []
            for name, is_file, content, pct in parts:
                oname = name if name_is_literal(name) else '{*}'
                if is_file:
                    entries.append((oname, name, ('tok', B.file_token(content, pct)), True))
                else:
                    entries.append((oname, name, utf8_or_none(content), False))
            res['body'] = self.name_map(entries, self.form_rule(groups), side + '.body', '.*')
        else:
            res['body'] = 'drop:bytes:' + len_class(length)
        return res

    def form_rule(self, groups):
        def rule_for(name):
            return self.leaf_rule(groups, [('m', name)]) if name is not None else None
        return rule_for

    def walk(self, node, steps, groups, dpath, xml=False, large=False, arr_level=0):
        if node is J.TRUNC_DEPTH:
            return 'trunc:depth'
        if isinstance(node, J.Obj):
            if self.container_drop(groups, steps):
                return 'drop:obj:' + len_class(len(node.members))
            out = {}
            coll = []
            lit = xml_key_is_literal if xml else name_is_literal
            for k, v in node.members[:self.max_keys]:
                if lit(k):
                    out[k] = self.walk(v, steps + [('m', k)], groups, dpath + '.' + k, xml, large, arr_level)
                else:
                    coll.append(self.walk(v, steps + [('m', k)], groups, dpath + '.*', xml, large, arr_level))
            if coll:
                out['{*}'] = sorted(coll, key=lambda x: J.dumps(x).encode('ascii'))
            if len(node.members) > self.max_keys:
                out['{trunc}'] = 'trunc:keys:' + len_class(len(node.members))
            return out
        if isinstance(node, list):
            if self.container_drop(groups, steps):
                return 'drop:arr:' + len_class(len(node))
            cap = self.max_array
            if large:  # 22.5
                cap = self.large_array if arr_level == 0 else self.large_nested
            out = [self.walk(v, steps + [('a',)], groups, dpath + '[*]', xml, large, arr_level + 1) for v in node[:cap]]
            if len(node) > cap:
                out.append('trunc:n:' + len_class(len(node)))
            return out
        return self.apply(self.leaf_rule(groups, steps), leaf_kind(node), node, dpath)

    # ---------------------------------------------------------- subject (11) and sampling (12)

    def subject_value(self, norm):
        ident = (self.p.get('identity') or {}).get('subject')
        if not ident:
            return None
        if ident['from'] == 'header':
            raw = header_value(norm, ascii_lower(ident['name']))
            if isinstance(raw, list):  # set-cookie is never joined; not a usable subject header
                raw = None
        else:
            raw = None
            v = header_value(norm, 'cookie')
            for piece in (v.split(b';') if v is not None else []):
                piece = piece.strip(OWS)
                if b'=' in piece:
                    nb, vb = piece.split(b'=', 1)
                    if utf8_or_none(nb) == ident['name']:
                        raw = vb
                        break
        if raw is None or raw == b'' or len(raw) > P.SUBJECT_MAX_BYTES:
            return None
        s = utf8_or_none(raw)
        if s is None:
            return None
        if ident['from'] == 'header' and ident.get('json_path') is not None:
            return self.json_member(s, ident['json_path'])  # 11, step 4 bis (v1.18): no bearer prefix
        if ident['from'] == 'header':
            m = re.match(r'[Bb][Ee][Aa][Rr][Ee][Rr][ \t]+', s)
            if m:
                s = s[m.end():]
                if s == '':
                    return None
        claim = ident.get('jwt_claim')
        if claim is None:
            return s.encode('utf-8')
        parts = s.split('.')
        if len(parts) != 3:
            return None
        payload = jwt_b64_decode(parts[1])
        if payload is None:
            return None
        try:
            doc = J.parse(payload)
        except J.InvalidJSON:
            return None
        if not isinstance(doc, J.Obj):
            return None
        v = doc.get(claim)
        if isinstance(v, str) and v != '' and J.is_valid_str(v):
            return v.encode('utf-8')
        if isinstance(v, J.Num) and lexeme_ok(v.lexeme):
            return J.canon_num(v.lexeme).encode('ascii')
        return None

    def json_member(self, s, path):
        """11, step 4 bis: the subject is a member of a header holding a JSON object, plain or base64/base64url."""
        s = s.strip(' \t')
        if s == '':
            return None
        if s.startswith('{'):
            data = s.encode('utf-8')
        else:
            data = b64_any_decode(s)
            if data is None:
                return None
        try:
            v = J.parse(data)
        except J.InvalidJSON:
            return None
        if not isinstance(v, J.Obj):
            return None
        for name in path.split('.'):
            if not isinstance(v, J.Obj):
                return None
            v = v.get(name)
        if isinstance(v, str) and v != '' and J.is_valid_str(v):
            return v.encode('utf-8')
        if isinstance(v, J.Num) and lexeme_ok(v.lexeme):
            return J.canon_num(v.lexeme).encode('ascii')
        return None

    def sample(self, inp, norm, subject):
        rate = int(self.p['sampling']['rate_bp'].lexeme)
        if inp['dir'] == 'outbound':
            if inp.get('inherited') is not None:
                return inp['inherited'], 'inherited'
        else:
            internal = self.svc is not None and self.svc['match'].get('internal') is True
            if self.p['sampling']['trust_baggage'] and internal:
                b = baggage_decision(header_value(norm, 'baggage'))
                if b is not None:
                    return b, 'baggage'
            if subject is not None:
                u = int.from_bytes(self.mac('sample', subject)[:4], 'big')
                return u % 10000 < rate, 'subject'
        if inp.get('trace_id'):
            u = int.from_bytes(self.mac('sample-trace', inp['trace_id'].encode('ascii'))[:4], 'big')
            return u % 10000 < rate, 'trace'
        if rate not in (0, 10000):
            raise ValueError('random sampling with 0 < rate_bp < 10000 is not deterministic')
        return rate == 10000, 'random'

    # ---------------------------------------------------------- whole exchange

    def run(self, inp):
        req_norm = normalize_headers(inp['req_headers'])
        segs = decompose_path(inp.get('raw_path', b''))
        truncated = len(segs) > P.MAX_PATH_SEGMENTS
        segs = segs[:P.MAX_PATH_SEGMENTS]
        service, nbase = self.select_service(inp, segs)
        subject = self.subject_value(req_norm)
        sampled, by = self.sample(inp, req_norm, subject)
        if not sampled:
            return {'outcome': 'not_sampled', 'sampled_by': by}

        method = ascii_upper(inp['method'])
        if not METHOD_RE.fullmatch(method):
            method = 'OTHER'
        opsegs = segs[nbase:]
        fr = inp.get('framework_route') if inp['dir'] == 'inbound' else None
        op, tmpl, route_source = self.select_template(method, opsegs, truncated, inp.get('framework'), fr)
        self.op = op
        groups = self.groups('request')
        full = []
        for i, (_, dec) in enumerate(segs):
            if i < nbase:
                full.append(dec)  # 4.2.2: base segments are declared literals
            else:
                full.append(self.path_segment(i, dec, tmpl[i - nbase] if tmpl else None, groups))
        if truncated:
            full.append('{trunc}')
        path = '/' + '/'.join(full)
        op_path = '/' + '/'.join(full[nbase:])
        out = {
            'service': service,
            'op': op['op'] if op is not None else method + ' ' + op_path,
            'route_source': route_source,
            'sampled_by': by,
        }
        req = {'path': path}
        if inp.get('raw_query') is not None:
            q = self.name_map(self.urlencoded_entries(inp['raw_query']),
                              lambda n: self.named_rule(groups, 'query', n), 'req.query', '.{*}')
            if q:
                req['query'] = q
        h = self.headers('req', req_norm, 'request', None)
        if h:
            req['headers'] = h
        c = self.cookies('req', req_norm, 'request', None)
        if c:
            req['cookies'] = c
        ct = media_value(req_norm, 'content-type')
        if ct is not None:
            req['ct'] = ct
        if self.treatment(ct) == 'xml':  # 22.2 point 11
            sa = header_value(req_norm, 'soapaction')
            if sa is None:
                sa_s = B.media_params(header_value(req_norm, 'content-type')).get('action')
            else:
                sa_s = utf8_or_none(sa)
                if sa_s is None:
                    sa_s = '{*}'
            if sa_s is not None:
                name = '{*}' if sa_s == '{*}' else B.soap_action_name(sa_s, name_is_literal)
                if name is not None:
                    req['soap_action'] = name
        req.update(self.body('req', 'request', req_norm, inp.get('req_body', b''), inp.get('req_body_total'),
                             inp.get('req_body_consumed', True), inp.get('req_body_decoded', False), None))
        out['req'] = req
        self.resp = True
        if inp.get('net_error') is None:
            status = inp.get('status')
            rn = normalize_headers(inp.get('resp_headers', []))
            resp = {}
            h = self.headers('resp', rn, 'response', status)
            if h:
                resp['headers'] = h
            c = self.cookies('resp', rn, 'response', status)
            if c:
                resp['cookies'] = c
            ct = media_value(rn, 'content-type')
            if ct is not None:
                resp['ct'] = ct
            saved = self.max_array
            if self.gql_gate():
                self.max_array = max(self.max_array, 4096)  # 5.7.2
            resp.update(self.body('resp', 'response', rn, inp.get('resp_body', b''), inp.get('resp_body_total'),
                                  inp.get('resp_body_consumed', True), inp.get('resp_body_decoded', False),
                                  status))
            self.max_array = saved
            out['resp'] = resp
        if subject is not None:
            out['subject'] = self.token('subject', subject)
        if self.disc:
            out['disc'] = self.disc_out()
        return {'outcome': 'event', 'canonical': limit_size(out)}


# ------------------------------------------------------------------ helpers

def trunc_depth(v, depth, max_depth):
    """9.2: a container deeper than max_depth becomes trunc:depth (the root has depth 1)."""
    if isinstance(v, J.Obj):
        if depth > max_depth:
            return J.TRUNC_DEPTH
        return J.Obj([(k, trunc_depth(x, depth + 1, max_depth)) for k, x in v.members])
    if isinstance(v, list):
        if depth > max_depth:
            return J.TRUNC_DEPTH
        return [trunc_depth(x, depth + 1, max_depth) for x in v]
    return v


def limit_size(out):
    """10.3: deterministic reductions above 512 KiB (measured on the output, A-EVENT-SIZE-BASE)."""
    c = J.dumps(out)
    steps = [('req', 'body'), ('resp', 'body'), ('disc', None)]
    for part, field in steps:
        if abs(len(c) - P.EVENT_MAX_BYTES) < P.EVENT_SIZE_MARGIN:
            raise ValueError('output size %d too close to the 10.3 limit (A-EVENT-SIZE-BASE)' % len(c))
        if len(c) <= P.EVENT_MAX_BYTES:
            break
        if field is None:
            out.pop('disc', None)
        elif field in (out.get(part) or {}):
            out[part][field] = 'trunc:size'
        c = J.dumps(out)
    if len(c) > P.EVENT_MAX_BYTES:
        raise SizeExceeded()
    return c


class SizeExceeded(Exception):
    """10.3 step 4: no event, sanitizer_errors counter."""


def inflate(data, wbits, cap):
    """One gzip (wbits 31) or zlib (wbits 15) stream; output capped at `cap` bytes; None on error."""
    d = zlib.decompressobj(wbits)
    try:
        out = d.decompress(data, cap)
    except zlib.error:
        return None
    if len(out) >= cap:
        return out  # cap reached: the caller reports trunc:size without looking further
    if not d.eof or d.unused_data:  # A-GZIP-STRICT
        return None
    return out


def jwt_b64_decode(s):
    """11.4.2: strict base64url alphabet, optional trailing '=' (at most two)."""
    m = re.fullmatch(r'([A-Za-z0-9_-]*)(={0,2})', s)
    if not m:
        return None
    body = m.group(1)
    if len(body) % 4 == 1:
        return None
    import base64
    try:
        return base64.urlsafe_b64decode(body + '=' * (-len(body) % 4))
    except Exception:  # noqa: BLE001
        return None


def b64_any_decode(s):
    """11, step 4 bis.2: standard or URL alphabet (never mixed), with or without padding (at most two '=' at the
    end, then a length multiple of 4). None on any other character or an impossible length."""
    import base64
    m = re.fullmatch(r'([A-Za-z0-9_+/-]*)(={0,2})', s)
    if not m:
        return None
    body, pad = m.group(1), m.group(2)
    if body == '' or (pad and (len(body) + len(pad)) % 4 != 0) or len(body) % 4 == 1:
        return None
    std = '+' in body or '/' in body
    if std and ('-' in body or '_' in body):
        return None
    body += '=' * (-len(body) % 4)
    return base64.b64decode(body, validate=True) if std else base64.urlsafe_b64decode(body)


def baggage_decision(v):
    """12, "Lettura del baggage"."""
    if v is None:
        return None
    s = utf8_or_none(v)
    if s is None:
        return None
    for member in s.split(','):
        kv = member.strip(' \t').split(';', 1)[0]
        if '=' not in kv:
            continue
        k, val = kv.split('=', 1)
        k, val = k.strip(' \t'), val.strip(' \t')
        if k == 'tt.s' and val in ('0', '1'):
            return val == '1'
    return None


def decompose_path(raw):
    """4.1 points 1-3 -> list of (raw bytes, decoded str or None if not UTF-8)."""
    return [(s, utf8_or_none(pct_decode(s))) for s in raw.split(b'/') if s]


def parse_op_key(key):
    method, _, tmpl = key.partition(' ')
    segs = []
    for s in tmpl.split('/'):
        if not s:
            continue
        if s.startswith('{') and s.endswith('}'):
            segs.append(('p', s[1:-1]))
        else:
            segs.append(('l', s))
    return method, segs


def parse_ttpath(p):
    steps = []
    i = 1
    while i < len(p):
        m = TTPATH_STEP_RE.match(p, i)
        t = m.group(0)
        steps.append(('s',) if t == '.*' else ('i',) if t == '[*]' else ('n', m.group(1)))
        i = m.end()
    return steps


def ttpath_matches(rule_steps, node_steps):
    if len(rule_steps) != len(node_steps):
        return False
    for r, n in zip(rule_steps, node_steps):
        if r[0] == 'i':
            if n[0] != 'a':
                return False
        elif n[0] != 'm':
            return False
        elif r[0] == 'n' and n[1] != r[1]:
            return False
    return True


def normalize_url_base(url_base):
    """3.1 -> (origin, (host[:port], (host, port, ipv6))) or (None, None) if the host is not valid.

    ipv6 is the 16-byte address of a bracketed IPv6 literal (spec v1.5), else None. The origin of an
    IPv6 literal never equals a base (the compiler refuses bracketed bases)."""
    m = re.fullmatch(r'([A-Za-z][A-Za-z0-9+.-]*)://(.*)', url_base or '')
    if not m:
        return None, None
    scheme = ascii_lower(m.group(1))
    auth = m.group(2)
    if any(c in auth for c in '@/?#'):
        return None, None
    ip6 = None
    if auth.startswith('['):
        end = auth.find(']')
        if end < 0:
            return None, None
        host, rest = ascii_lower(auth[1:end]), auth[end + 1:]
        ip6 = parse_ipv6(host)
        if ip6 is None:
            return None, None
        if rest == '':
            port = None
        elif rest.startswith(':'):
            port = rest[1:]
        else:
            return None, None
        host = '[' + host + ']'
    else:
        host, port = auth, None
        if ':' in auth:
            host, port = auth.rsplit(':', 1)
        host = ascii_lower(host)
        if not HOST_RE.fullmatch(host):
            return None, None
    if port is not None:
        if not re.fullmatch(r'[0-9]{1,5}', port) or not 1 <= int(port) <= 65535:
            return None, None
        port = str(int(port))  # A-PORT-ZEROS
    if port is not None and port == {'http': '80', 'https': '443'}.get(scheme):
        port = None
    hp = host + (':' + port if port else '')
    return scheme + '://' + hp, (hp, (host, port, ip6))


# ------------------------------------------------------------------ host patterns (3.5, 3.6; spec v1.5)

def host_label_safe(label):
    """3.5: a host label stays literal only if all the rules hold."""
    return (SAFE_LABEL_RE.fullmatch(label) is not None          # a. ^[a-z][a-z0-9-]{0,62}$ (ASCII, no '@')
            and SIX_DIGITS_RE.search(label) is None             # b. no 6 or more consecutive digits
            and HEX12_RE.search(label) is None                  # c. no 12 or more consecutive hex characters
            and detect_format(label) is None)                   # d. no value format of 6.3 (uuid, hex, ...)


def parse_ipv6(s):
    """3.1 (v1.5): RFC 4291 2.2 text form, lowercase, at most one '::', an optional dotted IPv4 tail
    (6.3 ipv4) as the last 32 bits, no zone. Returns 16 bytes or None."""
    def groups(parts, tail_ok):
        out = []
        for k, g in enumerate(parts):
            if tail_ok and k == len(parts) - 1 and '.' in g:
                if not FORMAT_RE['ipv4'].fullmatch(g):
                    return None
                o = [int(x) for x in g.split('.')]
                out += [(o[0] << 8) | o[1], (o[2] << 8) | o[3]]
            elif HEXGROUP_RE.fullmatch(g):
                out.append(int(g, 16))
            else:
                return None
        return out
    if s.count('::') > 1:
        return None
    if '::' in s:
        left, right = s.split('::')
        a = groups(left.split(':') if left else [], False)
        b = groups(right.split(':') if right else [], True)
        if a is None or b is None or len(a) + len(b) > 7:
            return None
        g = a + [0] * (8 - len(a) - len(b)) + b
    else:
        g = groups(s.split(':'), True)
        if g is None or len(g) != 8:
            return None
    return b''.join(x.to_bytes(2, 'big') for x in g)


def _in_prefix(addr, prefix, bits):
    n = int.from_bytes(addr, 'big') >> (len(addr) * 8 - bits)
    return n == int.from_bytes(prefix, 'big') >> (len(prefix) * 8 - bits)


# 3.6: every address not in these ranges is public.
IPV4_PRIVATE = [((0, 0, 0, 0), 8), ((10, 0, 0, 0), 8), ((100, 64, 0, 0), 10), ((127, 0, 0, 0), 8),
                ((169, 254, 0, 0), 16), ((172, 16, 0, 0), 12), ((192, 0, 0, 0), 24), ((192, 0, 2, 0), 24),
                ((192, 168, 0, 0), 16), ((198, 18, 0, 0), 15), ((198, 51, 100, 0), 24), ((203, 0, 113, 0), 24),
                ((224, 0, 0, 0), 4), ((240, 0, 0, 0), 4)]
IPV6_EMBEDDED_V4 = [('::ffff:0:0', 96), ('64:ff9b::', 96)]
IPV6_PRIVATE = [('::', 96), ('64:ff9b:1::', 48), ('100::', 64), ('2001::', 23), ('2001:db8::', 32),
                ('fc00::', 7), ('fe80::', 10), ('fec0::', 10), ('ff00::', 8)]


def ipv4_private(addr4):
    return any(_in_prefix(addr4, bytes(p), n) for p, n in IPV4_PRIVATE)


def ipv6_private(addr16):
    for p, n in IPV6_EMBEDDED_V4:
        if _in_prefix(addr16, parse_ipv6(p), n):
            return ipv4_private(addr16[12:])
    return any(_in_prefix(addr16, parse_ipv6(p), n) for p, n in IPV6_PRIVATE)


def host_pattern(host, port, ip6):
    """3.5: the pattern of a valid host (3.1), or None when the host has an empty label (host:invalid)."""
    suffix = ':' + port if port else ''
    if ip6 is not None:
        return 'ip:' + ('private' if ipv6_private(ip6) else 'public') + suffix
    h = host[:-1] if host.endswith('.') else host
    labels = h.split('.')
    if any(lab == '' for lab in labels):
        return None
    if FORMAT_RE['ipv4'].fullmatch(h):
        addr = bytes(int(x) for x in labels)
        return 'ip:' + ('private' if ipv4_private(addr) else 'public') + suffix
    return '.'.join(lab if host_label_safe(lab) else '{*}' for lab in labels) + suffix


def split_base(base):
    """Compiled match.base (already normalized) -> (origin, [segments])."""
    i = base.find('://')
    j = base.find('/', i + 3)
    if j < 0:
        return base, []
    return base[:j], [s for s in base[j:].split('/') if s]
