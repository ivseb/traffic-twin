"""Reference code for the body formats of spec v1.19 (sanitizer.md 22): XML and SOAP, multipart/form-data,
base64 documents and the document size classes. Python 3 standard library only.

Written from docs/spec/sanitizer.md 22 only. The functions here are pure: they never see the policy.
"""

import base64
import re

import ttjson as J

# ------------------------------------------------------------------ documents (22.4)

# 22.4: (inclusive upper bound, class) on the decoded length; None = no bound.
DOC_CLASSES = [(1024, 'l1k'), (16384, 'l16k'), (131072, 'l128k'), (1048576, 'l1m'), (8388608, 'l8m'), (None, 'lmax')]

B64_RE = re.compile(r'[A-Za-z0-9+/_-]*={0,2}')
DATA_PREFIX_RE = re.compile(r'data:[!-+\--~]*;base64', re.ASCII)  # printable ASCII without ','
DOC_MIN_CHARS = 16


def doc_class(n):
    for bound, name in DOC_CLASSES:
        if bound is None or n <= bound:
            return name
    raise AssertionError


def magic_kind(b):
    """22.4: kind of a document from its first bytes (and, for zip, the names it holds); None if none."""
    if b.startswith(b'%PDF-'):
        return 'pdf'
    if b.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'png'
    if b.startswith(b'\xff\xd8\xff'):
        return 'jpeg'
    if b.startswith(b'GIF87a') or b.startswith(b'GIF89a'):
        return 'gif'
    if b.startswith(b'RIFF') and b[8:12] == b'WEBP':
        return 'webp'
    if b.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'):
        return 'ole'
    if b.startswith(b'PK\x03\x04'):
        if b'word/document.xml' in b:
            return 'docx'
        if b'xl/workbook.xml' in b:
            return 'xlsx'
        if b'ppt/presentation.xml' in b:
            return 'pptx'
        return 'zip'
    return None


def base64_doc(s):
    """22.4: 'drop:doc:<kind>:<class>' if the string is the base64 of a document, else None."""
    if s.startswith('data:'):
        i = s.find(',')
        if i < 0 or not DATA_PREFIX_RE.fullmatch(s[:i]):
            return None
        s = s[i + 1:]
    if len(s) < DOC_MIN_CHARS or not B64_RE.fullmatch(s):
        return None
    body = s.rstrip('=')
    if len(body) != len(s) and len(s) % 4 != 0:
        return None
    if len(body) % 4 == 1:
        return None
    std = body.replace('-', '+').replace('_', '/')
    raw = base64.b64decode(std + '=' * (-len(std) % 4))
    kind = magic_kind(raw)
    if kind is None:
        return None
    return 'drop:doc:%s:%s' % (kind, doc_class(len(raw)))


# ------------------------------------------------------------------ media type parameters (22.2, 22.3)

def media_params(value):
    """Parameters of a normalized content-type value (bytes): {lowercase name: value}, first occurrence wins.

    The value is split on ';'; each piece is trimmed of spaces and tabs and split on the first '='.
    A value that starts with '"' must end with '"' (length >= 2) and loses both quotes; no escapes."""
    out = {}
    if value is None:
        return out
    try:
        s = value.decode('utf-8')
    except UnicodeDecodeError:
        return out
    for piece in s.split(';')[1:]:
        piece = piece.strip(' \t')
        if '=' not in piece:
            continue
        name, v = piece.split('=', 1)
        name = ''.join(chr(ord(c) + 32) if 'A' <= c <= 'Z' else c for c in name.strip(' \t'))
        v = v.strip(' \t')
        if v.startswith('"'):
            if len(v) < 2 or not v.endswith('"'):
                continue
            v = v[1:-1]
        if name not in out:
            out[name] = v
    return out


# ------------------------------------------------------------------ multipart (22.3)

BOUNDARY_RE = re.compile(r"[0-9A-Za-z'()+_,./:=? -]{0,69}[0-9A-Za-z'()+_,./:=?-]", re.ASCII)
PART_HEADER_NAME_RE = re.compile(rb"[A-Za-z0-9!#$%&'*+.^_`|~-]+")
FILE_TYPES = {'text/plain': 'text', 'text/csv': 'csv', 'application/json': 'json', 'application/xml': 'xml',
              'text/xml': 'xml'}


class InvalidMultipart(Exception):
    pass


def _alower(s):
    """ASCII lowercase only (sanitizer.md 0.1)."""
    return ''.join(chr(ord(c) + 32) if 'A' <= c <= 'Z' else c for c in s)


def _disposition(s):
    """content-disposition of a part -> {param: value} (first wins); InvalidMultipart if not form-data."""
    i = s.find(';')
    kind = (s if i < 0 else s[:i]).strip(' \t')
    if _alower(kind) != 'form-data':
        raise InvalidMultipart('disposition')
    params = {}
    pos = len(s) if i < 0 else i
    n = len(s)
    while pos < n:
        while pos < n and s[pos] in ' \t;':
            pos += 1
        if pos >= n:
            break
        start = pos
        while pos < n and s[pos] not in '=;':
            pos += 1
        name = _alower(s[start:pos].strip(' \t'))
        if pos >= n or s[pos] == ';':
            params.setdefault(name, '')
            continue
        pos += 1  # '='
        while pos < n and s[pos] in ' \t':
            pos += 1
        if pos < n and s[pos] == '"':
            pos += 1
            buf = []
            while True:
                if pos >= n:
                    raise InvalidMultipart('unterminated quoted string')
                c = s[pos]
                if c == '\\' and pos + 1 < n:
                    buf.append(s[pos + 1])
                    pos += 2
                    continue
                if c == '"':
                    pos += 1
                    break
                buf.append(c)
                pos += 1
            val = ''.join(buf)
            while pos < n and s[pos] in ' \t':
                pos += 1
            if pos < n and s[pos] != ';':
                raise InvalidMultipart('garbage after quoted string')
        else:
            start = pos
            while pos < n and s[pos] != ';':
                pos += 1
            val = s[start:pos].strip(' \t')
        params.setdefault(name, val)
    return params


def parse_multipart(data, boundary):
    """22.3 -> list of (name str, is_file, content bytes, part content-type media or None). InvalidMultipart."""
    if boundary is None or not BOUNDARY_RE.fullmatch(boundary):
        raise InvalidMultipart('boundary')
    delim = b'--' + boundary.encode('ascii')
    if data.startswith(delim):
        pos = 0
    else:
        i = data.find(b'\r\n' + delim)
        if i < 0:
            raise InvalidMultipart('no delimiter')
        pos = i + 2
    parts = []
    while True:
        pos += len(delim)
        if data[pos:pos + 2] == b'--':
            break
        while pos < len(data) and data[pos] in b' \t':
            pos += 1
        if data[pos:pos + 2] != b'\r\n':
            raise InvalidMultipart('delimiter line')
        pos += 2
        nxt = data.find(b'\r\n' + delim, pos)
        if nxt < 0:
            raise InvalidMultipart('no close delimiter')
        parts.append(data[pos:nxt])
        pos = nxt + 2
    out = []
    for p in parts:
        if p.startswith(b'\r\n'):
            head, content = b'', p[2:]
        else:
            j = p.find(b'\r\n\r\n')
            if j < 0:
                raise InvalidMultipart('part headers')
            head, content = p[:j], p[j + 4:]
        headers = {}
        for line in (head.split(b'\r\n') if head else []):
            k = line.find(b':')
            if k <= 0 or not PART_HEADER_NAME_RE.fullmatch(line[:k]):
                raise InvalidMultipart('part header line')
            name = line[:k].lower()
            if name not in headers:
                headers[name] = line[k + 1:].strip(b' \t')
        cd = headers.get(b'content-disposition')
        if cd is None:
            raise InvalidMultipart('no content-disposition')
        try:
            cds = cd.decode('utf-8')
        except UnicodeDecodeError:
            raise InvalidMultipart('content-disposition not UTF-8')
        params = _disposition(cds)
        if 'name' not in params:
            raise InvalidMultipart('no name')
        is_file = 'filename' in params or 'filename*' in params
        ct = None
        if b'content-type' in headers:
            try:
                ct = _alower(headers[b'content-type'].decode('utf-8').split(';', 1)[0].strip(' \t'))
            except UnicodeDecodeError:
                ct = None
        out.append((params['name'], is_file, content, ct))
    return out


def file_token(content, ct):
    """22.3: drop:file:<kind>:<class> of a file part."""
    kind = magic_kind(content) or FILE_TYPES.get(ct or '', 'bin')
    return 'drop:file:%s:%s' % (kind, doc_class(len(content)))


# ------------------------------------------------------------------ XML (22.2)

NS_XML = 'http://www.w3.org/XML/1998/namespace'
SOAP11 = 'http://schemas.xmlsoap.org/soap/envelope/'
SOAP12 = 'http://www.w3.org/2003/05/soap-envelope'
XML_MAX_NESTING = 256
XML_WS = ' \t\n'
NS_RUN_RE = re.compile(r'[A-Za-z0-9_-]+')
NS_MAX_BYTES = 512


class InvalidXML(Exception):
    pass


def _name_start(c):
    return ('A' <= c <= 'Z') or ('a' <= c <= 'z') or c == '_' or ord(c) >= 0x80


def _name_char(c):
    return _name_start(c) or ('0' <= c <= '9') or c in '.-:'


def _xml_char(cp):
    return cp in (0x9, 0xA, 0xD) or 0x20 <= cp <= 0xD7FF or 0xE000 <= cp <= 0xFFFD or 0x10000 <= cp <= 0x10FFFF


ENTITIES = {'lt': '<', 'gt': '>', 'amp': '&', 'apos': "'", 'quot': '"'}


def _refs(raw, attr):
    """Character and predefined entity references; attribute values turn tab and newline into spaces."""
    out = []
    i = 0
    n = len(raw)
    while i < n:
        c = raw[i]
        if c == '&':
            j = raw.find(';', i + 1)
            if j < 0:
                raise InvalidXML('unterminated reference')
            ent = raw[i + 1:j]
            if ent in ENTITIES:
                out.append(ENTITIES[ent])
            elif ent.startswith('#x') and len(ent) > 2 and all(d in '0123456789abcdefABCDEF' for d in ent[2:]):
                cp = 0
                for d in ent[2:]:
                    cp = cp * 16 + int(d, 16)
                    if cp > 0x10FFFF:
                        raise InvalidXML('reference out of range')
                if not _xml_char(cp):
                    raise InvalidXML('reference to a forbidden character')
                out.append(chr(cp))
            elif ent.startswith('#') and len(ent) > 1 and all('0' <= d <= '9' for d in ent[1:]):
                cp = 0
                for d in ent[1:]:
                    cp = cp * 10 + int(d)
                    if cp > 0x10FFFF:
                        raise InvalidXML('reference out of range')
                if not _xml_char(cp):
                    raise InvalidXML('reference to a forbidden character')
                out.append(chr(cp))
            else:
                raise InvalidXML('unknown entity')
            i = j + 1
            continue
        if attr and c in '\t\n':
            out.append(' ')
        else:
            out.append(c)
        i += 1
    return ''.join(out)


def _split_qname(q):
    if ':' not in q:
        return None, q
    p, _, l = q.partition(':')
    if not p or not l or ':' in l:
        raise InvalidXML('qualified name')
    return p, l


class Elem:
    __slots__ = ('local', 'ns', 'attrs', 'children', 'text')

    def __init__(self, local, ns, attrs):
        self.local = local
        self.ns = ns
        self.attrs = attrs        # list of (local, value) without namespace declarations
        self.children = []
        self.text = []


def parse_xml(data):
    """22.2 points 1-6 -> root Elem. InvalidXML for anything outside the accepted subset."""
    if data.startswith(b'\xef\xbb\xbf'):
        data = data[3:]
    try:
        s = data.decode('utf-8')
    except UnicodeDecodeError:
        raise InvalidXML('not UTF-8')
    for ch in s:
        cp = ord(ch)
        if (cp < 0x20 and cp not in (9, 10, 13)) or cp in (0xFFFE, 0xFFFF) or 0xD800 <= cp <= 0xDFFF:
            raise InvalidXML('forbidden character')
    s = s.replace('\r\n', '\n').replace('\r', '\n')
    n = len(s)
    pos = 0
    stack = []   # (qname, Elem, nsmap)
    root = None

    def read_name(p):
        if p >= n or not _name_start(s[p]):
            raise InvalidXML('name')
        q = p + 1
        while q < n and _name_char(s[q]):
            q += 1
        return s[p:q], q

    def skip_ws(p):
        while p < n and s[p] in XML_WS:
            p += 1
        return p

    def misc(p):
        """Comment or processing instruction at p -> end, or None if none starts there."""
        if s.startswith('<!--', p):
            e = s.find('-->', p + 4)
            if e < 0:
                raise InvalidXML('unterminated comment')
            return e + 3
        if s.startswith('<?', p):
            e = s.find('?>', p + 2)
            if e < 0:
                raise InvalidXML('unterminated processing instruction')
            return e + 2
        return None

    def start_tag(p, parent_ns):
        qname, p = read_name(p + 1)
        raw_attrs = []
        seen = set()
        empty = False
        while True:
            q = skip_ws(p)
            if s.startswith('/>', q):
                p, empty = q + 2, True
                break
            if s.startswith('>', q):
                p = q + 1
                break
            if q == p:
                raise InvalidXML('attribute without space')
            aname, q = read_name(q)
            q = skip_ws(q)
            if q >= n or s[q] != '=':
                raise InvalidXML('attribute without =')
            q = skip_ws(q + 1)
            if q >= n or s[q] not in '"\'':
                raise InvalidXML('attribute value')
            e = s.find(s[q], q + 1)
            if e < 0:
                raise InvalidXML('unterminated attribute value')
            raw = s[q + 1:e]
            if '<' in raw:
                raise InvalidXML('< in attribute value')
            if aname in seen:
                raise InvalidXML('duplicate attribute')
            seen.add(aname)
            raw_attrs.append((aname, _refs(raw, True)))
            p = e + 1
        nsmap = dict(parent_ns)
        for aname, v in raw_attrs:
            if aname == 'xmlns':
                nsmap[''] = v
            elif aname.startswith('xmlns:'):
                pre = aname[6:]
                if not pre or ':' in pre:
                    raise InvalidXML('namespace declaration')
                nsmap[pre] = v
        prefix, local = _split_qname(qname)
        if prefix is None:
            ns = nsmap.get('', '')
        elif prefix == 'xml':
            ns = NS_XML
        elif prefix in nsmap:
            ns = nsmap[prefix]
        else:
            raise InvalidXML('undeclared prefix')
        attrs = []
        for aname, v in raw_attrs:
            if aname == 'xmlns' or aname.startswith('xmlns:'):
                continue
            ap, al = _split_qname(aname)
            if ap is not None and ap != 'xml' and ap not in nsmap:
                raise InvalidXML('undeclared attribute prefix')
            attrs.append((al, v))
        return qname, Elem(local, ns, attrs), nsmap, empty, p

    # prolog
    while True:
        pos = skip_ws(pos)
        if pos >= n:
            raise InvalidXML('no root element')
        e = misc(pos)
        if e is not None:
            pos = e
            continue
        if s.startswith('<!', pos) or s[pos] != '<':
            raise InvalidXML('prolog')
        break
    qname, el, nsmap, empty, pos = start_tag(pos, {})
    root = el
    if not empty:
        stack.append((qname, el, nsmap))
    while stack:
        if pos >= n:
            raise InvalidXML('unclosed element')
        qn, cur, cur_ns = stack[-1]
        if s[pos] != '<':
            e = s.find('<', pos)
            if e < 0:
                raise InvalidXML('unclosed element')
            cur.text.append(_refs(s[pos:e], False))
            pos = e
            continue
        if s.startswith('<![CDATA[', pos):
            e = s.find(']]>', pos + 9)
            if e < 0:
                raise InvalidXML('unterminated CDATA')
            cur.text.append(s[pos + 9:e])
            pos = e + 3
            continue
        e = misc(pos)
        if e is not None:
            pos = e
            continue
        if s.startswith('<!', pos):
            raise InvalidXML('declaration in content')
        if s.startswith('</', pos):
            name, q = read_name(pos + 2)
            q = skip_ws(q)
            if q >= n or s[q] != '>' or name != qn:
                raise InvalidXML('end tag')
            stack.pop()
            pos = q + 1
            continue
        qname, el, nsmap, empty, pos = start_tag(pos, cur_ns)
        cur.children.append(el)
        if not empty:
            if len(stack) >= XML_MAX_NESTING:
                raise InvalidXML('nesting')
            stack.append((qname, el, nsmap))
    # epilogue
    while True:
        pos = skip_ws(pos)
        if pos >= n:
            break
        e = misc(pos)
        if e is None:
            raise InvalidXML('content after the root element')
        pos = e
    return root


def _xml_value(el, literal):
    """22.2 point 7: element -> tree value (str or J.Obj)."""
    if not el.attrs and not el.children:
        return ''.join(el.text)
    members = []
    index = {}
    for local, v in el.attrs:  # duplicates (same local name): the last wins, at its own position
        k = '@' + local
        if k in index:
            members[index[k]] = None
        index[k] = len(members)
        members.append((k, v))
    members = [m for m in members if m is not None]
    groups = {}
    order = []
    for c in el.children:
        if c.local not in groups:
            groups[c.local] = []
            order.append(c.local)
        groups[c.local].append(_xml_value(c, literal))
    for k in order:
        vs = groups[k]
        members.append((k, vs[0] if len(vs) == 1 else vs))
    text = ''.join(el.text)
    if text.strip(' \t\n\r') != '':
        members.append(('#text', text))
    return J.Obj(members)


def ns_pattern(uri):
    """22.2 point 9: 'ns:' + pattern of a namespace URI."""
    if uri == '':
        return 'ns:{none}'
    if len(uri.encode('utf-8')) > NS_MAX_BYTES or any(not ('!' <= c <= '~') or c in '@{}' for c in uri):
        return 'ns:{*}'

    def run(m):
        t = m.group(0)
        if len(t) > 64 or re.search(r'[0-9]{6}', t) or re.search(r'[0-9A-Fa-f]{12}', t):
            return '{*}'
        return t
    return 'ns:' + NS_RUN_RE.sub(run, uri)


def xml_tree(root, literal, max_depth):
    """-> (body tree, xmlns entries [(path, token)] in document order, fmt)."""
    tree = J.Obj([(root.local, _xml_value(root, literal))])
    entries = []
    seen = set()

    def visit(el, path, parent_ns, depth):
        if depth > max_depth:
            return
        if el.ns != parent_ns and path not in seen:
            seen.add(path)
            entries.append((path, ns_pattern(el.ns)))
        counts = {}
        for c in el.children:
            counts[c.local] = counts.get(c.local, 0) + 1
        for c in el.children:
            p = path + ('.' + c.local if literal(c.local) else '.*') + ('[*]' if counts[c.local] > 1 else '')
            visit(c, p, el.ns, depth + 1)

    visit(root, '$' + ('.' + root.local if literal(root.local) else '.*'), '', 1)
    fmt = 'xml'
    if root.local == 'Envelope' and root.ns == SOAP11:
        fmt = 'soap11'
    elif root.local == 'Envelope' and root.ns == SOAP12:
        fmt = 'soap12'
    return tree, entries, fmt


def soap_action_name(raw, literal):
    """22.2 point 11: the operation name of a SOAPAction value (str), or None when empty."""
    s = raw.strip(' \t')
    if len(s) >= 2 and s.startswith('"') and s.endswith('"'):
        s = s[1:-1]
    if s == '':
        return None
    cut = max(s.rfind('/'), s.rfind('#'), s.rfind(':'))
    name = s[cut + 1:]
    return name if literal(name) else '{*}'
