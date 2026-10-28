"""Body formats of spec v1.19 (sanitizer.md 22): XML and SOAP, multipart/form-data,
base64 documents and the document size classes.

The XML reader is a hand-written strict subset of XML 1.0 + Namespaces (22.2): it never
reads a DTD, never resolves an entity other than the five predefined ones and character
references, and is iterative (an explicit stack, nesting capped at 256), so no input can
make it recurse or expand. No generic XML library is used on purpose.

Everything here is pure: these functions never see the policy.
"""

from __future__ import annotations

import base64
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from .jsonlex import JObj

# ---------------------------------------------------------------------------------
# Documents (22.4)

_DOC_CLASSES = ((1024, "l1k"), (16384, "l16k"), (131072, "l128k"), (1048576, "l1m"), (8388608, "l8m"))
_B64_RE = re.compile(r"[A-Za-z0-9+/_-]*={0,2}")
_DATA_PREFIX_RE = re.compile(r"data:[!-+\--~]*;base64")  # printable ASCII without ','
DOC_MIN_CHARS = 16


def doc_class(n: int) -> str:
    for bound, name in _DOC_CLASSES:
        if n <= bound:
            return name
    return "lmax"


def magic_kind(b: bytes) -> Optional[str]:
    """22.4 point 3: kind of a document from its first bytes; None if not recognized."""
    if b.startswith(b"%PDF-"):
        return "pdf"
    if b.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if b.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if b.startswith(b"GIF87a") or b.startswith(b"GIF89a"):
        return "gif"
    if b.startswith(b"RIFF") and b[8:12] == b"WEBP":
        return "webp"
    if b.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if b.startswith(b"PK\x03\x04"):
        if b"word/document.xml" in b:
            return "docx"
        if b"xl/workbook.xml" in b:
            return "xlsx"
        if b"ppt/presentation.xml" in b:
            return "pptx"
        return "zip"
    return None


def base64_doc(s: str) -> Optional[str]:
    """22.4: ``drop:doc:<kind>:<class>`` if the string is the base64 of a document, else None."""
    if s.startswith("data:"):
        i = s.find(",")
        if i < 0 or not _DATA_PREFIX_RE.fullmatch(s, 0, i):
            return None
        s = s[i + 1:]
    if len(s) < DOC_MIN_CHARS or not _B64_RE.fullmatch(s):
        return None
    body = s.rstrip("=")
    if len(body) != len(s) and len(s) % 4 != 0:
        return None
    if len(body) % 4 == 1:
        return None
    # Only the first bytes decide the kind, except for zip (names anywhere): decode a
    # prefix first and the whole string only for a zip candidate.
    std = body.replace("-", "+").replace("_", "/")
    head = std[:16]
    raw = base64.b64decode(head + "=" * (-len(head) % 4))
    if magic_kind(raw) is None:
        return None
    raw = base64.b64decode(std + "=" * (-len(std) % 4))
    kind = magic_kind(raw)
    if kind is None:
        return None
    return "drop:doc:%s:%s" % (kind, doc_class(len(raw)))


# ---------------------------------------------------------------------------------
# Media type parameters (22.2 point 11, 22.3 point 1)

_ASCII_LOWER = {c: c + 32 for c in range(0x41, 0x5B)}


def media_params(value: Optional[bytes]) -> Dict[str, str]:
    """Parameters of a normalized content-type value: {lowercase name: value}, first wins."""
    out: Dict[str, str] = {}
    if value is None:
        return out
    try:
        s = value.decode("utf-8")
    except UnicodeDecodeError:
        return out
    for piece in s.split(";")[1:]:
        piece = piece.strip(" \t")
        eq = piece.find("=")
        if eq < 0:
            continue
        name = piece[:eq].strip(" \t").translate(_ASCII_LOWER)
        v = piece[eq + 1:].strip(" \t")
        if v.startswith('"'):
            if len(v) < 2 or not v.endswith('"'):
                continue
            v = v[1:-1]
        if name not in out:
            out[name] = v
    return out


# ---------------------------------------------------------------------------------
# multipart/form-data (22.3)

_BOUNDARY_RE = re.compile(r"[0-9A-Za-z'()+_,./:=? -]{0,69}[0-9A-Za-z'()+_,./:=?-]")
_PART_HEADER_NAME_RE = re.compile(rb"[A-Za-z0-9!#$%&'*+.^_`|~-]+")
_FILE_TYPES = {"text/plain": "text", "text/csv": "csv", "application/json": "json", "application/xml": "xml",
               "text/xml": "xml"}


class InvalidMultipart(Exception):
    pass


def _disposition(s: str) -> Dict[str, str]:
    """content-disposition of a part -> {param: value} (first wins)."""
    i = s.find(";")
    kind = (s if i < 0 else s[:i]).strip(" \t")
    if kind.translate(_ASCII_LOWER) != "form-data":
        raise InvalidMultipart("disposition")
    params: Dict[str, str] = {}
    n = len(s)
    pos = n if i < 0 else i
    while pos < n:
        while pos < n and s[pos] in " \t;":
            pos += 1
        if pos >= n:
            break
        start = pos
        while pos < n and s[pos] not in "=;":
            pos += 1
        name = s[start:pos].strip(" \t").lower()
        if pos >= n or s[pos] == ";":
            params.setdefault(name, "")
            continue
        pos += 1  # '='
        while pos < n and s[pos] in " \t":
            pos += 1
        if pos < n and s[pos] == '"':
            pos += 1
            buf: List[str] = []
            while True:
                if pos >= n:
                    raise InvalidMultipart("unterminated quoted string")
                c = s[pos]
                if c == "\\" and pos + 1 < n:
                    buf.append(s[pos + 1])
                    pos += 2
                    continue
                if c == '"':
                    pos += 1
                    break
                buf.append(c)
                pos += 1
            val = "".join(buf)
            while pos < n and s[pos] in " \t":
                pos += 1
            if pos < n and s[pos] != ";":
                raise InvalidMultipart("garbage after quoted string")
        else:
            start = pos
            while pos < n and s[pos] != ";":
                pos += 1
            val = s[start:pos].strip(" \t")
        params.setdefault(name, val)
    return params


class MultipartPart:
    __slots__ = ("name", "is_file", "content", "ct")

    def __init__(self, name: str, is_file: bool, content: bytes, ct: Optional[str]) -> None:
        self.name = name
        self.is_file = is_file
        self.content = content
        self.ct = ct


def parse_multipart(data: bytes, boundary: Optional[str]) -> List[MultipartPart]:
    """22.3 points 1-5. Raises InvalidMultipart."""
    if boundary is None or not _BOUNDARY_RE.fullmatch(boundary):
        raise InvalidMultipart("boundary")
    delim = b"--" + boundary.encode("ascii")
    sep = b"\r\n" + delim
    if data.startswith(delim):
        pos = 0
    else:
        i = data.find(sep)
        if i < 0:
            raise InvalidMultipart("no delimiter")
        pos = i + 2
    raw_parts: List[bytes] = []
    n = len(data)
    while True:
        pos += len(delim)
        if data[pos:pos + 2] == b"--":
            break
        while pos < n and data[pos] in b" \t":
            pos += 1
        if data[pos:pos + 2] != b"\r\n":
            raise InvalidMultipart("delimiter line")
        pos += 2
        nxt = data.find(sep, pos)
        if nxt < 0:
            raise InvalidMultipart("no close delimiter")
        raw_parts.append(data[pos:nxt])
        pos = nxt + 2
    out: List[MultipartPart] = []
    for p in raw_parts:
        if p.startswith(b"\r\n"):
            head, content = b"", p[2:]
        else:
            j = p.find(b"\r\n\r\n")
            if j < 0:
                raise InvalidMultipart("part headers")
            head, content = p[:j], p[j + 4:]
        headers: Dict[bytes, bytes] = {}
        for line in (head.split(b"\r\n") if head else []):
            k = line.find(b":")
            if k <= 0 or not _PART_HEADER_NAME_RE.fullmatch(line, 0, k):
                raise InvalidMultipart("part header line")
            name = line[:k].lower()
            if name not in headers:
                headers[name] = line[k + 1:].strip(b" \t")
        cd = headers.get(b"content-disposition")
        if cd is None:
            raise InvalidMultipart("no content-disposition")
        try:
            cds = cd.decode("utf-8")
        except UnicodeDecodeError:
            raise InvalidMultipart("content-disposition not UTF-8") from None
        params = _disposition(cds)
        if "name" not in params:
            raise InvalidMultipart("no name")
        is_file = "filename" in params or "filename*" in params
        ct: Optional[str] = None
        if b"content-type" in headers:
            try:
                ct = headers[b"content-type"].decode("utf-8").split(";", 1)[0].strip(" \t").translate(_ASCII_LOWER)
            except UnicodeDecodeError:
                ct = None
        out.append(MultipartPart(params["name"], is_file, content, ct))
    return out


def file_token(content: bytes, ct: Optional[str]) -> str:
    """22.3 point 5: ``drop:file:<kind>:<class>`` of a file part."""
    kind = magic_kind(content) or _FILE_TYPES.get(ct or "", "bin")
    return "drop:file:%s:%s" % (kind, doc_class(len(content)))


# ---------------------------------------------------------------------------------
# XML (22.2)

NS_XML = "http://www.w3.org/XML/1998/namespace"
SOAP11 = "http://schemas.xmlsoap.org/soap/envelope/"
SOAP12 = "http://www.w3.org/2003/05/soap-envelope"
XML_MAX_NESTING = 256
NS_MAX_BYTES = 512
NS_MAX_ENTRIES = 64

# Point 1: control characters other than tab, LF and CR, U+FFFE and U+FFFF (a strict UTF-8
# decode never yields surrogates).
_FORBIDDEN = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿\ud800-\udfff]")
_WS_RUN = re.compile("[ \t\n]*")
# Point 3: a name starts with an ASCII letter, '_' or a non-ASCII character and goes on with
# letters, digits, '.', '-', ':', '_' or non-ASCII characters.
_NAME = re.compile("[A-Za-z_\u0080-\U0010ffff][A-Za-z0-9._:\\-\u0080-\U0010ffff]*")
_REF = re.compile("&([^;]*);")
_NS_RUN = re.compile(r"[A-Za-z0-9_-]+")
_SIX_DIGITS = re.compile(r"[0-9]{6}")
_HEX12 = re.compile(r"[0-9A-Fa-f]{12}")
_NS_PRINTABLE = re.compile(r"[!-~]*")
_DEC = re.compile(r"[0-9]+")
_HEX = re.compile(r"[0-9A-Fa-f]+")
_ENTITIES = {"lt": "<", "gt": ">", "amp": "&", "apos": "'", "quot": '"'}


class InvalidXML(Exception):
    pass


def _xml_char(cp: int) -> bool:
    return cp in (0x9, 0xA, 0xD) or 0x20 <= cp <= 0xD7FF or 0xE000 <= cp <= 0xFFFD or 0x10000 <= cp <= 0x10FFFF


def _char_ref(digits: str, base: int) -> str:
    # The digit string may be very long: reject as soon as the value leaves the code space
    # (no big-integer work on attacker-sized input).
    cp = 0
    for d in digits:
        cp = cp * base + int(d, 16)
        if cp > 0x10FFFF:
            raise InvalidXML("reference out of range")
    if not _xml_char(cp):
        raise InvalidXML("reference to a forbidden character")
    return chr(cp)


def _refs(raw: str, attr: bool) -> str:
    """Point 5: predefined entities and character references; attribute values turn tab and LF into spaces."""
    if "&" not in raw:
        if attr and ("\t" in raw or "\n" in raw):
            return raw.replace("\t", " ").replace("\n", " ")
        return raw
    out: List[str] = []
    i = 0
    n = len(raw)
    while i < n:
        j = raw.find("&", i)
        chunk = raw[i:] if j < 0 else raw[i:j]
        if attr:
            chunk = chunk.replace("\t", " ").replace("\n", " ")
        out.append(chunk)
        if j < 0:
            break
        e = raw.find(";", j + 1)
        if e < 0:
            raise InvalidXML("unterminated reference")
        ent = raw[j + 1:e]
        rep = _ENTITIES.get(ent)
        if rep is not None:
            out.append(rep)
        elif ent.startswith("#x") and _HEX.fullmatch(ent, 2):
            out.append(_char_ref(ent[2:], 16))
        elif ent.startswith("#") and _DEC.fullmatch(ent, 1):
            out.append(_char_ref(ent[1:], 10))
        else:
            raise InvalidXML("unknown entity")
        i = e + 1
    return "".join(out)


def _split_qname(q: str) -> Tuple[Optional[str], str]:
    c = q.find(":")
    if c < 0:
        return None, q
    p, local = q[:c], q[c + 1:]
    if not p or not local or ":" in local:
        raise InvalidXML("qualified name")
    return p, local


class Elem:
    """One XML element: local name, namespace URI ('' = none), attributes (local, value)
    without the namespace declarations, child elements, text pieces and, once built, its
    tree value."""

    __slots__ = ("local", "ns", "attrs", "children", "text", "value")

    def __init__(self, local: str, ns: str, attrs: List[Tuple[str, str]]) -> None:
        self.local = local
        self.ns = ns
        self.attrs = attrs
        self.children: List["Elem"] = []
        self.text: List[str] = []
        self.value: Any = None


class _XmlReader:
    __slots__ = ("s", "n")

    def __init__(self, s: str) -> None:
        self.s = s
        self.n = len(s)

    def name(self, p: int) -> Tuple[str, int]:
        m = _NAME.match(self.s, p)
        if m is None:
            raise InvalidXML("name")
        return m.group(), m.end()

    def ws(self, p: int) -> int:
        return _WS_RUN.match(self.s, p).end()  # type: ignore[union-attr]

    def misc(self, p: int) -> Optional[int]:
        """Comment or processing instruction at p -> its end, or None if none starts there."""
        s = self.s
        if s.startswith("<!--", p):
            e = s.find("-->", p + 4)
            if e < 0:
                raise InvalidXML("unterminated comment")
            return e + 3
        if s.startswith("<?", p):
            e = s.find("?>", p + 2)
            if e < 0:
                raise InvalidXML("unterminated processing instruction")
            return e + 2
        return None

    def start_tag(self, p: int, parent_ns: Dict[str, str]) -> Tuple[str, Elem, Dict[str, str], bool, int]:
        s, n = self.s, self.n
        qname, p = self.name(p + 1)
        raw_attrs: List[Tuple[str, str]] = []
        seen = set()
        empty = False
        while True:
            q = self.ws(p)
            if s.startswith("/>", q):
                p, empty = q + 2, True
                break
            if s.startswith(">", q):
                p = q + 1
                break
            if q == p:
                raise InvalidXML("attribute without space")
            aname, q = self.name(q)
            q = self.ws(q)
            if q >= n or s[q] != "=":
                raise InvalidXML("attribute without =")
            q = self.ws(q + 1)
            if q >= n or s[q] not in "\"'":
                raise InvalidXML("attribute value")
            e = s.find(s[q], q + 1)
            if e < 0:
                raise InvalidXML("unterminated attribute value")
            raw = s[q + 1:e]
            if "<" in raw:
                raise InvalidXML("< in attribute value")
            if aname in seen:
                raise InvalidXML("duplicate attribute")
            seen.add(aname)
            raw_attrs.append((aname, _refs(raw, True)))
            p = e + 1
        nsmap = parent_ns
        for aname, v in raw_attrs:
            if aname == "xmlns" or aname.startswith("xmlns:"):
                if nsmap is parent_ns:
                    nsmap = dict(parent_ns)
                if aname == "xmlns":
                    nsmap[""] = v
                else:
                    pre = aname[6:]
                    if not pre or ":" in pre:
                        raise InvalidXML("namespace declaration")
                    nsmap[pre] = v
        prefix, local = _split_qname(qname)
        if prefix is None:
            ns = nsmap.get("", "")
        elif prefix == "xml":
            ns = NS_XML
        elif prefix in nsmap:
            ns = nsmap[prefix]
        else:
            raise InvalidXML("undeclared prefix")
        attrs: List[Tuple[str, str]] = []
        for aname, v in raw_attrs:
            if aname == "xmlns" or aname.startswith("xmlns:"):
                continue
            ap, al = _split_qname(aname)
            if ap is not None and ap != "xml" and ap not in nsmap:
                raise InvalidXML("undeclared attribute prefix")
            attrs.append((al, v))
        return qname, Elem(local, ns, attrs), nsmap, empty, p


def parse_xml(data: bytes) -> Elem:
    """22.2 points 1-6 -> root element. Raises InvalidXML outside the accepted subset."""
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        raise InvalidXML("not UTF-8") from None
    if _FORBIDDEN.search(s):
        raise InvalidXML("forbidden character")
    if "\r" in s:
        s = s.replace("\r\n", "\n").replace("\r", "\n")
    r = _XmlReader(s)
    n = len(s)
    pos = 0
    # prolog
    while True:
        pos = r.ws(pos)
        if pos >= n:
            raise InvalidXML("no root element")
        e = r.misc(pos)
        if e is not None:
            pos = e
            continue
        if s.startswith("<!", pos) or s[pos] != "<":
            raise InvalidXML("prolog")
        break
    qname, root, nsmap, empty, pos = r.start_tag(pos, {})
    stack: List[Tuple[str, Elem, Dict[str, str]]] = []
    if not empty:
        stack.append((qname, root, nsmap))
    while stack:
        if pos >= n:
            raise InvalidXML("unclosed element")
        qn, cur, cur_ns = stack[-1]
        if s[pos] != "<":
            e = s.find("<", pos)
            if e < 0:
                raise InvalidXML("unclosed element")
            cur.text.append(_refs(s[pos:e], False))
            pos = e
            continue
        if s.startswith("<![CDATA[", pos):
            e = s.find("]]>", pos + 9)
            if e < 0:
                raise InvalidXML("unterminated CDATA")
            cur.text.append(s[pos + 9:e])
            pos = e + 3
            continue
        e2 = r.misc(pos)
        if e2 is not None:
            pos = e2
            continue
        if s.startswith("<!", pos):
            raise InvalidXML("declaration in content")
        if s.startswith("</", pos):
            name, q = r.name(pos + 2)
            q = r.ws(q)
            if q >= n or s[q] != ">" or name != qn:
                raise InvalidXML("end tag")
            stack.pop()
            pos = q + 1
            continue
        qname, el, nsmap, empty, pos = r.start_tag(pos, cur_ns)
        cur.children.append(el)
        if not empty:
            if len(stack) >= XML_MAX_NESTING:
                raise InvalidXML("nesting")
            stack.append((qname, el, nsmap))
    # epilogue
    while True:
        pos = r.ws(pos)
        if pos >= n:
            break
        e = r.misc(pos)
        if e is None:
            raise InvalidXML("content after the root element")
        pos = e
    return root


def _element_value(el: Elem) -> Any:
    """Point 7, for one element whose children already hold their value."""
    if not el.attrs and not el.children:
        return "".join(el.text)
    members: List[Optional[Tuple[str, bool, Any]]] = []
    index: Dict[str, int] = {}
    for local, v in el.attrs:  # same local name twice: the last wins, at its own position
        k = "@" + local
        if k in index:
            members[index[k]] = None
        index[k] = len(members)
        members.append((k, False, v))
    groups: Dict[str, List[Any]] = {}
    order: List[str] = []
    for c in el.children:
        g = groups.get(c.local)
        if g is None:
            g = groups[c.local] = []
            order.append(c.local)
        g.append(c.value)
    for k in order:
        vs = groups[k]
        members.append((k, False, vs[0] if len(vs) == 1 else vs))
    text = "".join(el.text)
    if text.strip(" \t\n\r") != "":
        members.append(("#text", False, text))
    o = JObj()
    o.m = [m for m in members if m is not None]
    return o


def _build_values(root: Elem) -> None:
    """Post-order, iterative: each element gets its tree value."""
    stack: List[Tuple[Elem, bool]] = [(root, False)]
    while stack:
        el, done = stack.pop()
        if done:
            el.value = _element_value(el)
            for c in el.children:
                c.value = None  # held by the parent's value now
            continue
        stack.append((el, True))
        for c in el.children:
            stack.append((c, False))


def ns_pattern(uri: str) -> str:
    """Point 9: ``ns:`` + pattern of a namespace URI."""
    if uri == "":
        return "ns:{none}"
    if len(uri) > NS_MAX_BYTES or not _NS_PRINTABLE.fullmatch(uri) or "@" in uri or "{" in uri or "}" in uri:
        return "ns:{*}"

    def run(m: "re.Match[str]") -> str:
        t = m.group(0)
        if len(t) > 64 or _SIX_DIGITS.search(t) or _HEX12.search(t):
            return "{*}"
        return t
    return "ns:" + _NS_RUN.sub(run, uri)


def xml_tree(root: Elem, literal: Callable[[str], bool], max_depth: int) -> Tuple[JObj, List[Tuple[str, str]], str]:
    """-> (body tree, xmlns entries [(path, token)] in document order, fmt)."""
    # xmlns entries first: building the values releases the children's values, not the elements.
    entries: List[Tuple[str, str]] = []
    seen = set()
    stack: List[Tuple[Elem, str, str, int]] = [(root, "$" + ("." + root.local if literal(root.local) else ".*"), "", 1)]
    while stack:
        el, path, parent_ns, depth = stack.pop()
        if depth > max_depth:
            continue
        if el.ns != parent_ns and path not in seen:
            seen.add(path)
            entries.append((path, ns_pattern(el.ns)))
        if not el.children or depth + 1 > max_depth:
            continue
        counts: Dict[str, int] = {}
        for c in el.children:
            counts[c.local] = counts.get(c.local, 0) + 1
        nxt = []
        for c in el.children:
            p = path + ("." + c.local if literal(c.local) else ".*") + ("[*]" if counts[c.local] > 1 else "")
            nxt.append((c, p, el.ns, depth + 1))
        stack.extend(reversed(nxt))  # document order
    _build_values(root)
    tree = JObj()
    tree.m = [(root.local, False, root.value)]
    fmt = "xml"
    if root.local == "Envelope" and root.ns == SOAP11:
        fmt = "soap11"
    elif root.local == "Envelope" and root.ns == SOAP12:
        fmt = "soap12"
    return tree, entries, fmt


def soap_action_name(raw: str, literal: Callable[[str], bool]) -> Optional[str]:
    """Point 11: the operation name of a SOAPAction value, or None when empty."""
    s = raw.strip(" \t")
    if len(s) >= 2 and s.startswith('"') and s.endswith('"'):
        s = s[1:-1]
    if s == "":
        return None
    cut = max(s.rfind("/"), s.rfind("#"), s.rfind(":"))
    name = s[cut + 1:]
    return name if literal(name) else "{*}"
