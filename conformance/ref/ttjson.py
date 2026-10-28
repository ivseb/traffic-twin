"""Lexeme-preserving JSON parser and tt canonical JSON (tt-cjson) writer.

Reference code for the conformance vectors. Python 3 standard library only.

Spec: docs/spec/sanitizer.md section 9.2 (parsing) and section 10 (canonical form).
"""

import re


NUM_RE = re.compile(r'-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?')
WS = ' \t\n\r'


class InvalidJSON(Exception):
    pass


class Num:
    """A JSON number kept as its original lexeme (never converted to a double)."""

    __slots__ = ('lexeme',)

    def __init__(self, lexeme):
        self.lexeme = lexeme

    def __repr__(self):
        return 'Num(%s)' % self.lexeme

    def __eq__(self, other):
        return isinstance(other, Num) and other.lexeme == self.lexeme

    def __hash__(self):
        return hash(self.lexeme)


class Obj:
    """A JSON object after duplicate-key resolution.

    `members` is the ordered list of (key, value). A duplicated key keeps only its
    last occurrence, at the position of that last occurrence (sanitizer.md 9.2).
    Keys are Python str and may contain lone surrogates (from \\uD800 escapes).
    """

    __slots__ = ('members',)

    def __init__(self, members):
        self.members = members

    def get(self, key, default=None):
        for k, v in self.members:
            if k == key:
                return v
        return default


class _TruncDepth:
    def __repr__(self):
        return 'TRUNC_DEPTH'


TRUNC_DEPTH = _TruncDepth()


def is_valid_str(s):
    """False if the string holds a lone surrogate code point."""
    return not any(0xD800 <= ord(c) <= 0xDFFF for c in s)


def utf8(s):
    """UTF-8 bytes of a string; lone surrogates are encoded as WTF-8 (only used for sorting)."""
    return s.encode('utf-8', 'surrogatepass')


class _Parser:
    def __init__(self, text, max_depth):
        self.s = text
        self.i = 0
        self.max_depth = max_depth

    def fail(self, msg):
        raise InvalidJSON('%s at %d' % (msg, self.i))

    def ws(self):
        s, i = self.s, self.i
        while i < len(s) and s[i] in WS:
            i += 1
        self.i = i

    def value(self, depth):
        self.ws()
        if self.i >= len(self.s):
            self.fail('unexpected end')
        c = self.s[self.i]
        if c == '{':
            return self.obj(depth)
        if c == '[':
            return self.arr(depth)
        if c == '"':
            return self.string()
        if self.s.startswith('true', self.i):
            self.i += 4
            return True
        if self.s.startswith('false', self.i):
            self.i += 5
            return False
        if self.s.startswith('null', self.i):
            self.i += 4
            return None
        m = NUM_RE.match(self.s, self.i)
        if m and m.end() > self.i:
            self.i = m.end()
            return Num(m.group(0))
        self.fail('unexpected character')

    def too_deep(self, depth):
        return self.max_depth is not None and depth > self.max_depth

    def obj(self, depth):
        self.i += 1
        members = []
        index = {}
        self.ws()
        if self.i < len(self.s) and self.s[self.i] == '}':
            self.i += 1
            return TRUNC_DEPTH if self.too_deep(depth) else Obj([])
        while True:
            self.ws()
            if self.i >= len(self.s) or self.s[self.i] != '"':
                self.fail('expected key')
            k = self.string()
            self.ws()
            if self.i >= len(self.s) or self.s[self.i] != ':':
                self.fail('expected colon')
            self.i += 1
            v = self.value(depth + 1)
            if k in index:
                members[index[k]] = None
            index[k] = len(members)
            members.append((k, v))
            self.ws()
            if self.i >= len(self.s):
                self.fail('unterminated object')
            c = self.s[self.i]
            self.i += 1
            if c == '}':
                break
            if c != ',':
                self.fail('expected , or }')
        if self.too_deep(depth):
            return TRUNC_DEPTH
        return Obj([m for m in members if m is not None])

    def arr(self, depth):
        self.i += 1
        items = []
        self.ws()
        if self.i < len(self.s) and self.s[self.i] == ']':
            self.i += 1
            return TRUNC_DEPTH if self.too_deep(depth) else []
        while True:
            items.append(self.value(depth + 1))
            self.ws()
            if self.i >= len(self.s):
                self.fail('unterminated array')
            c = self.s[self.i]
            self.i += 1
            if c == ']':
                break
            if c != ',':
                self.fail('expected , or ]')
        if self.too_deep(depth):
            return TRUNC_DEPTH
        return items

    def string(self):
        s = self.s
        self.i += 1
        out = []
        while True:
            if self.i >= len(s):
                self.fail('unterminated string')
            c = s[self.i]
            if c == '"':
                self.i += 1
                break
            if ord(c) < 0x20:
                self.fail('control character in string')
            if c != '\\':
                out.append(c)
                self.i += 1
                continue
            self.i += 1
            if self.i >= len(s):
                self.fail('bad escape')
            e = s[self.i]
            self.i += 1
            simple = {'"': '"', '\\': '\\', '/': '/', 'b': '\b', 'f': '\f',
                      'n': '\n', 'r': '\r', 't': '\t'}
            if e in simple:
                out.append(simple[e])
            elif e == 'u':
                h = s[self.i:self.i + 4]
                if len(h) != 4 or not re.fullmatch(r'[0-9A-Fa-f]{4}', h):
                    self.fail('bad \\u escape')
                self.i += 4
                out.append(chr(int(h, 16)))
            else:
                self.fail('bad escape')
        # Join escaped surrogate pairs into one code point; lone ones stay as-is.
        joined = []
        chars = out
        k = 0
        while k < len(chars):
            c = chars[k]
            o = ord(c)
            if 0xD800 <= o <= 0xDBFF and k + 1 < len(chars) and 0xDC00 <= ord(chars[k + 1]) <= 0xDFFF:
                joined.append(chr(0x10000 + ((o - 0xD800) << 10) + (ord(chars[k + 1]) - 0xDC00)))
                k += 2
            else:
                joined.append(c)
                k += 1
        return ''.join(joined)


def parse(data, max_depth=None):
    """Parse RFC 8259 JSON from bytes. Raises InvalidJSON.

    Containers deeper than max_depth (root = depth 1) become TRUNC_DEPTH, but the
    whole document is still validated.
    """
    if data.startswith(b'\xef\xbb\xbf'):  # 9.2: BOM rejected
        raise InvalidJSON('byte order mark')
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        raise InvalidJSON('invalid UTF-8')
    p = _Parser(text, max_depth)
    v = p.value(1)
    p.ws()
    if p.i != len(text):
        p.fail('trailing data')
    return v


def to_py(v):
    """Obj -> dict (for policy documents and vector files, which have no duplicates)."""
    if isinstance(v, Obj):
        return {k: to_py(x) for k, x in v.members}
    if isinstance(v, list):
        return [to_py(x) for x in v]
    return v


# ---------------------------------------------------------------- canonical numbers

def canon_num(lexeme):
    """Canonical form of a JSON number lexeme (sanitizer.md 10.2), exact decimal."""
    m = NUM_RE.fullmatch(lexeme)
    if not m:
        raise ValueError('not a JSON number: %r' % lexeme)
    neg = lexeme.startswith('-')
    intp = m.group(1)
    frac = (m.group(2) or '.')[1:]
    exp = int(m.group(3)[1:]) if m.group(3) else 0
    digits = (intp + frac).lstrip('0')
    e10 = exp - len(frac)
    if not digits:
        return '0'
    stripped = digits.rstrip('0')
    e10 += len(digits) - len(stripped)
    digits = stripped
    n = len(digits)
    e = e10 + n
    if -6 < e <= 21:
        if e10 >= 0:
            s = digits + '0' * e10
        elif e > 0:
            s = digits[:e] + '.' + digits[e:]
        else:
            s = '0.' + '0' * (-e) + digits
    else:
        k = e - 1
        s = digits[0] + ('.' + digits[1:] if n > 1 else '') + 'e' + ('+' if k >= 0 else '-') + str(abs(k))
    return ('-' if neg else '') + s


# ---------------------------------------------------------------- canonical writer

def _esc(s):
    out = ['"']
    for ch in s:
        c = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif c < 0x20 or c >= 0x7F:
            if c > 0xFFFF:
                c -= 0x10000
                out.append('\\u%04x\\u%04x' % (0xD800 + (c >> 10), 0xDC00 + (c & 0x3FF)))
            else:
                out.append('\\u%04x' % c)
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def dumps(v):
    """tt-cjson: no whitespace, keys sorted by UTF-8 bytes, minimal escapes, canonical numbers."""
    if v is None:
        return 'null'
    if v is True:
        return 'true'
    if v is False:
        return 'false'
    if isinstance(v, Num):
        return canon_num(v.lexeme)
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return _esc(v)
    if isinstance(v, list):
        return '[' + ','.join(dumps(x) for x in v) + ']'
    if isinstance(v, dict):
        keys = sorted(v.keys(), key=utf8)
        return '{' + ','.join(_esc(k) + ':' + dumps(v[k]) for k in keys) + '}'
    raise TypeError('cannot serialize %r' % (v,))


def pretty(v, indent=0):
    """Readable, deterministic, ASCII-only JSON for vector files (insertion order kept)."""
    pad = '  ' * indent
    if isinstance(v, dict):
        if not v:
            return '{}'
        items = [pad + '  ' + _esc(k) + ': ' + pretty(x, indent + 1) for k, x in v.items()]
        return '{\n' + ',\n'.join(items) + '\n' + pad + '}'
    if isinstance(v, list):
        if not v:
            return '[]'
        if all(not isinstance(x, (dict, list)) for x in v):
            flat = '[' + ', '.join(pretty(x) for x in v) + ']'
            if len(flat) <= 100:
                return flat
        items = [pad + '  ' + pretty(x, indent + 1) for x in v]
        return '[\n' + ',\n'.join(items) + '\n' + pad + ']'
    return dumps(v)
