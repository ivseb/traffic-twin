"""GraphQL document shape, sanitizer.md 5.7 (spec v1.14). Python 3 stdlib only.

shape(text) -> (shape, introspection_only) or None when the text is not an executable document
within the limits (the caller then emits the drop form of the string).
"""

MAX_NESTING = 64
MAX_SHAPE_BYTES = 32768
MAX_NAME_BYTES = 64

_PUNCT1 = '!$&:=@|'
_OPEN = '([{'
_CLOSE = ')]}'


class _Err(Exception):
    pass


def _name_start(c):
    return c == '_' or 'A' <= c <= 'Z' or 'a' <= c <= 'z'


def _name_cont(c):
    return _name_start(c) or '0' <= c <= '9'


def _digit(c):
    return '0' <= c <= '9'


def _hexd(c):
    return '0' <= c <= '9' or 'a' <= c <= 'f' or 'A' <= c <= 'F'


def _lex(src):
    """Tokens as [kind, text, value_flag]; kind in punct, name, int, float, str."""
    toks = []
    i, n, opened = 0, len(src), 0
    while i < n:
        c = src[i]
        if c in ' \t\n\r,' or c == '﻿':
            i += 1
        elif c == '#':
            while i < n and src[i] not in '\n\r':
                i += 1
        elif c in _PUNCT1:
            toks.append(['punct', c, False])
            i += 1
        elif c in _OPEN:
            opened += 1
            if opened > MAX_NESTING:
                raise _Err()
            toks.append(['punct', c, False])
            i += 1
        elif c in _CLOSE:
            opened -= 1
            if opened < 0:
                raise _Err()
            toks.append(['punct', c, False])
            i += 1
        elif c == '.':
            if src[i:i + 3] != '...':
                raise _Err()
            toks.append(['punct', '...', False])
            i += 3
        elif _name_start(c):
            j = i + 1
            while j < n and _name_cont(src[j]):
                j += 1
            toks.append(['name', src[i:j], False])
            i = j
        elif c == '-' or _digit(c):
            i, kind = _number(src, i)
            toks.append([kind, '', False])
        elif c == '"':
            i = _string(src, i)
            toks.append(['str', '', False])
        else:
            raise _Err()
    if opened != 0:
        raise _Err()
    return toks


def _number(src, i):
    n = len(src)
    j = i
    if src[j] == '-':
        j += 1
    if j >= n or not _digit(src[j]):
        raise _Err()
    if src[j] == '0':
        j += 1
        if j < n and _digit(src[j]):
            raise _Err()
    else:
        while j < n and _digit(src[j]):
            j += 1
    kind = 'int'
    if j < n and src[j] == '.':
        j += 1
        if j >= n or not _digit(src[j]):
            raise _Err()
        while j < n and _digit(src[j]):
            j += 1
        kind = 'float'
    if j < n and src[j] in 'eE':
        j += 1
        if j < n and src[j] in '+-':
            j += 1
        if j >= n or not _digit(src[j]):
            raise _Err()
        while j < n and _digit(src[j]):
            j += 1
        kind = 'float'
    if j < n and (src[j] == '.' or _name_start(src[j])):
        raise _Err()
    return j, kind


def _string(src, i):
    n = len(src)
    if src[i:i + 3] == '"""':
        j = i + 3
        while j < n:
            if src[j:j + 4] == '\\"""':
                j += 4
            elif src[j:j + 3] == '"""':
                return j + 3
            elif ord(src[j]) < 0x20 and src[j] not in '\t\n\r':
                raise _Err()
            else:
                j += 1
        raise _Err()
    j = i + 1
    while j < n:
        c = src[j]
        if c == '"':
            return j + 1
        if c == '\\':
            if j + 1 >= n:
                raise _Err()
            e = src[j + 1]
            if e in '"\\/bfnrt':
                j += 2
            elif e == 'u':
                h = src[j + 2:j + 6]
                if len(h) != 4 or not all(_hexd(x) for x in h):
                    raise _Err()
                j += 6
            else:
                raise _Err()
        elif ord(c) < 0x20 and c != '\t':
            raise _Err()
        else:
            j += 1
    raise _Err()


class _Parser:
    def __init__(self, toks):
        self.t = toks
        self.p = 0
        self.ops = []  # root selections per operation: list of (kind, alias, name)

    def peek(self):
        return self.t[self.p] if self.p < len(self.t) else None

    def is_punct(self, s):
        t = self.peek()
        return t is not None and t[0] == 'punct' and t[1] == s

    def is_name(self, s=None):
        t = self.peek()
        return t is not None and t[0] == 'name' and (s is None or t[1] == s)

    def expect(self, s):
        if not self.is_punct(s):
            raise _Err()
        self.p += 1

    def name(self):
        if not self.is_name():
            raise _Err()
        self.p += 1
        return self.t[self.p - 1][1]

    def document(self):
        if not self.t:
            raise _Err()
        while self.p < len(self.t):
            if self.is_punct('{'):
                self.ops.append(self.selection_set())
            elif self.is_name('query') or self.is_name('mutation') or self.is_name('subscription'):
                self.p += 1
                if self.is_name():
                    self.p += 1
                if self.is_punct('('):
                    self.p += 1
                    if self.is_punct(')'):
                        raise _Err()
                    while not self.is_punct(')'):
                        self.var_def()
                    self.p += 1
                self.directives()
                self.ops.append(self.selection_set())
            elif self.is_name('fragment'):
                self.p += 1
                if self.name() == 'on':
                    raise _Err()
                if not self.is_name('on'):
                    raise _Err()
                self.p += 1
                self.name()
                self.directives()
                self.selection_set()
            else:
                raise _Err()

    def var_def(self):
        self.expect('$')
        self.name()
        self.expect(':')
        self.type_ref()
        if self.is_punct('='):
            self.p += 1
            self.value()
        self.directives()

    def type_ref(self):
        if self.is_punct('['):
            self.p += 1
            self.type_ref()
            self.expect(']')
        else:
            self.name()
        if self.is_punct('!'):
            self.p += 1

    def selection_set(self):
        self.expect('{')
        out = []
        while not self.is_punct('}'):
            out.append(self.selection())
        if not out:
            raise _Err()
        self.p += 1
        return out

    def selection(self):
        if self.is_punct('...'):
            self.p += 1
            if self.is_name() and not self.is_name('on'):
                self.p += 1
                self.directives()
                return ('spread', None, None)
            if self.is_name():  # on
                self.p += 1
                self.name()
            self.directives()
            self.selection_set()
            return ('inline', None, None)
        n = self.name()
        alias = None
        if self.is_punct(':'):
            self.p += 1
            alias, n = n, self.name()
        if self.is_punct('('):
            self.arguments()
        self.directives()
        if self.is_punct('{'):
            self.selection_set()
        return ('field', alias, n)

    def arguments(self):
        self.expect('(')
        if self.is_punct(')'):
            raise _Err()
        while not self.is_punct(')'):
            self.name()
            self.expect(':')
            self.value()
        self.p += 1

    def directives(self):
        while self.is_punct('@'):
            self.p += 1
            self.name()
            if self.is_punct('('):
                self.arguments()

    def value(self):
        t = self.peek()
        if t is None:
            raise _Err()
        if t[0] == 'punct':
            if t[1] == '$':
                self.p += 1
                self.name()
                return
            if t[1] == '[':
                self.p += 1
                while not self.is_punct(']'):
                    self.value()
                self.p += 1
                return
            if t[1] == '{':
                self.p += 1
                while not self.is_punct('}'):
                    self.name()
                    self.expect(':')
                    self.value()
                self.p += 1
                return
            raise _Err()
        if t[0] == 'name':
            t[2] = True
        self.p += 1


def name_safe(name):
    """The key rule of 9.3 on a GraphQL name (5.7.1)."""
    b = len(name)
    if b == 0 or b > MAX_NAME_BYTES or not _name_start(name[0]) or not all(_name_cont(c) for c in name):
        return False
    if b >= 16 and all(_hexd(c) for c in name):
        return False
    run = 0
    for c in name:
        run = run + 1 if _digit(c) else 0
        if run >= 6:
            return False
    return True


def is_name(s):
    return len(s) > 0 and _name_start(s[0]) and all(_name_cont(c) for c in s)


def _word(c):
    return _name_cont(c) or c in '?*'


def shape(src):
    try:
        toks = _lex(src)
        p = _Parser(toks)
        p.document()
    except (_Err, IndexError):
        return None
    out = []
    size = 0
    prev_word = False
    for kind, text, value in toks:
        if kind == 'punct':
            s = text
        elif kind == 'name':
            if value:
                s = '?b' if text in ('true', 'false') else '?n' if text == 'null' else '?e'
            else:
                s = text if name_safe(text) else '*'
        elif kind == 'int':
            s = '?i'
        elif kind == 'float':
            s = '?f'
        else:
            s = '?s'
        if prev_word and _word(s[0]):
            out.append(' ')
            size += 1
        out.append(s)
        size += len(s)
        prev_word = _word(s[-1])
        if size > MAX_SHAPE_BYTES:
            return None
    intro = bool(p.ops) and all(
        k == 'field' and alias is None and n in ('__schema', '__type', '__typename')
        for sel in p.ops for (k, alias, n) in sel)
    return ''.join(out), intro
