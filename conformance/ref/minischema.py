"""A small JSON Schema (draft 2020-12) validator, standard library only.

Supports the keywords used by conformance/schema/vector.v1.schema.json and by the
repository schemas in schemas/: $ref (local), type, enum, const, properties,
required, additionalProperties, propertyNames, patternProperties, items,
prefixItems, minItems, maxItems, minLength, maxLength, minimum, maximum,
minProperties, maxProperties, pattern, oneOf, anyOf, allOf, not, if/then/else.
`format` is an annotation and is ignored. Instances come from ttjson (numbers are
ttjson.Num).
"""

import re
from decimal import Decimal

import ttjson as J


def _num(v):
    return Decimal(v.lexeme) if isinstance(v, J.Num) else None


def _type_ok(v, t):
    if t == 'object':
        return isinstance(v, dict)
    if t == 'array':
        return isinstance(v, list)
    if t == 'string':
        return isinstance(v, str)
    if t == 'boolean':
        return v is True or v is False
    if t == 'null':
        return v is None
    if t == 'number':
        return isinstance(v, J.Num)
    if t == 'integer':
        return isinstance(v, J.Num) and _num(v) == _num(v).to_integral_value()
    raise ValueError('unknown type ' + t)


def _eq(a, b):
    if isinstance(a, J.Num) and isinstance(b, J.Num):
        return _num(a) == _num(b)
    if isinstance(a, J.Num) or isinstance(b, J.Num):
        an = _num(a) if isinstance(a, J.Num) else (Decimal(a) if isinstance(a, int) and not isinstance(a, bool) else None)
        bn = _num(b) if isinstance(b, J.Num) else (Decimal(b) if isinstance(b, int) and not isinstance(b, bool) else None)
        return an is not None and an == bn
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_eq(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_eq(a[k], b[k]) for k in a)
    return type(a) == type(b) and a == b


class Validator:
    def __init__(self, root):
        self.root = root

    def resolve(self, ref):
        assert ref.startswith('#'), ref
        node = self.root
        for part in ref[1:].split('/')[1:]:
            node = node[part.replace('~1', '/').replace('~0', '~')]
        return node

    def errors(self, v, schema=None, path='$'):
        if schema is None:
            schema = self.root
        out = []
        self._check(v, schema, path, out)
        return out

    def valid(self, v, schema, path='$'):
        out = []
        self._check(v, schema, path, out)
        return not out

    def _check(self, v, s, path, out):
        if s is True:
            return
        if s is False:
            out.append('%s: false schema' % path)
            return
        if '$ref' in s:
            self._check(v, self.resolve(s['$ref']), path, out)
        if 'type' in s:
            ts = s['type'] if isinstance(s['type'], list) else [s['type']]
            if not any(_type_ok(v, t) for t in ts):
                out.append('%s: expected type %s' % (path, s['type']))
                return
        if 'const' in s and not _eq(v, s['const']):
            out.append('%s: expected const %r' % (path, s['const']))
        if 'enum' in s and not any(_eq(v, e) for e in s['enum']):
            out.append('%s: not in enum %r' % (path, s['enum']))
        if isinstance(v, str):
            if 'pattern' in s and not re.search(s['pattern'], v):
                out.append('%s: %r does not match %s' % (path, v[:80], s['pattern']))
            n = len(v)  # code points
            if 'minLength' in s and n < int(s['minLength'].lexeme):
                out.append('%s: shorter than minLength' % path)
            if 'maxLength' in s and n > int(s['maxLength'].lexeme):
                out.append('%s: longer than maxLength' % path)
        if isinstance(v, J.Num):
            if 'minimum' in s and _num(v) < _num(s['minimum']):
                out.append('%s: below minimum' % path)
            if 'maximum' in s and _num(v) > _num(s['maximum']):
                out.append('%s: above maximum' % path)
        if isinstance(v, list):
            if 'minItems' in s and len(v) < int(s['minItems'].lexeme):
                out.append('%s: fewer than minItems' % path)
            if 'maxItems' in s and len(v) > int(s['maxItems'].lexeme):
                out.append('%s: more than maxItems' % path)
            if s.get('uniqueItems') is True:
                for i in range(len(v)):
                    if any(_eq(v[i], v[j]) for j in range(i)):
                        out.append('%s: items not unique' % path)
                        break
            pre = s.get('prefixItems', [])
            for i, x in enumerate(v):
                if i < len(pre):
                    self._check(x, pre[i], '%s[%d]' % (path, i), out)
                elif 'items' in s:
                    self._check(x, s['items'], '%s[%d]' % (path, i), out)
        if isinstance(v, dict):
            if 'minProperties' in s and len(v) < int(s['minProperties'].lexeme):
                out.append('%s: fewer than minProperties' % path)
            if 'maxProperties' in s and len(v) > int(s['maxProperties'].lexeme):
                out.append('%s: more than maxProperties' % path)
            for r in s.get('required', []):
                if r not in v:
                    out.append('%s: missing required %s' % (path, r))
            props = s.get('properties', {})
            pprops = s.get('patternProperties', {})
            for k, x in v.items():
                if 'propertyNames' in s:
                    self._check(k, s['propertyNames'], '%s{%s}' % (path, k), out)
                matched = False
                if k in props:
                    matched = True
                    self._check(x, props[k], '%s.%s' % (path, k), out)
                for pat, sub in pprops.items():
                    if re.search(pat, k):
                        matched = True
                        self._check(x, sub, '%s.%s' % (path, k), out)
                if not matched and 'additionalProperties' in s:
                    self._check(x, s['additionalProperties'], '%s.%s' % (path, k), out)
        if 'allOf' in s:
            for sub in s['allOf']:
                self._check(v, sub, path, out)
        if 'anyOf' in s and not any(self.valid(v, sub, path) for sub in s['anyOf']):
            out.append('%s: matches no anyOf branch' % path)
        if 'oneOf' in s:
            n = sum(1 for sub in s['oneOf'] if self.valid(v, sub, path))
            if n != 1:
                out.append('%s: matches %d oneOf branches' % (path, n))
        if 'not' in s and self.valid(v, s['not'], path):
            out.append('%s: matches a not schema' % path)
        if 'if' in s:
            if self.valid(v, s['if'], path):
                if 'then' in s:
                    self._check(v, s['then'], path, out)
            elif 'else' in s:
                self._check(v, s['else'], path, out)
