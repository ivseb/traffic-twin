#!/usr/bin/env python3
"""Property check for guarantee G1 (sanitizer.md section 13) over the vectors.

Usage: python3 conformance/ref/leakcheck.py

For every vector whose policy is empty (no rules, no services, no identity, no
discovery, auto_words false, empty allow list) and whose outcome is an event:

  A. every string in the output outside the service fields is a closed-grammar
     token (drop:* or trunc:*), and every path segment is {drop:*}, {trunc};
  B. every object key in the output is a fixed field name, {*}, {trunc}, or a
     name that occurs in the input (header, cookie, query, form or JSON key);
  C. no input string value of length >= 3 appears in the output once the
     allowed parts are removed (closed tokens, method, ct, size, service,
     route_source, sampled_by). Input values are: path segments (raw and
     decoded), query and form values (raw and decoded), header values and their
     sub-tokens, cookie values, JSON string leaves, number lexemes and dynamic
     keys, and the words of non-JSON bodies. A value that is itself an allowed
     name of the same exchange is reported as skipped, not as a leak;
  D. (spec v1.5) a host service is host:unlisted, host:invalid, host:ip:<class>[:port]
     or a pattern whose every label is {*} or passes the safe-label rule of
     sanitizer.md 3.5 (the host itself is structure, like a name);
  E. (spec v1.14) for every graphql vector (any policy): every gql: token of a
     request is made of the shape alphabet only, and no string literal (>= 3
     characters) nor number literal (>= 2 characters) written inline in an
     input GraphQL document appears in it.
  F. (spec v1.19) XML and multipart bodies: element, attribute and part names are names, text, attribute
     and part contents are values; fmt is one of its closed values; soap_action is {*} or an input name
     (an element of the SOAPAction); the xmlns values are ns:{none}, ns:{*} or patterns whose every
     [A-Za-z0-9_-] run is {*} or passes the run rule of sanitizer.md 22.2 point 9.

Exits non-zero on any violation.
"""

import os
import re
import sys

sys.setrecursionlimit(20000)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bodies as BD  # noqa: E402
import sanitizer as S  # noqa: E402
import ttjson as J  # noqa: E402
import vectorio  # noqa: E402

CLASSES = 'l8|l32|l128|l1024|lmax'
CLOSED = re.compile(
    r'drop:(null|bool|int|dec|bytes|str:(invalid|uuid|jwt|email|datetime|date|url|ipv4|phone|digits|hex|'
    + CLASSES + r')|(obj|arr|bytes):(' + CLASSES + r'))'
    r'|trunc:(depth|invalid-json|invalid-xml|invalid-multipart|size|(n|keys):(' + CLASSES + r'))'
    r'|drop:(doc|file):[a-z]{3,4}:(l1k|l16k|l128k|l1m|l8m|lmax)')
FORMATS_V112 = {'xml', 'soap11', 'soap12', 'multipart'}
FIXED_KEYS = {'service', 'op', 'route_source', 'sampled_by', 'subject', 'disc', 'req', 'resp', 'path', 'query',
              'headers', 'cookies', 'ct', 'size', 'body', '{*}', '{trunc}', 'fmt', 'xmlns', 'soap_action', '#text'}
SPLIT = re.compile(r'[\s;,=:"<>()\[\]{}/\\?&]+')


def is_empty_policy(p):
    def no_rules(scope):
        return not any(scope.get(k) for k in ('request', 'response', 'errors'))
    return (not p.get('services') and no_rules(p.get('global') or {}) and 'identity' not in p
            and not (p.get('discovery') or {}).get('enabled') and not p['segments']['auto_words']
            and not p['segments']['allow'] and not p['segments']['hosts_allow'])


def text(b):
    return S.utf8_or_none(b)


def json_values(node, values, names):
    if isinstance(node, J.Obj):
        for k, v in node.members:
            (names if S.name_is_literal(k) else values).add(k)
            json_values(v, values, names)
    elif isinstance(node, list):
        for v in node:
            json_values(v, values, names)
    elif isinstance(node, J.Num):
        values.add(node.lexeme)
    elif isinstance(node, str):
        values.add(node)


def urlencoded_values(raw, values, names):
    for part in raw.split(b'&'):
        if not part:
            continue
        nb, _, vb = part.partition(b'=')
        for b in (vb, S.pct_decode(vb, True)):
            t = text(b)
            if t is not None:
                values.add(t)
        n = text(S.pct_decode(nb, True))
        if n is not None:
            (names if S.name_is_literal(n) else values).add(n)
            if not S.name_is_literal(n):
                values.add(text(nb) or '')


def xml_values(el, values, names):
    (names if S.name_is_literal(el.local) else values).add(el.local)
    for k, v in el.attrs:
        if S.name_is_literal(k):
            names.update(('@' + k, k))
        else:
            values.add(k)
        values.add(v)
    values.add(''.join(el.text))
    for c in el.children:
        xml_values(c, values, names)


def collect(inp):
    values, names = set(), set()
    for seg in inp['raw_path'].split(b'/'):
        for b in (seg, S.pct_decode(seg)):
            t = text(b)
            if t:
                values.add(t)
    urlencoded_values(inp.get('raw_query', b''), values, names)
    if inp.get('trace_id'):
        values.add(inp['trace_id'])
    for side in ('req', 'resp'):
        hdrs = inp.get(side + '_headers', [])
        ct = None
        enc = None
        for n, v in hdrs:
            names.add(S.header_name_out(S.ascii_lower(n)))
            if S.ascii_lower(n) == 'content-encoding' and enc is None:
                enc = S.ascii_lower(v.decode('latin-1').strip(' \t'))
            if S.ascii_lower(n) in ('cookie', 'set-cookie'):
                # set-cookie: only the first piece names a cookie; attributes are values.
                pieces = v.split(b';') if S.ascii_lower(n) == 'cookie' else v.split(b';')[:1]
                for piece in pieces:
                    if b'=' not in piece:
                        continue
                    k = text(piece.strip(b' \t').partition(b'=')[0])
                    if k is not None and S.name_is_literal(k):
                        names.add(k)
            t = text(v)
            if t is None:
                continue
            values.add(t)
            values.update(SPLIT.split(t))
            if S.ascii_lower(n) == 'content-type' and ct is None:
                ct = S.media_value(S.normalize_headers([(n, v)]), 'content-type')
            if S.ascii_lower(n) in ('cookie', 'set-cookie'):
                for piece in t.split(';'):
                    k, _, val = piece.strip(' \t').partition('=')
                    values.add(val)
                    if k not in names:
                        values.add(k)
        body = inp.get(side + '_body', b'')
        if not body:
            continue
        if enc in ('gzip', 'x-gzip', 'deflate') and not inp.get(side + '_body_decoded'):
            body = S.inflate(body, 15 if enc == 'deflate' else 31, 64 << 20) or body
        if ct == 'application/x-www-form-urlencoded':
            urlencoded_values(body, values, names)
            continue
        if ct == 'multipart/form-data':
            bnd = BD.media_params(S.normalize_headers(hdrs) and S.header_value(S.normalize_headers(hdrs), 'content-type')).get('boundary')
            try:
                for pn, _, content, _ in BD.parse_multipart(body, bnd):
                    (names if S.name_is_literal(pn) else values).add(pn)
                    t = text(content)
                    if t is not None:
                        values.add(t)
                continue
            except BD.InvalidMultipart:
                pass
        try:
            xml_values(BD.parse_xml(body), values, names)
            for q in re.findall(r'</?([A-Za-z_][A-Za-z0-9_.-]*):', body.decode('utf-8', 'replace')):
                names.add(q)  # namespace prefixes are structure (they never leave)
            continue
        except BD.InvalidXML:
            pass
        try:
            json_values(J.parse(body), values, names)
            continue
        except J.InvalidJSON:
            pass
        t = text(body)
        if t is not None:
            values.add(t)
            values.update(re.split(r'[^A-Za-z0-9@._+%-]+', t))
    return {v for v in values if v and len(v) >= 3}, names


def check(vec):
    errors = []
    inp = vectorio.load_input(vec['input'])
    out = J.to_py(J.parse(vec['expected']['canonical'].encode('ascii')))
    values, names = collect(inp)
    allowed = set()

    def walk(node, where, multimap=False):
        if isinstance(node, dict):
            for k, v in node.items():
                if k not in FIXED_KEYS and k not in names:
                    errors.append('B: key %r at %s is not an input name' % (k, where))
                walk(v, where + '.' + k)
        elif isinstance(node, list):
            for v in node:
                walk(v, where + '[]')
        elif isinstance(node, str):
            if not CLOSED.fullmatch(node):
                errors.append('A: free string %r at %s' % (node, where))
        elif node is not None and not isinstance(node, bool):
            errors.append('A: non-string value %r at %s' % (node, where))

    for side in ('req', 'resp'):
        part = dict(out.get(side) or {})
        if not part:
            continue
        for f in ('ct', 'size'):
            if f in part:
                allowed.add(part.pop(f))
        fmt = part.pop('fmt', None)
        if fmt is not None:
            if fmt not in FORMATS_V112:
                errors.append('F: fmt %r' % fmt)
            allowed.add(fmt)
        sa = part.pop('soap_action', None)
        if sa is not None and sa != '{*}' and not S.name_is_literal(sa):
            errors.append('F: soap_action %r' % sa)
        if sa is not None:
            allowed.add(sa)
        for xp, tok in (part.pop('xmlns', None) or {}).items():
            allowed.add(xp)
            allowed.add(tok)
            if xp == '{trunc}':
                if not CLOSED.fullmatch(tok):
                    errors.append('F: xmlns trunc %r' % tok)
                continue
            for k in re.findall(r'\.([^.\[]+)', xp):
                if k != '*' and k not in names:
                    errors.append('F: xmlns path %r names %r, not an input name' % (xp, k))
            pat = tok[len('ns:'):]
            if pat not in ('{none}', '{*}'):
                for run in re.findall(r'[A-Za-z0-9_-]+', pat.replace('{*}', '')):
                    if len(run) > 64 or re.search(r'[0-9]{6}', run) or re.search(r'[0-9A-Fa-f]{12}', run):
                        errors.append('F: xmlns run %r is not safe' % run)
        path = part.pop('path', None)
        if path is not None and path != '/':
            for seg in path[1:].split('/'):
                if seg != '{trunc}' and not (seg.startswith('{') and CLOSED.fullmatch(seg[1:-1])):
                    errors.append('A: path segment %r' % seg)
        walk(part, side)
    method, _, oppath = out['op'].partition(' ')
    if oppath != out['req']['path']:
        errors.append('A: op path differs from req.path')
    allowed.update([out['service'], method])
    svc = out['service']
    if svc.startswith('host:') and svc not in ('host:unlisted', 'host:invalid'):
        pat = svc[len('host:'):]
        if ':' in pat and pat.rsplit(':', 1)[1].isdigit():
            pat = pat.rsplit(':', 1)[0]
        if pat not in ('ip:private', 'ip:public'):
            for lab in pat.split('.'):
                if lab != '{*}' and not S.host_label_safe(lab):
                    errors.append('D: host label %r is not safe' % lab)
    if set(out) - {'service', 'op', 'route_source', 'sampled_by', 'req', 'resp'}:
        errors.append('A: unexpected top-level fields %s' % sorted(set(out) - FIXED_KEYS))

    # C: residual text = canonical minus closed tokens and allowed service values.
    residual = vec['expected']['canonical']
    residual = re.sub(r'"(%s)"' % CLOSED.pattern, '""', residual)
    residual = re.sub(r'\{(%s)\}' % CLOSED.pattern, '{}', residual)
    for a in sorted(allowed, key=len, reverse=True):
        residual = residual.replace(J.dumps(a), '""')
    residual = residual.replace(method + ' /', ' /')
    for k in sorted(FIXED_KEYS | names, key=len, reverse=True):
        residual = residual.replace(J.dumps(k) + ':', ':')
    skipped = 0
    for v in sorted(values):
        if v in names or v == method or v in ('{*}', '{trunc}'):
            skipped += 1
            continue
        if v in residual or J.dumps(v)[1:-1] in residual:
            errors.append('C: input value %r appears in the output' % v)
    return errors, len(values), skipped


GQL_SHAPE = re.compile(r'gql:[A-Za-z0-9_!$&():=@\[\]{}|. ?*]+')
GQL_STRING = re.compile(r'"""(?:\\"""|[^"]|"(?!""))*"""|"(?:\\.|[^"\\])*"')
GQL_NUMBER = re.compile(r'(?<![A-Za-z0-9_])-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?')


def gql_check(vec):
    """E: inline literals of the request documents never reach a gql: token."""
    inp = vectorio.load_input(vec['input'])
    out = J.to_py(J.parse(vec['expected']['canonical'].encode('ascii')))
    docs = []  # the GraphQL documents of the request: JSON string members, a raw body, query values
    body = inp.get('req_body') or b''
    try:
        tree = J.to_py(J.parse(body))
        if isinstance(tree, dict):
            docs.extend(v for v in tree.values() if isinstance(v, str))
    except Exception:  # noqa: BLE001
        docs.append(S.utf8_or_none(body) or '')
    for piece in (inp.get('raw_query') or b'').split(b'&'):
        if b'=' in piece:
            docs.append(S.utf8_or_none(S.pct_decode(piece.split(b'=', 1)[1], True)) or '')
    lits = set()
    for d in docs:
        for m in GQL_STRING.finditer(d):
            body = m.group(0).strip('"')
            if len(body) >= 3:
                lits.add(body)
        for m in GQL_NUMBER.finditer(GQL_STRING.sub('""', d)):
            if len(m.group(0)) >= 2:
                lits.add(m.group(0))
    shapes = []

    def walk(node):
        if isinstance(node, dict):
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
        elif isinstance(node, str) and node.startswith('gql:'):
            shapes.append(node)
    walk(out.get('req') or {})
    errors = []
    for sh in shapes:
        if not GQL_SHAPE.fullmatch(sh):
            errors.append('E: %r is outside the shape alphabet' % sh[:80])
        body = sh[4:]
        for lit in lits:
            if lit in body and not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', lit):
                errors.append('E: inline literal %r appears in %r' % (lit, sh[:80]))
            elif re.fullmatch(r'-?[0-9][0-9.eE+-]*', lit) and re.search(r'(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])' % re.escape(lit), body):
                errors.append('E: number literal %r appears in %r' % (lit, sh[:80]))
    return errors, len(lits)


def main():
    vdir = os.path.join(vectorio.ROOT, 'vectors')
    checked = failed = total_values = total_skipped = 0
    gql_vectors = gql_lits = 0
    for name in sorted(os.listdir(vdir)):
        vec = vectorio.load_file(os.path.join(vdir, name))
        if vec['expected'].get('outcome') != 'event':
            continue
        if vec.get('category') == 'graphql':
            gql_vectors += 1
            errors, n = gql_check(vec)
            gql_lits += n
            if errors:
                failed += 1
                print('LEAK %s' % name)
                for e in errors[:10]:
                    print('  ' + e)
        try:
            policy = vectorio.resolve_policy(vec)
        except Exception:  # noqa: BLE001
            continue
        if not is_empty_policy(policy):
            continue
        checked += 1
        errors, n, skipped = check(vec)
        total_values += n
        total_skipped += skipped
        if errors:
            failed += 1
            print('LEAK %s' % name)
            for e in errors[:10]:
                print('  ' + e)
    print('leakcheck: %d empty-policy vectors, %d input values checked (%d skipped as names), %d failures'
          % (checked, total_values, total_skipped, failed))
    print('leakcheck: %d graphql vectors, %d inline literals checked' % (gql_vectors, gql_lits))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
