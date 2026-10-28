#!/usr/bin/env python3
"""Self-check of the conformance suite with the reference implementation.

Usage: python3 conformance/ref/run.py [vector-id-prefix ...]

For every conformance/vectors/*.json it:
  1. validates the file against conformance/schema/vector.v1.schema.json;
  2. executes it with the reference implementation and compares the result with
     `expected` (byte-for-byte on `canonical`);
  3. checks that `canonical` is in tt-cjson form (parse + re-serialize is identical);
  4. wraps the output into a full tt.http.exchange/v1 event and validates it against
     schemas/event.v1.schema.json;
  5. checks that every ambiguity id is defined in conformance/AMBIGUITIES.md.

This file is also a template for runners in other languages: steps 1 and 3-5 are
optional for them, step 2 is the conformance test.
"""

import os
import re
import sys

sys.setrecursionlimit(20000)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import minischema  # noqa: E402
import ttjson as J  # noqa: E402
import vectorio  # noqa: E402

ROOT = vectorio.ROOT


def wrap_event(vec, out):
    ev = dict(out)
    ev['schema'] = 'tt.http.exchange/v1'
    ev['policy'] = {'id': 'p-conformance', 'version': J.Num('1'), 'hash': 'sha256:' + '0' * 64}
    ev['source'] = {'kind': 'sdk-go', 'version': '0.0.0', 'id': 'src-conformance'}
    ev['ts'] = '2026-10-23T10:00:00.000Z'
    ev['latency_ms'] = J.Num('1')
    inp = vec['input']
    ev['dir'] = inp['dir']
    if 'net_error' in inp:
        ev['net_error'] = inp['net_error']
    else:
        ev['status'] = inp['status']
    if 'trace_id' in inp:
        ev['trace_id'] = inp['trace_id']
    return ev


def main(prefixes):
    vschema = vectorio.load_file(os.path.join(ROOT, 'schema', 'vector.v1.schema.json'))
    eschema = vectorio.load_file(os.path.join(ROOT, '..', 'schemas', 'event.v1.schema.json'))
    vval = minischema.Validator(vschema)
    eval_ = minischema.Validator(eschema)
    with open(os.path.join(ROOT, 'AMBIGUITIES.md'), encoding='utf-8') as fh:
        defined = set()
        for heading in re.findall(r'^### (.*)$', fh.read(), re.M):
            defined.update(re.findall(r'A-[A-Z0-9]+(?:-[A-Z0-9]+)*', heading))
    failures = 0
    count = 0
    used = set()
    for name in sorted(os.listdir(os.path.join(ROOT, 'vectors'))):
        if not name.endswith('.json') or (prefixes and not any(name.startswith(p) for p in prefixes)):
            continue
        count += 1
        problems = []
        vec = vectorio.load_file(os.path.join(ROOT, 'vectors', name))
        problems += vval.errors(vec)
        if vec.get('id') + '.json' != name:
            problems.append('file name does not match id')
        for a in vec.get('ambiguities', []):
            used.add(a)
            if a not in defined:
                problems.append('ambiguity %s not defined in AMBIGUITIES.md' % a)
        try:
            got = vectorio.execute(vec)
        except Exception as e:  # noqa: BLE001
            got = {'error': repr(e)}
        exp = vec['expected']
        if got != exp:
            problems.append('result differs:\n    expected %s\n    got      %s' % (exp, got))
        if exp.get('outcome') == 'event':
            c = exp['canonical']
            out = J.to_py(J.parse(c.encode('ascii')))
            if J.dumps(out) != c:
                problems.append('canonical is not in tt-cjson form')
            problems += ['event schema: ' + e for e in eval_.errors(wrap_event(vec, out))]
        if problems:
            failures += 1
            print('FAIL %s' % name)
            for p in problems[:10]:
                print('  ' + p)
    unused = defined - used
    print('%d vectors, %d failures; %d ambiguities defined, %d referenced by vectors'
          % (count, failures, len(defined), len(defined & used)))
    if unused and not prefixes:
        print('ambiguities without vectors (documented only): ' + ', '.join(sorted(unused)))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
