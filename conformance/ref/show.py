#!/usr/bin/env python3
"""Print the expected result of vectors (review helper).

Usage: python3 conformance/ref/show.py [id-prefix ...]
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import vectorio  # noqa: E402


def main(prefixes):
    vdir = os.path.join(vectorio.ROOT, 'vectors')
    for name in sorted(os.listdir(vdir)):
        if prefixes and not any(name.startswith(p) for p in prefixes):
            continue
        e = vectorio.load_file(os.path.join(vdir, name))['expected']
        text = e.get('canonical') or e
        if isinstance(text, str) and len(text) > 1500:
            text = text[:700] + ' ... ' + text[-700:]
        print('%s => %s' % (name[:-5], text))


if __name__ == '__main__':
    main(sys.argv[1:])
