"""Runs the conformance vectors: ``python -m traffic_twin.conformance [dir] [id-prefix ...]``.

The default directory is ``conformance/`` of the repository (found by walking up from
this file or from the current directory), or ``TT_CONFORMANCE_DIR``. Exit status 0 only
if every selected vector passes; a vector that cannot be run is reported as
"not applicable", never as passed.
"""

from __future__ import annotations

import glob
import os
import sys
from typing import List, Optional

from .vectors import expected_matches, parse_vector, run_vector


def find_conformance_dir() -> Optional[str]:
    env = os.environ.get("TT_CONFORMANCE_DIR")
    if env and os.path.isdir(os.path.join(env, "vectors")):
        return env
    for start in (os.path.dirname(os.path.abspath(__file__)), os.getcwd()):
        d = start
        for _ in range(10):
            cand = os.path.join(d, "conformance")
            if os.path.isdir(os.path.join(cand, "vectors")):
                return cand
            parent = os.path.dirname(d)
            if parent == d:
                break
            d = parent
    return None


def run_all(root: str, prefixes: Optional[List[str]] = None, out=sys.stdout) -> dict:
    """Returns ``{"passed": n, "failed": [...], "not_applicable": [...]}``."""
    files = sorted(glob.glob(os.path.join(root, "vectors", "*.json")))
    passed = 0
    failed: List[str] = []
    na: List[str] = []
    for path in files:
        vid = os.path.basename(path)[:-5]
        if prefixes and not any(vid.startswith(p) for p in prefixes):
            continue
        with open(path, "rb") as f:
            vec = parse_vector(f.read())
        try:
            res = run_vector(vec, root)
        except Exception as e:  # an internal error is a failure of the vector
            failed.append(vid)
            out.write("FAIL %s: exception %s: %s\n" % (vid, type(e).__name__, e))
            continue
        if expected_matches(vec, res):
            passed += 1
        else:
            failed.append(vid)
            exp = vec["expected"]
            out.write("FAIL %s\n  expected: %s\n  actual:   %s\n" % (vid, exp.get("canonical", exp), res.get("canonical", res)))
    return {"passed": passed, "failed": failed, "not_applicable": na}


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    root = None
    if args and os.path.isdir(os.path.join(args[0], "vectors")):
        root = args.pop(0)
    root = root or find_conformance_dir()
    if root is None:
        sys.stderr.write("conformance directory not found (pass it or set TT_CONFORMANCE_DIR)\n")
        return 2
    r = run_all(root, args or None)
    total = r["passed"] + len(r["failed"]) + len(r["not_applicable"])
    print("vectors: %d passed, %d failed, %d not applicable (of %d)" % (r["passed"], len(r["failed"]), len(r["not_applicable"]), total))
    return 0 if not r["failed"] and total > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
