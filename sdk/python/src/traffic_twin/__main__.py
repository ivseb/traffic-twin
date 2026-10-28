"""``python -m traffic_twin run -- <command ...>`` starts a program with the agent loaded
(through ``sitecustomize``) without touching its code; ``python -m traffic_twin vectors``
runs the conformance vectors; ``python -m traffic_twin status`` prints the version."""

import os
import sys


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help", "help"):
        sys.stdout.write(__doc__ + "\n")
        return 0
    cmd = args.pop(0)
    if cmd == "run":
        if args and args[0] == "--":
            args.pop(0)
        if not args:
            sys.stderr.write("usage: python -m traffic_twin run -- <command ...>\n")
            return 2
        boot = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bootstrap")
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(p for p in (boot, env.get("PYTHONPATH", "")) if p)
        os.execvpe(args[0], args, env)
        return 127  # pragma: no cover
    if cmd == "vectors":
        from .conformance import main as vmain

        return vmain(args)
    if cmd == "version":
        from ._version import SDK_VERSION

        print(SDK_VERSION)
        return 0
    sys.stderr.write("unknown command: %s\n" % cmd)
    return 2


if __name__ == "__main__":
    sys.exit(main())
