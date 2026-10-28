"""Debug output: status and error codes only, never payload values (threat model M14)."""

from __future__ import annotations

import sys

_debug = False


def set_debug(on: bool) -> None:
    global _debug
    _debug = bool(on)


def notice(message: str) -> None:
    """A message the developer must see even without ``TT_DEBUG`` (a configuration problem,
    never a payload value)."""
    try:
        sys.stderr.write("[traffic-twin] " + message + "\n")
    except Exception:
        pass


def debug(*parts: object) -> None:
    if _debug:
        try:
            sys.stderr.write("[traffic-twin] " + " ".join(str(p) for p in parts) + "\n")
        except Exception:
            pass


def notice(message: str) -> None:
    """A message the developer must see even without ``TT_DEBUG`` (a configuration problem,
    never a payload value). Said on stderr, once per call site by the callers."""
    try:
        sys.stderr.write("[traffic-twin] " + message + "\n")
    except Exception:
        pass
