"""Auto start through ``sitecustomize`` (the same idea as OpenTelemetry's auto-instrumentation).

``python -m traffic_twin run -- <command>`` puts this directory first on ``PYTHONPATH``.
Python imports ``sitecustomize`` at start-up: this module first runs any ``sitecustomize``
the application already had, then starts the agent from the ``TT_*`` environment.
"""

import importlib.util
import os
import sys

_here = os.path.dirname(os.path.abspath(__file__))

# 1. Chain to the next sitecustomize on the path (the application's own, if any).
try:
    for _p in sys.path:
        if os.path.abspath(_p or ".") == _here:
            continue
        _cand = os.path.join(_p or ".", "sitecustomize.py")
        if os.path.isfile(_cand):
            _spec = importlib.util.spec_from_file_location("_tt_chained_sitecustomize", _cand)
            if _spec and _spec.loader:
                _mod = importlib.util.module_from_spec(_spec)
                _spec.loader.exec_module(_mod)
            break
except Exception:
    pass

# 2. Start traffic-twin; pending work is done by background threads.
try:
    import traffic_twin.auto  # noqa: F401
except Exception:
    pass
