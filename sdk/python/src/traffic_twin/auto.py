"""Importing this module starts the agent from the environment (``TT_*`` variables).

Used by the ``sitecustomize`` bootstrap (``python -m traffic_twin run ...``) and by apps
that prefer a one-line start: ``import traffic_twin.auto``. Never raises.

This is the zero-code start, so besides the agent it arms the automatic capture
(``traffic_twin.autocapture``): web apps created by Flask, FastAPI/Starlette, Django and
the ones uvicorn and gunicorn load are wrapped for inbound capture, ``requests`` and
``httpx`` get the outbound hook when imported (``TT_OUTBOUND=off`` turns the outbound
side off, a list such as ``TT_OUTBOUND=httpx`` chooses it), and a warning plus the problem
``inbound_not_captured`` say it when no web app could be wrapped.
"""

import os

try:
    from . import autocapture
    from .runtime import start

    _out = os.environ.get("TT_OUTBOUND", "").strip().lower()
    _default = _out in ("", "auto")
    start(outbound="urllib" if _default else None)
    autocapture.enable(outbound_auto=_default)
    autocapture.start_monitor()
except Exception:  # an SDK problem must never stop the application
    pass
