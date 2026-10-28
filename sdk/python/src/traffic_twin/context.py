"""Exchange context (event.md 1.1, sanitizer.md 12, ARCHITECTURE 3.2).

A ``contextvars.ContextVar`` binds outbound calls to the inbound exchange being served:
same ``trace_id``, inherited sampling decision. W3C ``traceparent`` is read from the
inbound request. If ``opentelemetry-api`` is importable, only the *current span context*
is read; this module never creates or registers a tracer provider, a propagator or a
context, and never injects ``traceparent``.
"""

from __future__ import annotations

import contextvars
import os
import re
import threading
from typing import Optional, Tuple


class ExchangeCtx:
    __slots__ = ("sampled", "trace_id", "trace_known", "span_id")

    def __init__(self, sampled: bool, trace_id: str, trace_known: bool, span_id: str) -> None:
        self.sampled = sampled
        self.trace_id = trace_id
        self.trace_known = trace_known
        self.span_id = span_id


current: "contextvars.ContextVar[Optional[ExchangeCtx]]" = contextvars.ContextVar("traffic_twin_exchange", default=None)

#: Set while a client-level hook (requests adapter, httpx transport, urllib handler) is
#: capturing: lower layers (the optional http.client hook) must not capture the same call.
suppress: "contextvars.ContextVar[bool]" = contextvars.ContextVar("traffic_twin_suppress", default=False)

#: Set in the threads owned by the SDK (exporter, Fleet): their requests are never captured.
internal: "contextvars.ContextVar[bool]" = contextvars.ContextVar("traffic_twin_internal", default=False)


def mark_internal_thread() -> None:
    """Call at the start of a thread owned by the SDK."""
    internal.set(True)


# Ids come from a pooled CSPRNG buffer: one system call per 256 ids instead of one per id.
_pool = bytearray()
_pool_off = 0
_pool_lock = threading.Lock()


def _hex(nbytes: int) -> str:
    global _pool, _pool_off
    while True:
        with _pool_lock:
            if _pool_off + nbytes > len(_pool):
                _pool = bytearray(os.urandom(4096))
                _pool_off = 0
            h = _pool[_pool_off:_pool_off + nbytes].hex()
            _pool_off += nbytes
        if h.strip("0"):
            return h


def new_trace_id() -> str:
    return _hex(16)


def new_span_id() -> str:
    return _hex(8)


_TRACEPARENT = re.compile(r"([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})(-.*)?", re.S)


def parse_traceparent(v: Optional[str]) -> Optional[Tuple[str, str]]:
    """W3C trace context: ``(trace_id, span_id)`` from a traceparent value, or None."""
    if not isinstance(v, str):
        return None
    m = _TRACEPARENT.fullmatch(v.strip(" \t"))
    if not m:
        return None
    if m.group(1) == "ff" or (m.group(1) == "00" and m.group(5) is not None):
        return None
    if not m.group(2).strip("0") or not m.group(3).strip("0"):
        return None
    return m.group(2), m.group(3)


_otel_trace = None
_otel_checked = False


def load_otel_api() -> bool:
    """Imports ``opentelemetry.trace`` if the app has it (importing the API package has no
    side effect; only read-only functions are ever called on it)."""
    global _otel_trace, _otel_checked
    if _otel_checked:
        return _otel_trace is not None
    _otel_checked = True
    try:
        import importlib.util

        if importlib.util.find_spec("opentelemetry") is None:
            return False
        from opentelemetry import trace as t  # type: ignore

        if hasattr(t, "get_current_span"):
            _otel_trace = t
    except Exception:
        _otel_trace = None
    return _otel_trace is not None


def otel_active() -> Optional[Tuple[str, str]]:
    """``(trace_id, span_id)`` of the active OpenTelemetry span, if the app has one."""
    t = _otel_trace
    if t is None:
        return None
    try:
        sc = t.get_current_span().get_span_context()
        if not getattr(sc, "is_valid", False):
            return None
        tid = "%032x" % sc.trace_id
        sid = "%016x" % sc.span_id
        if not tid.strip("0"):
            return None
        return tid, sid
    except Exception:
        return None
