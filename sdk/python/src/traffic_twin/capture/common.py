"""Shared pieces of the capture hooks."""

from __future__ import annotations

import errno
import re
import socket
import ssl
from typing import Any, Callable, List, Optional, Tuple

from ..sanitizer import Decision, Exchange, Sanitizer


class BodyTap:
    """Body tee (sanitizer.md 9.0): keeps a copy of the first ``limit`` bytes and counts the
    rest. Never alters the chunks it sees; copies only what it keeps."""

    __slots__ = ("limit", "chunks", "kept", "total", "ended")

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.chunks: List[bytes] = []
        self.kept = 0
        self.total = 0
        self.ended = False

    def add(self, chunk: Any) -> None:
        """Records a chunk (bytes-like or str). Never raises."""
        try:
            if not chunk:
                return
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8")
            n = len(chunk)
            self.total += n
            room = self.limit - self.kept
            if room > 0:
                take = bytes(chunk[:room]) if not isinstance(chunk, bytes) or n > room else chunk
                self.chunks.append(take)
                self.kept += len(take)
        except Exception:
            pass

    def bytes(self) -> bytes:
        if not self.chunks:
            return b""
        if len(self.chunks) > 1:
            self.chunks = [b"".join(self.chunks)]
        return self.chunks[0]


class RawExchange:
    """A finished exchange, converted to sanitizer input lazily (off the request path)."""

    __slots__ = (
        "sanitizer", "decision", "build", "dir", "ts_ms", "latency_ms", "trace_id", "span_id", "parent_span_id",
        "status", "net_error", "held",
    )

    def __init__(self, sanitizer: Sanitizer, decision: Decision, build: Callable[[], Exchange], dir: str,
                 ts_ms: int, latency_ms: int, trace_id: Optional[str], span_id: Optional[str],
                 parent_span_id: Optional[str], status: Optional[int], net_error: Optional[str], held: int) -> None:
        self.sanitizer = sanitizer
        self.decision = decision
        self.build = build
        self.dir = dir
        self.ts_ms = ts_ms
        self.latency_ms = latency_ms
        self.trace_id = trace_id
        self.span_id = span_id
        self.parent_span_id = parent_span_id
        self.status = status
        self.net_error = net_error
        self.held = held


def latin1(s: Any) -> bytes:
    if isinstance(s, (bytes, bytearray, memoryview)):
        return bytes(s)
    return str(s).encode("latin-1", "replace")


def name_str(n: Any) -> str:
    return n.decode("latin-1") if isinstance(n, (bytes, bytearray)) else str(n)


_ABS_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^/?#]*")


def split_target(target: str) -> Tuple[bytes, Optional[bytes]]:
    """Splits a request target into raw path and raw query bytes (query None without ``?``)."""
    t = target
    m = _ABS_URL.match(t)
    if m:
        t = t[m.end():] or "/"
    h = t.find("#")
    if h >= 0:
        t = t[:h]
    q = t.find("?")
    if q < 0:
        return t.encode("latin-1", "replace"), None
    return t[:q].encode("latin-1", "replace"), t[q + 1:].encode("latin-1", "replace")


def net_error_of(err: BaseException) -> str:
    """Maps a network exception (following its ``__cause__`` / ``__context__`` chain) to the
    event enum of event.md: timeout, reset, refused, dns, tls or other."""
    e: Optional[BaseException] = err
    for _ in range(6):
        if e is None:
            break
        name = type(e).__name__
        if isinstance(e, (socket.timeout, TimeoutError)) or name in (
                "ConnectTimeout", "ReadTimeout", "WriteTimeout", "PoolTimeout", "Timeout", "TimeoutException"):
            return "timeout"
        if isinstance(e, ssl.SSLError) or name in ("SSLError", "SSLCertVerificationError"):
            return "tls"
        if isinstance(e, socket.gaierror):
            return "dns"
        if isinstance(e, ConnectionRefusedError):
            return "refused"
        if (isinstance(e, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError))
                or (isinstance(e, OSError) and e.errno in (errno.ECONNRESET, errno.EPIPE, errno.ECONNABORTED))
                or name in ("RemoteDisconnected", "RemoteProtocolError", "ProtocolError", "IncompleteRead",
                            "ReadError", "WriteError")):
            return "reset"
        e = e.__cause__ or e.__context__
    return "other"


def with_tt_s(existing: Optional[str], sampled: bool) -> str:
    """Puts ``tt.s`` in front of a baggage header value without touching the other members.

    The reader of a baggage takes the first valid ``tt.s`` member (sanitizer.md 12), so a ``tt.s``
    that a client forged and the application forwarded cannot override the decision made here."""
    member = "tt.s=" + ("1" if sampled else "0")
    if not existing or not existing.strip():
        return member
    return member + "," + existing
