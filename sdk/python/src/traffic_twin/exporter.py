"""OTLP/HTTP JSON exporter (event.md 4): bounded queue, batches of at most 512 events or
4 MiB, retry with exponential backoff and jitter on 429/502/503/504 and network errors
(at most 5 times, ``Retry-After`` honoured), drop-oldest under pressure.

The app never waits: ``enqueue`` only appends to a deque; a daemon thread sends.
"""

from __future__ import annotations

import collections
import email.utils
import gzip
import http.client
import random
import socket
import ssl
import threading
import time
from typing import Any, Callable, Deque, Dict, List, Optional

from ._log import debug
from .context import mark_internal_thread
from .event import QueuedEvent, otlp_body
from .fleet import HttpsClient

RETRYABLE = frozenset([429, 502, 503, 504])
DROP = frozenset([400, 401, 403, 413])


class Counters:
    """Monotonic counters of the heartbeat (fleet-api Heartbeat.counters)."""

    NAMES = ("exchanges_seen", "exchanges_sampled", "events_sent", "events_dropped_queue", "events_rejected",
             "send_errors", "sanitizer_errors")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._v = {n: 0 for n in self.NAMES}

    def inc(self, name: str, n: int = 1) -> None:
        with self._lock:
            self._v[name] += n

    def get(self, name: str) -> int:
        return self._v[name]

    def snapshot(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._v)


class Exporter:
    def __init__(self, url: str, ctx: ssl.SSLContext, service_name: str, source_id: str, counters: Counters,
                 on_error: Callable[[str], None], max_events: int = 10_000, max_bytes: int = 16 << 20,
                 batch_events: int = 512, batch_bytes: int = 4 << 20, flush_s: float = 1.0, max_retries: int = 5,
                 base_backoff_s: float = 1.0, max_backoff_s: float = 30.0) -> None:
        self.url = url
        self.service_name = service_name
        self.source_id = source_id
        self.counters = counters
        self.on_error = on_error
        self.max_events = max_events
        self.max_bytes = max_bytes
        self.batch_events = batch_events
        self.batch_bytes = batch_bytes
        self.flush_s = flush_s
        self.max_retries = max_retries
        self.base_backoff_s = base_backoff_s
        self.max_backoff_s = max_backoff_s
        self._q: Deque[QueuedEvent] = collections.deque()
        self._bytes = 0
        # Kill-switch generation (as internal/sourceclient/exporter.go): ``clear()`` bumps it; a batch built
        # under an older generation is dropped, never sent (also while it waits to be retried).
        self._gen = 0
        self._batch_gen = 0
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._idle = threading.Event()
        self._idle.set()
        self._http = HttpsClient(url, ctx, 15.0)
        self._path = self._http.base_path or "/"
        # The intake URL of the Fleet response is a full URL (".../v1/logs"): it is used as is.
        self._http.base_path = ""
        self._thread: Optional[threading.Thread] = None

    # --- queue --------------------------------------------------------------------

    @property
    def size(self) -> Dict[str, int]:
        return {"events": len(self._q), "bytes": self._bytes}

    def set_target(self, url: str, ctx: ssl.SSLContext) -> None:
        old = self._http
        self.url = url
        self._http = HttpsClient(url, ctx, 15.0)
        self._path = self._http.base_path or "/"
        self._http.base_path = ""
        old.close()

    def start(self) -> None:
        if self._thread is None or not self._thread.is_alive():
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, name="traffic-twin-export", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        t = self._thread
        if t is not None and t is not threading.current_thread():
            t.join(timeout=2.0)
        self._http.shutdown()

    @property
    def generation(self) -> int:
        return self._gen

    def enqueue(self, e: QueuedEvent, gen: Optional[int] = None) -> bool:
        """Queues ``e``. With ``gen`` (the generation read before the event was built) an event built
        under an older generation is dropped: the kill switch arrived meanwhile."""
        dropped = 0
        with self._lock:
            if gen is not None and gen != self._gen:
                self.counters.inc("events_dropped_queue")
                return False
            self._q.append(e)
            self._bytes += len(e.json)
            while len(self._q) > self.max_events or self._bytes > self.max_bytes:
                old = self._q.popleft()
                self._bytes -= len(old.json)
                dropped += 1
            self._idle.clear()
        if dropped:
            self.counters.inc("events_dropped_queue", dropped)
        if len(self._q) >= self.batch_events:
            self._wake.set()
        return True

    def clear(self) -> None:
        """Drops everything queued (kill switch)."""
        with self._lock:
            self._gen += 1
            n = len(self._q)
            self._q.clear()
            self._bytes = 0
        if n:
            self.counters.inc("events_dropped_queue", n)

    def flush(self, timeout: float = 10.0) -> bool:
        """Sends what is queued; True when the queue is empty and nothing is in flight."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self._q and self._idle.is_set():
                return True
            self._wake.set()
            time.sleep(0.01)
        return not self._q and self._idle.is_set()

    # --- sender thread --------------------------------------------------------------

    def _take_batch(self) -> List[QueuedEvent]:
        batch: List[QueuedEvent] = []
        size = 0
        with self._lock:
            self._batch_gen = self._gen
            while self._q and len(batch) < self.batch_events:
                e = self._q[0]
                if batch and size + len(e.json) > self.batch_bytes:
                    break
                self._q.popleft()
                self._bytes -= len(e.json)
                batch.append(e)
                size += len(e.json)
        return batch

    def _run(self) -> None:
        mark_internal_thread()
        while not self._stop.is_set():
            self._wake.wait(self.flush_s)
            self._wake.clear()
            while not self._stop.is_set():
                batch = self._take_batch()
                if not batch:
                    self._idle.set()
                    break
                gen = self._batch_gen
                try:
                    self._send(batch, gen)
                except Exception:  # never let the sender thread die
                    self.counters.inc("send_errors")
                    self.counters.inc("events_dropped_queue", len(batch))
                    self.on_error("export_internal")
                if not self._q:
                    self._idle.set()

    def _stale(self, batch: List[QueuedEvent], gen: int) -> bool:
        if gen == self._gen:
            return False
        self.counters.inc("events_dropped_queue", len(batch))
        return True

    def _send(self, batch: List[QueuedEvent], gen: Optional[int] = None) -> bool:
        if gen is None:
            gen = self._gen
        if self._stale(batch, gen):
            return False
        body = otlp_body(batch, self.service_name, self.source_id, int(time.time() * 1000))
        headers = {"Content-Type": "application/json"}
        if len(body) > 1024:
            body = gzip.compress(body, 3, mtime=0)
            headers["Content-Encoding"] = "gzip"
        attempt = 0
        while True:
            if self._stale(batch, gen):  # the kill switch arrived: never (re)send
                return False
            res = None
            net_err = False
            try:
                res = self._http.request("POST", self._path, headers, body, max_response=64 << 10)
            except (OSError, http.client.HTTPException):
                net_err = True
            if res is not None and 200 <= res.status < 300:
                rejected = 0
                j = res.json()
                if isinstance(j, dict) and isinstance(j.get("partialSuccess"), dict):
                    try:
                        rejected = int(j["partialSuccess"].get("rejectedLogRecords") or 0)
                    except (TypeError, ValueError):
                        rejected = 0
                rejected = min(max(0, rejected), len(batch))
                self.counters.inc("events_sent", len(batch) - rejected)
                if rejected:
                    self.counters.inc("events_rejected", rejected)
                    self.on_error("intake_partial_reject")
                return True
            retryable = net_err or (res is not None and res.status in RETRYABLE)
            if not retryable or attempt >= self.max_retries or self._stop.is_set():
                if res is not None and res.status in DROP:
                    self.counters.inc("events_rejected", len(batch))
                else:
                    self.counters.inc("events_dropped_queue", len(batch))
                self.counters.inc("send_errors")
                self.on_error("intake_http_%d" % res.status if res is not None else "intake_network")
                debug("export_drop", res.status if res is not None else "network")
                return False
            self.counters.inc("send_errors")
            delay = min(self.max_backoff_s, self.base_backoff_s * 2 ** attempt)
            delay = delay / 2 + random.random() * (delay / 2)
            ra = res.headers.get("retry-after") if res is not None else None
            if ra:
                secs = _retry_after_seconds(ra)
                if secs is not None and secs > 0:
                    delay = min(max(delay, secs), 300.0)
            attempt += 1
            if self._stop.wait(delay):
                self.counters.inc("events_dropped_queue", len(batch))
                return False


def _retry_after_seconds(v: str) -> Optional[float]:
    v = v.strip()
    if v.isdigit():
        return float(v)
    try:
        dt = email.utils.parsedate_to_datetime(v)
        return dt.timestamp() - time.time()
    except (TypeError, ValueError):
        return None
