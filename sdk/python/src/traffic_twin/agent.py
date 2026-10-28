"""The agent: Fleet lifecycle (policy.md 4, fleet-api), capture gate, asynchronous
sanitization and export. Fail-closed everywhere: any doubt means "do not capture".

Threads (all daemon, all marked internal so their own HTTP calls are never captured):
``traffic-twin-sanitize`` (turns finished exchanges into events), ``traffic-twin-export``
(sends batches) and ``traffic-twin-fleet`` (enrollment, heartbeat, policy poll). The
application threads only append a finished exchange to a bounded deque.
"""

from __future__ import annotations

import collections
import os
import platform
import re
import socket
import ssl
import threading
import time
from typing import Any, Deque, Dict, FrozenSet, List, Optional, Tuple

from . import ed25519
from ._log import debug, set_debug
from ._version import SDK_VERSION, SOURCE_KIND
from .capture.common import RawExchange
from .context import load_otel_api, mark_internal_thread
from .event import QueuedEvent, build_event
from .exporter import Counters, Exporter
from .fleet import FleetClient, FleetError, client_context, enroll
from .jsonlex import JsonError, parse_plain
from .policy import (
    KeyRing, Policy, Refused, UNSAFE_DETAIL, b64url_decode_strict, check_acceptance, ed25519_public_key, parse_key_ring, select_key,
    verify_envelope,
)
from .sanitizer import Sanitizer, normalize_url_base
from .store import StateStore, default_state_dir
from .textutil import ascii_lower

PENDING_MAX = 2000
PENDING_MAX_BYTES = 64 << 20
_SVC_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}")
_KID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")


class AgentOptions:
    """Settings of the agent; every field has an environment variable (see the README)."""

    def __init__(self, enroll_url: Optional[str] = None, enroll_token: Optional[str] = None,
                 hmac_key: Optional[str] = None, hmac_key_file: Optional[str] = None,
                 service_name: Optional[str] = None, state_dir: Optional[str] = None,
                 instance: Optional[str] = None, debug: bool = False, ca_file: Optional[str] = None,
                 heartbeat_interval_s: Optional[float] = None, policy_poll_interval_s: Optional[float] = None,
                 export_flush_s: Optional[float] = None, outbound: Optional[str] = None,
                 disabled: bool = False) -> None:
        self.enroll_url = enroll_url
        self.enroll_token = enroll_token
        self.hmac_key = hmac_key
        self.hmac_key_file = hmac_key_file
        self.service_name = service_name
        self.state_dir = state_dir
        self.instance = instance
        self.debug = debug
        self.ca_file = ca_file
        self.heartbeat_interval_s = heartbeat_interval_s
        self.policy_poll_interval_s = policy_poll_interval_s
        self.export_flush_s = export_flush_s
        self.outbound = outbound
        self.disabled = disabled


def service_name_from_env(env: Dict[str, str]) -> Optional[str]:
    raw = env.get("TT_SERVICE_NAME") or env.get("OTEL_SERVICE_NAME")
    if not raw:
        return None
    s = re.sub(r"[^a-z0-9._-]", "-", ascii_lower(raw))
    s = re.sub(r"^[^a-z0-9]+", "", s)[:63]
    return s if _SVC_RE.fullmatch(s) else None


def _ms_env(v: Optional[str]) -> Optional[float]:
    if not v or not re.fullmatch(r"[0-9]{1,9}", v):
        return None
    return max(100, int(v)) / 1000.0


def options_from_env(env: Optional[Dict[str, str]] = None) -> AgentOptions:
    e = dict(os.environ) if env is None else env
    return AgentOptions(
        enroll_url=e.get("TT_ENROLL_URL") or None,
        enroll_token=e.get("TT_ENROLL_TOKEN") or None,
        hmac_key=e.get("TT_HMAC_KEY") or None,
        hmac_key_file=e.get("TT_HMAC_KEY_FILE") or None,
        service_name=service_name_from_env(e),
        state_dir=e.get("TT_STATE_DIR") or None,
        instance=e.get("TT_INSTANCE") or None,
        debug=bool(re.fullmatch(r"(?i)1|true|yes|debug", e.get("TT_DEBUG", ""))),
        ca_file=e.get("TT_ENROLL_CA_FILE") or None,
        heartbeat_interval_s=_ms_env(e.get("TT_HEARTBEAT_INTERVAL_MS")),
        policy_poll_interval_s=_ms_env(e.get("TT_POLICY_POLL_INTERVAL_MS")),
        export_flush_s=_ms_env(e.get("TT_EXPORT_FLUSH_MS")),
        outbound=e.get("TT_OUTBOUND") or None,
        disabled=bool(re.fullmatch(r"(?i)1|true|yes", e.get("TT_DISABLED", ""))),
    )


class Agent:
    def __init__(self, opts: AgentOptions) -> None:
        self.opts = opts
        if opts.debug:
            set_debug(True)
        self.counters = Counters()
        self.state = "starting"

        self._san: Optional[Sanitizer] = None
        self._policy: Optional[Policy] = None
        self._policy_kid = ""
        self._rejected: Optional[str] = None
        # A heartbeat said a newer policy is current (a normal policy change): capture pauses until
        # it is fetched, and only a failed fetch is an error (policy.md 4).
        self._switching = False
        self._ring: Optional[KeyRing] = None
        self._heartbeat_ok = False
        self._last_contact = 0.0
        self._persisted: Dict[str, Any] = {}
        self._override_bp: Optional[int] = None
        self._decision_names: FrozenSet[str] = frozenset(["cookie", "baggage", "traceparent"])
        self._decision_bytes: FrozenSet[bytes] = frozenset([b"cookie", b"baggage", b"traceparent"])
        self._overhead: List[int] = []
        self._overhead_i = 0
        self._last_errors: Deque[Dict[str, str]] = collections.deque(maxlen=20)

        self._pending: Deque[RawExchange] = collections.deque()
        self._pending_bytes = 0
        self._plock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._threads: List[threading.Thread] = []
        self._started = False
        self._hooks_inherited = False  # set in a child of fork: the patches of the parent are still in place

        self._store: Optional[StateStore] = None
        self._enrollment: Optional[Dict[str, Any]] = None
        self._fleet: Optional[FleetClient] = None
        self._exporter: Optional[Exporter] = None
        self._etag: Optional[str] = None
        self._gen = 0  # kill-switch generation of the sanitize queue (bumped by _drop_queues)
        self._taken_gen = 0
        self._uninstall: List[Any] = []

    # --- CaptureHost (hot path) -----------------------------------------------------

    def active(self) -> Optional[Sanitizer]:
        return self._san

    def service_name(self) -> str:
        e = self._enrollment
        return e["service_name"] if e else ""

    def decision_headers(self) -> FrozenSet[str]:
        return self._decision_names

    def decision_headers_bytes(self) -> FrozenSet[bytes]:
        return self._decision_bytes

    def may_propagate(self, url_base: str) -> bool:
        p = self._policy
        if p is None or not p.propagate_to:
            return False
        u = normalize_url_base(url_base)
        if u.invalid or u.ip6 is not None:  # propagate_to and bases hold names, never IPv6 literals (v1.5)
            return False
        host = re.sub(r":[0-9]+$", "", u.hostport)
        # D-M8: never toward a host that matches a policy base (external service).
        if u.hostport in p.base_hosts or host in p.base_hosts:
            return False
        return u.hostport in p.propagate_to or host in p.propagate_to

    def note_seen(self) -> None:
        self.counters.inc("exchanges_seen")

    def note_sampled(self) -> None:
        self.counters.inc("exchanges_sampled")

    def note_overhead(self, ns: int) -> None:
        buf = self._overhead
        if len(buf) < 1024:
            buf.append(ns)
        else:
            buf[self._overhead_i % 1024] = ns
        self._overhead_i += 1

    def note_error(self, code: str) -> None:
        self._last_errors.append({"code": code[:64], "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        debug("error", code)

    def submit(self, raw: RawExchange) -> None:
        with self._plock:
            if self._san is None or len(self._pending) >= PENDING_MAX or self._pending_bytes + raw.held > PENDING_MAX_BYTES:
                full = True
            else:
                full = False
                self._pending.append(raw)
                self._pending_bytes += raw.held
        if full:
            self.counters.inc("events_dropped_queue")
            return
        self._wake.set()

    # --- asynchronous sanitization ----------------------------------------------------

    def _take(self) -> Optional[RawExchange]:
        with self._plock:
            if not self._pending:
                return None
            raw = self._pending.popleft()
            self._pending_bytes -= raw.held
            self._taken_gen = self._gen  # the worker is the only taker
            return raw

    def _gate_open(self, gen: int) -> bool:
        """The capture gate, re-checked right before the enqueue: no kill/revocation arrived since the exchange
        was taken (generation) and capture is still on."""
        return (gen == self._gen and self._san is not None and not self._persisted.get("kill")
                and not self._persisted.get("revoked"))

    def _worker(self) -> None:
        mark_internal_thread()
        while not self._stop.is_set():
            self._wake.wait(0.5)
            self._wake.clear()
            while not self._stop.is_set():
                raw = self._take()
                if raw is None:
                    break
                self._process(raw)
                time.sleep(0)  # let application threads run between events

    def _process(self, raw: RawExchange) -> None:
        exporter, enrollment = self._exporter, self._enrollment
        if exporter is None or enrollment is None:
            return
        gen, egen = self._taken_gen, exporter.generation
        try:
            r = raw.sanitizer.run(raw.build(), time.time(), raw.decision)
            if r.outcome == "not_sampled":
                return
            if r.outcome == "too_large":
                self.counters.inc("sanitizer_errors")
                self.note_error("event_too_large")
                return
            p = raw.sanitizer.policy
            js = build_event(r.parts, p.policy_id, p.version, p.hash, enrollment["source_id"], raw.dir, raw.ts_ms,
                             raw.latency_ms, raw.status, raw.net_error, raw.trace_id, raw.span_id, raw.parent_span_id)
            if js is None:
                self.counters.inc("sanitizer_errors")
                self.note_error("event_invalid_or_too_large")
                return
            if not self._gate_open(gen):  # the kill switch arrived while this exchange was being sanitized
                self.counters.inc("events_dropped_queue")
                return
            exporter.enqueue(QueuedEvent(js, raw.ts_ms, raw.trace_id, raw.span_id, p.hash), egen)
        except Exception:
            # An internal error never produces an event (sanitizer.md, introduction).
            self.counters.inc("sanitizer_errors")
            self.note_error("sanitizer_error")

    # --- lifecycle ----------------------------------------------------------------------

    def start(self, wait: float = 0.0) -> "Agent":
        """Starts the threads and installs the opt-in outbound hooks. Never raises. With
        ``wait`` it blocks up to that many seconds for the first Fleet cycle (tests)."""
        if self.opts.disabled:
            self._ready.set()
            return self
        if not self._started:
            self._started = True
            try:
                load_otel_api()
                if not self._hooks_inherited:
                    from .capture import outbound as _out

                    self._uninstall.extend(_out.install_from_option(self._hook_host(), self.opts.outbound))
            except Exception:
                self.note_error("start_hooks")
            for name, target in (("sanitize", self._worker), ("fleet", self._control)):
                t = threading.Thread(target=target, name="traffic-twin-" + name, daemon=True)
                t.start()
                self._threads.append(t)
        if wait > 0:
            self._ready.wait(wait)
        return self

    def install_outbound_hook(self, name: str) -> None:
        """Installs one outbound hook (``requests``, ``httpx``, ...) after the agent started: the
        zero-code start calls it when the client library is imported. Never raises."""
        try:
            from .capture import outbound as _out

            self._uninstall.extend(_out.install_from_option(self, name))
        except Exception:
            self.note_error("start_hooks")

    def install_outbound_hook(self, name: str) -> None:
        """Installs one outbound hook (``requests``, ``httpx``, ...) after the agent started: the
        zero-code start calls it when the client library is imported. Never raises."""
        try:
            from .capture import outbound as _out

            self._uninstall.extend(_out.install_from_option(self._hook_host(), name))
        except Exception:
            self.note_error("start_hooks")

    def _hook_host(self) -> Any:
        """What the outbound hooks report to: the process-wide agent looked up at call time (so a
        child of ``fork`` keeps working with its own agent), or this agent when it is not the
        process-wide one (tests, embedded use)."""
        from .capture import outbound as _out
        from .runtime import get_agent

        return _out.CURRENT if get_agent() is self else self

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        for u in self._uninstall:
            try:
                u()
            except Exception:
                pass
        self._uninstall = []
        self._san = None
        if self._exporter is not None:
            self._exporter.stop()
        if self._fleet is not None:
            self._fleet.shutdown()
        for t in self._threads:
            if t is not threading.current_thread():
                t.join(timeout=2.0)
        if self._store is not None:
            self._store.cleanup_ephemeral()

    def flush(self, timeout: float = 10.0) -> bool:
        """Sanitizes what is pending and sends everything queued (tests, graceful shutdown)."""
        deadline = time.monotonic() + timeout
        while True:
            raw = self._take()
            if raw is None:
                break
            self._process(raw)
        ex = self._exporter
        return ex.flush(max(0.1, deadline - time.monotonic())) if ex is not None else True

    def status(self) -> Dict[str, Any]:
        ex = self._exporter
        return {"state": self.state, "counters": self.counters.snapshot(),
                "queue": ex.size if ex is not None else {"events": 0, "bytes": 0}}

    # --- control thread ------------------------------------------------------------------

    def _control(self) -> None:
        mark_internal_thread()
        try:
            self._bootstrap()
        except Exception as e:
            self.note_error(e.code if isinstance(e, FleetError) else "start_failed")
        self._recompute()
        self._ready.set()
        if self._fleet is None or self._enrollment is None:
            return
        e = self._enrollment
        hb = self.opts.heartbeat_interval_s or max(5, e["heartbeat_interval_s"])
        pp = self.opts.policy_poll_interval_s or max(5, e["policy_poll_interval_s"])
        next_hb = time.monotonic() + hb
        next_pp = time.monotonic() + pp
        while not self._stop.is_set():
            now = time.monotonic()
            if self._stop.wait(max(0.05, min(next_hb, next_pp) - now)):
                break
            now = time.monotonic()
            try:
                if now >= next_hb:
                    self._heartbeat()
                    next_hb = time.monotonic() + hb
                if now >= next_pp:
                    self._poll_policy()
                    next_pp = time.monotonic() + pp
            except Exception:
                self.note_error("control_loop")

    def _bootstrap(self) -> None:
        o = self.opts
        if not o.enroll_url or not o.service_name:
            self.note_error("not_configured")
            return
        self._store = StateStore(o.state_dir or default_state_dir(o.enroll_url, o.service_name), self.note_error)
        self._store.ensure()
        self._persisted = self._store.read_json("state.json") or {}
        self._load_keys()
        if not self._load_saved_enrollment():
            if not o.enroll_token:
                self.note_error("enroll_token_missing")
                return
            with self._store.lock():
                if not self._load_saved_enrollment():  # another process may have enrolled meanwhile
                    self._enroll_with_retry()
        if self._enrollment is None:
            return
        self._connect()
        cached = self._store.read_text("policy.envelope.json")
        if cached is not None:
            try:
                self._try_accept(parse_plain(cached.encode("utf-8"), True), True, cached)
            except (JsonError, ValueError):
                self.note_error("policy_cache_invalid")
        self._heartbeat()
        self._poll_policy()

    def _load_saved_enrollment(self) -> bool:
        st = self._store
        saved = st.read_json("enrollment.json")
        key = st.read_text("client.key")
        if isinstance(saved, dict) and key and saved.get("enroll_url") == self.opts.enroll_url:
            self._enrollment = saved
            return True
        return False

    def _enroll_with_retry(self) -> None:
        o = self.opts
        delay = 2.0
        for _attempt in range(8):
            if self._stop.is_set():
                return
            try:
                source = {
                    "kind": SOURCE_KIND, "version": SDK_VERSION, "service_name": o.service_name,
                    "instance": (o.instance or socket.gethostname())[:128],
                    "runtime": {"lang": "python", "lang_version": platform.python_version()[:64],
                                "os": platform.system().lower()[:32], "arch": platform.machine()[:32]},
                }
                if self._ring is not None:
                    source["hmac_kids"] = self._ring.order[:8]
                rec, key_pem = enroll(o.enroll_url, o.enroll_token, source, ca_file=o.ca_file)
                self._store.write_text("client.key", key_pem)
                self._store.write_json("enrollment.json", rec)
                self._enrollment = rec
                return
            except FleetError as e:
                self.note_error(e.code)
                # Token or identity errors will not fix themselves.
                if (e.status is not None and e.status < 500) or re.search(r"pin|root|token|chain|bad_|no_key|not_https", e.code):
                    return
            except Exception:
                self.note_error("enroll_failed")
            if self._stop.wait(delay):
                return
            delay = min(delay * 2, 300.0)

    def _connect(self) -> None:
        e = self._enrollment
        st = self._store
        st.write_text("client.crt", e["client_cert"])
        ctx = client_context(e["ca_chain"], st.path("client.crt"), st.path("client.key"))
        if st.ephemeral:
            pass  # key lives only in the private temporary directory, removed at stop()
        if self._fleet is not None:
            self._fleet.close()
        self._fleet = FleetClient(e["fleet_url"], ctx)
        if self._exporter is not None:
            self._exporter.set_target(e["intake_url"], ctx)
        else:
            self._exporter = Exporter(e["intake_url"], ctx, e["service_name"], e["source_id"], self.counters,
                                      self.note_error, flush_s=self.opts.export_flush_s or 1.0)
            self._exporter.start()

    # --- keys ------------------------------------------------------------------------------

    def _load_keys(self) -> None:
        text = self.opts.hmac_key
        if text is None and self.opts.hmac_key_file:
            try:
                with open(self.opts.hmac_key_file, "r", encoding="utf-8") as f:
                    text = f.read()
            except (OSError, UnicodeDecodeError):
                text = None
        try:
            self._ring = parse_key_ring(text)
        except Refused:
            self._ring = None

    def _signing_keys(self) -> Dict[str, bytes]:
        revoked = set(self._persisted.get("revoked_kids") or [])
        out: Dict[str, bytes] = {}
        e = self._enrollment or {}
        for k in list(e.get("policy_signing_keys") or []) + list(self._persisted.get("added_keys") or []):
            kid = k.get("kid") if isinstance(k, dict) else None
            if not isinstance(kid, str) or kid in revoked or kid in out:
                continue
            pk = ed25519_public_key(k.get("public_key", ""))
            if pk is not None:
                out[kid] = pk
        return out

    def _persist(self) -> None:
        try:
            if self._store is not None:
                self._store.write_json("state.json", self._persisted)
        except OSError:
            self.note_error("state_write_failed")

    # --- policy (policy.md 4) -------------------------------------------------------------

    def _try_accept(self, envelope: Any, from_cache: bool, raw_text: str) -> None:
        try:
            v = verify_envelope(envelope, self._signing_keys(), True)
            p = Policy(v.body)
            p.hash = v.hash
            if self._policy is not None and self._policy.hash == p.hash and not from_cache:
                return
            check_acceptance(p, self._enrollment["group"], time.time(), int(self._persisted.get("last_issued_seq") or 0),
                             int(self._persisted.get("min_issued_seq") or 0), allow_equal_seq=from_cache)
            if self._switching:
                debug("info", "policy_changed: now issued_seq %d" % p.issued_seq)
            self._policy = p
            self._policy_kid = v.kid
            self._rejected = None
            self._switching = False
            self._persisted["last_issued_seq"] = p.issued_seq
            self._persist()
            # The cache holds the signed envelope exactly as received; it is re-verified at start.
            if not from_cache:
                self._store.write_text("policy.envelope.json", raw_text)
            names = {"cookie", "baggage", "traceparent"}
            if p.subject is not None and p.subject.frm == "header":
                names.add(ascii_lower(p.subject.name))
            self._decision_names = frozenset(names)
            self._decision_bytes = frozenset(n.encode("latin-1") for n in names)
        except Refused as e:
            # hardening.md 2.2: a policy refused for the safety subset is reported as policy_unsafe.
            self.note_error("policy_unsafe" if e.detail.startswith(UNSAFE_DETAIL) else e.code)
            if self._policy is None:
                self._rejected = "expired_policy" if e.code == "expired_policy" else "policy_rejected"
        except Exception:
            self.note_error("policy_rejected")
            if self._policy is None:
                self._rejected = "policy_rejected"
        self._recompute()

    def _poll_policy(self) -> None:
        if self._fleet is None or self._stop.is_set():
            return
        try:
            r = self._fleet.get_policy(self._etag if self._policy is not None else None)
            if r.status == 304:
                self._last_contact = time.time()
            elif r.status == 200:
                self._last_contact = time.time()
                try:
                    env = parse_plain(r.body, True)
                except (JsonError, ValueError):
                    self.note_error("policy_json")
                    if self._policy is None:
                        self._rejected = "policy_rejected"
                    self._recompute()
                    return
                self._try_accept(env, False, r.body.decode("utf-8", "replace"))
                if self._policy is not None and r.headers.get("etag"):
                    self._etag = r.headers["etag"]
            elif r.status == 404:
                self._last_contact = time.time()
                self._policy = None
                self._rejected = "no_policy"
            elif r.status == 403:
                self._revoke()
            else:
                self.note_error("policy_http_%d" % r.status)
        except Exception:
            self.note_error("policy_network")
        if self._switching and self._policy is None:
            # The newer policy announced by the heartbeat could not be fetched or accepted.
            self._switching = False
            if self._rejected == "starting":
                self._rejected = "policy_rejected"
                self.note_error("policy_below_min_issued_seq")
        self._recompute()

    # --- heartbeat --------------------------------------------------------------------------

    def _overhead_us(self) -> Dict[str, int]:
        n = min(self._overhead_i, 1024)
        if n == 0:
            return {"p50": 0, "p99": 0}
        a = sorted(self._overhead[:n])

        def q(f: float) -> int:
            return int(round(a[min(n - 1, int(f * n))] / 1000))

        return {"p50": q(0.5), "p99": q(0.99)}

    def _heartbeat(self) -> None:
        if self._fleet is None or self._stop.is_set():
            return
        self._load_keys()
        self._recompute()
        p = self._policy
        body: Dict[str, Any] = {
            "source_id": self._enrollment["source_id"],
            "state": self.state,
            "counters": self.counters.snapshot(),
            "overhead_us": self._overhead_us(),
            "queue": self._exporter.size if self._exporter else {"events": 0, "bytes": 0},
            "last_errors": list(self._last_errors),
            "runtime": {"lang": "python", "lang_version": platform.python_version()},
            # The policy signing kids trusted now: tt-core waits for a rotation to reach the
            # source before it lets the old key be revoked.
            "signing_kids": sorted(self._signing_keys()),
        }
        if p is not None:
            body["policy"] = {"id": p.policy_id, "version": p.version, "issued_seq": p.issued_seq, "hash": p.hash}
        try:
            status, j = self._fleet.heartbeat(body)
            if status == 403:
                self._revoke()
            elif status == 200 and j is not None:
                self._apply_heartbeat(j)
            else:
                self.note_error("heartbeat_http_%d" % status)
        except Exception:
            self.note_error("heartbeat_network")
        self._recompute()

    def _apply_heartbeat(self, j: Dict[str, Any]) -> None:
        self._heartbeat_ok = True
        self._last_contact = time.time()
        kill = j.get("kill") is True
        if kill != (self._persisted.get("kill") is True):
            self._persisted["kill"] = kill
            self._persist()
        if kill:
            self._drop_queues()
        mis = j.get("min_issued_seq")
        if isinstance(mis, int) and not isinstance(mis, bool) and mis >= 0:
            if mis != self._persisted.get("min_issued_seq"):
                self._persisted["min_issued_seq"] = mis
                self._persist()
            if self._policy is not None and self._policy.issued_seq < mis:
                cur = j.get("policy_current")
                newer = (isinstance(cur, dict) and isinstance(cur.get("hash"), str) and cur["hash"] != self._policy.hash
                         and isinstance(cur.get("issued_seq"), int) and not isinstance(cur.get("issued_seq"), bool)
                         and cur["issued_seq"] >= mis)
                # The policy in use is superseded for good: capture stops at once (fail-closed).
                self._policy = None
                if newer:
                    # A normal policy change: the newer policy is fetched right away (policy_current below).
                    self._switching = True
                    self._rejected = "starting"
                    debug("info", "policy_superseded: fetching issued_seq %d" % cur["issued_seq"])
                else:
                    self._rejected = "policy_rejected"
                    self.note_error("policy_below_min_issued_seq")
                self._recompute()
        o = j.get("sampling_override_bp")
        # The override can only lower the policy rate; Sanitizer.rate_bp() takes the minimum.
        self._override_bp = o if isinstance(o, int) and not isinstance(o, bool) and 0 <= o <= 10000 else None
        # Revocations first: they only remove trust, and a key endorsed by a kid revoked in this
        # very response must not be pinned (RT3-KEY-3).
        if isinstance(j.get("revoke_signing_keys"), list):
            rk = set(self._persisted.get("revoked_kids") or [])
            before = len(rk)
            rk.update(k for k in j["revoke_signing_keys"] if isinstance(k, str))
            if len(rk) != before:
                self._persisted["revoked_kids"] = sorted(rk)
                self._persist()
            if self._policy is not None and self._policy_kid in rk:
                self._policy = None
                self._rejected = "policy_rejected"
                self.note_error("policy_key_revoked")
        if isinstance(j.get("add_signing_keys"), list):
            self._add_signing_keys(j["add_signing_keys"])
        cur = j.get("policy_current")
        if isinstance(cur, dict) and isinstance(cur.get("hash"), str) and (self._policy is None or cur["hash"] != self._policy.hash):
            self._poll_policy()
        rb = j.get("renew_before")
        if isinstance(rb, str):
            from .policy import parse_time

            t = parse_time(rb)
            if t == t and time.time() >= t:
                self._renew()

    def _add_signing_keys(self, items: List[Any]) -> None:
        """tt-core sends every endorsed key at every heartbeat, an endorser before the keys it
        endorses: the list is processed in order, so a key pinned earlier in it can endorse a
        later one. A revoked kid is never pinned again; a kid already pinned with the same key is
        skipped silently, one pinned with another key is refused."""
        revoked = set(self._persisted.get("revoked_kids") or [])
        known = self._signing_keys()
        pinned: Dict[str, bytes] = {}
        e = self._enrollment or {}
        for k in list(e.get("policy_signing_keys") or []) + list(self._persisted.get("added_keys") or []):
            kid = k.get("kid") if isinstance(k, dict) else None
            if not isinstance(kid, str) or kid in revoked or kid in pinned:
                continue
            raw = b64url_decode_strict(k.get("public_key", "")) if isinstance(k.get("public_key"), str) else None
            if raw is not None:
                pinned[kid] = raw
        added = list(self._persisted.get("added_keys") or [])
        changed = False
        for k in items:
            # Canonical codes (docs/spec/policy.md §3.1): malformed -> rejected; a kid pinned to
            # other bytes -> conflict; unknown/revoked endorser -> endorser_unknown; bad signature
            # -> endorsement_invalid.
            if not isinstance(k, dict):
                self.note_error("signing_key_rejected")
                continue
            kid, alg, pub, by, end = (k.get(x) for x in ("kid", "alg", "public_key", "endorsed_by", "endorsement"))
            if not (isinstance(kid, str) and _KID_RE.fullmatch(kid)):
                self.note_error("signing_key_rejected")
                continue
            if kid in revoked:
                continue
            if not (alg == "Ed25519" and isinstance(pub, str) and isinstance(by, str) and isinstance(end, str)):
                self.note_error("signing_key_rejected")
                continue
            raw = b64url_decode_strict(pub)
            sig = b64url_decode_strict(end)
            pk = ed25519_public_key(pub) if raw is not None and len(raw) == 32 else None
            if raw is None or len(raw) != 32 or sig is None or len(sig) != 64 or pk is None:
                self.note_error("signing_key_rejected")
                continue
            have = pinned.get(kid)
            if have is not None:
                if have != raw:
                    self.note_error("signing_key_conflict")
                continue
            endorser = None if by in revoked else known.get(by)
            if endorser is None:
                self.note_error("signing_key_endorser_unknown")
                continue
            msg = b"tt-fleet-key/v1\x00" + kid.encode("latin-1") + b"\x00" + raw
            if not ed25519.verify(endorser, msg, sig):
                self.note_error("signing_key_endorsement_invalid")
                continue
            added.append({"kid": kid, "alg": "Ed25519", "public_key": pub})
            known[kid] = pk
            pinned[kid] = raw
            changed = True
        if changed:
            self._persisted["added_keys"] = added
            self._persist()

    def _renew(self) -> None:
        if self._fleet is None or self._enrollment is None:
            return
        try:
            r = self._fleet.renew()
            if r is None:
                self.note_error("renew_failed")
                return
            self._enrollment["client_cert"] = r["client_cert"]
            if isinstance(r.get("not_after"), str):
                self._enrollment["not_after"] = r["not_after"]
            self._store.write_text("client.key", r["client_key"])
            self._store.write_json("enrollment.json", self._enrollment)
            self._connect()
        except Exception:
            self.note_error("renew_network")

    def _revoke(self) -> None:
        self._persisted["revoked"] = True
        self._persist()
        self._drop_queues()
        self.note_error("source_revoked")

    def _drop_queues(self) -> None:
        with self._plock:
            self._gen += 1
            n = len(self._pending)
            self._pending.clear()
            self._pending_bytes = 0
        if n:
            self.counters.inc("events_dropped_queue", n)
        if self._exporter is not None:
            self._exporter.clear()

    # --- state and capture gate ---------------------------------------------------------------

    def _recompute(self) -> None:
        now = time.time()
        p = self._policy
        max_age = (self._enrollment or {}).get("policy_max_age_s", 86400)
        key: Optional[Tuple[str, bytes]] = None
        if self._persisted.get("kill") or self._persisted.get("revoked"):
            st = "killed"
        elif p is None:
            st = self._rejected or "no_policy"
        elif not (now < p.not_after) or (self._last_contact > 0 and now - self._last_contact > max_age):
            st = "expired_policy"
        elif self._ring is None:
            st = "key_missing"
        else:
            try:
                key = select_key(self._ring, p)
                st = "capturing" if self._heartbeat_ok else "starting"
            except Refused:
                st = "key_mismatch"
        # Capture only after a heartbeat in this process (kill switch and min_issued_seq known).
        if st == "capturing" and key is not None and p is not None and self._last_contact > 0:
            cur = self._san
            if (cur is None or cur.policy is not p or cur.kid != key[0] or cur.key is not key[1]
                    or cur.rate_override_bp != self._override_bp):
                self._san = Sanitizer(p, key[0], key[1], rate_override_bp=self._override_bp)
        else:
            if st == "capturing":
                st = "starting"
            self._san = None
        if st != self.state:
            debug("state", st)
        self.state = st
