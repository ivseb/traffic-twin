"""Red team round 2: the Python SDK (sdk/python) against a fake, sometimes malicious, tt-core.

Invented data only; every canary is random per run. Reuses the SDK's own test helpers
(sdk/python/tests: FakeCore, Env, WsgiRunner), no install needed.

Run (from the repository root):
    python3 -m unittest discover -s test/redteam/python -t test/redteam/python -v

All tests pass: the former findings (kill switch vs. retrying batch / in-flight sanitization) are regression tests.
"""

from __future__ import annotations

import gzip
import http.client
import io
import json
import logging
import os
import random
import shutil
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
import warnings

HERE = os.path.dirname(os.path.abspath(__file__))
SDK = os.path.normpath(os.path.join(HERE, "..", "..", "..", "sdk", "python"))
for p in (os.path.join(SDK, "src"), SDK):
    if p not in sys.path:
        sys.path.insert(0, p)

from traffic_twin import context as ttctx  # noqa: E402
from traffic_twin import ed25519  # noqa: E402
from traffic_twin.agent import Agent, AgentOptions  # noqa: E402
from traffic_twin.capture.wsgi import WSGIMiddleware  # noqa: E402
from traffic_twin.policy import b64url_nopad  # noqa: E402
from traffic_twin.sanitizer import Sanitizer  # noqa: E402
from tests.fakecore import HMAC_KEY, SIGNING_KID, FakeCore, base_policy  # noqa: E402
from tests.harness import Env, Upstream, WsgiRunner, call, shop_policy  # noqa: E402
from tests.pki import Pki  # noqa: E402


def hook_routes(core: FakeCore, hook) -> None:
    """``hook(handler, method, path, body) -> bool``: True when it answered itself."""
    base = core.server.RequestHandlerClass

    class Hooked(base):  # type: ignore[misc, valid-type]
        def _route(self, method: str) -> None:
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            body = gzip.decompress(raw) if self.headers.get("Content-Encoding") == "gzip" else raw
            if hook(self, method, self.path.split("?")[0], body):
                return
            orig, self.rfile = self.rfile, io.BufferedReader(io.BytesIO(raw))  # replay for the original route
            try:
                super()._route(method)
            finally:
                self.rfile = orig

    core.server.RequestHandlerClass = Hooked


def hooked_env(policy, **kw) -> Env:
    """An Env whose fake core routes every request through ``env.hook`` first (installed
    before the agent connects, so kept-alive connections see it too)."""
    env = Env(policy, **kw)
    env.hook = None
    hook_routes(env.core, lambda h, m, p, b: bool(env.hook and env.hook(h, m, p, b)))
    return env


def reply(h, status: int, body: bytes = b"", headers=None) -> bool:
    h.send_response(status)
    h.send_header("Content-Length", str(len(body)))
    for k, v in (headers or {}).items():
        h.send_header(k, v)
    h.end_headers()
    if body:
        h.wfile.write(body)
    return True


def codes(core: FakeCore):
    return {e["code"] for hb in core.heartbeats for e in hb.get("last_errors", [])}


def make_agent(core: FakeCore, state_dir, **kw) -> Agent:
    o = dict(enroll_url=core.url, enroll_token=core.token, hmac_key=HMAC_KEY, service_name="shop-api", state_dir=state_dir,
             export_flush_s=0.1, heartbeat_interval_s=0.3, policy_poll_interval_s=0.3)
    o.update(kw)
    return Agent(AgentOptions(**o))


def echo_app(upstream_base=None):
    def app(environ, start_response):
        c = environ.get("HTTP_X_RT_CANARY", "none")
        n = int(environ.get("CONTENT_LENGTH") or 0)
        environ["wsgi.input"].read(n)
        if environ["PATH_INFO"].startswith("/out") and upstream_base:
            port = int(upstream_base.rsplit(":", 1)[1])
            hc = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            hc.request("POST", "/v1/shipments/%s?orderId=%s" % (c, c), body=json.dumps({"orderId": c, "note": c}).encode(),
                       headers={"Content-Type": "application/json", "X-Rt-Out": c, "Cookie": "sid=" + c})
            hc.getresponse().read()
            hc.close()
        out = json.dumps({"id": c, "status": "CREATED", "email": c + "@example.com", "nested": {"deep": [c, {"k": c}]}}).encode()
        start_response("200 OK", [("Content-Type", "application/json"), ("X-Rt-Echo", c), ("Set-Cookie", "sess=%s; Path=/" % c),
                                  ("Content-Length", str(len(out)))])
        return [out]
    return app


class _Tee(io.TextIOBase):
    def __init__(self) -> None:
        self.buf = io.StringIO()
        self.lock = threading.Lock()

    def write(self, s):  # type: ignore[override]
        with self.lock:
            self.buf.write(s)
        return len(s)

    def getvalue(self) -> str:
        with self.lock:
            return self.buf.getvalue()


class GuardTests(unittest.TestCase):
    def test_debug_mode_never_logs_payload_values(self):
        c = "rtcanary" + os.urandom(8).hex()
        cn = "n%d" % random.randint(100000000, 999999999)  # a name the name rule must hide (6+ digits)
        tee = _Tee()
        records = []

        class H(logging.Handler):
            def emit(self, r):
                records.append(self.format(r))

        root = logging.getLogger()
        lh = H(level=logging.DEBUG)
        root.addHandler(lh)
        old_level = root.level
        root.setLevel(logging.DEBUG)
        old_err, old_out = sys.stderr, sys.stdout
        try:
            with warnings.catch_warnings(record=True) as warned, Upstream() as up:
                warnings.simplefilter("always")
                sys.stderr = tee
                sys.stdout = tee
                with Env(shop_policy(carrier_base=up.base), debug=True, outbound="http.client") as env:
                    env.core.fail_logs = 1  # one failed export: exercises the error path
                    with WsgiRunner(WSGIMiddleware(echo_app(up.base), host=env.agent)) as srv:
                        h = {"X-Rt-Canary": c, "Authorization": "Bearer " + c, "Cookie": "a=%s; %s=1" % (c, cn), "X-" + cn: c,
                             "User-Agent": c, "Referer": "https://x.example/" + c}
                        deep = ("[" * 4000 + json.dumps(c) + "]" * 4000).encode()
                        reqs = [
                            ("GET", "/x/%s/y?q=%s&%s=1&%s" % (c, c, cn, c), None, {}),
                            ("POST", "/orders", json.dumps({"email": c, cn: [c, {"c": c}]}).encode(), {"Content-Type": "application/json"}),
                            ("POST", "/orders", ('{"broken": "%s",,' % c).encode(), {"Content-Type": "application/json"}),
                            ("POST", "/orders", deep, {"Content-Type": "application/json"}),
                            ("POST", "/orders", b'{"a":"\xff\xfe' + c.encode() + b'"}', {"Content-Type": "application/json"}),
                            ("POST", "/orders", b"not-gzip-" + c.encode(), {"Content-Type": "application/json", "Content-Encoding": "gzip"}),
                            ("POST", "/orders", gzip.compress(json.dumps({"v": c}).encode()), {"Content-Type": "application/json", "Content-Encoding": "gzip"}),
                            ("POST", "/orders", ("%s=%s&e=%s" % (cn, c, c)).encode(), {"Content-Type": "application/x-www-form-urlencoded"}),
                            ("POST", "/orders", c.encode() * 200000, {"Content-Type": "text/plain"}),
                            ("POST", "/out", b"{}", {"Content-Type": "application/json"}),
                        ]
                        for m, path, body, extra in reqs:
                            call(srv.port, m, path, body, dict(h, **extra))
                        env.events(n=len(reqs) + 1, timeout=15)
                        env.core.wait_for(lambda core: len(core.heartbeats) >= 6, 5)
                    hbs = json.dumps(env.core.heartbeats)
                    evs = "\n".join(env.core.event_strings)
                    self.assertGreaterEqual(len(env.core.events), len(reqs), "events")
        finally:
            sys.stderr, sys.stdout = old_err, old_out
            root.removeHandler(lh)
            root.setLevel(old_level)
        where = {"stderr/stdout": tee.getvalue(), "logging": "\n".join(records), "warnings": "\n".join(str(w.message) for w in warned),
                 "heartbeats": hbs, "events": evs}
        self.assertIn("[traffic-twin]", tee.getvalue(), "debug output is on")
        leaks = {k: v[max(0, v.lower().find(c) if c in v.lower() else v.find(cn)) - 200:][:300]
                 for k, v in where.items() if c in v.lower() or cn in v}
        self.assertEqual(leaks, {}, "canary leaked")

    def test_state_dir_and_file_permissions(self):
        home = tempfile.mkdtemp(prefix="tt-rt-home-")
        old_home = os.environ.get("HOME")
        try:
            with Env(base_policy()) as env:
                os.environ["HOME"] = home
                a2 = make_agent(env.core, None).start(wait=20)
                try:
                    self.assertTrue(env.core.wait_for(lambda c: sum(h["state"] == "capturing" for h in c.heartbeats) >= 3), env.core.heartbeats[-1:])
                    env.core.kill = True
                    self.assertTrue(env.core.wait_for(lambda c: c.heartbeats[-1]["state"] == "killed" and a2.state == "killed"))
                    time.sleep(0.5)
                finally:
                    a2.stop()
                root = os.path.join(home, ".traffic-twin")
                dirs = [env.state_dir] + [os.path.join(root, d) for d in os.listdir(root)]
                self.assertEqual(os.stat(root).st_mode & 0o777, 0o700, root)
                for d in dirs:
                    self.assertEqual(os.stat(d).st_mode & 0o777, 0o700, d)
                    files = os.listdir(d)
                    for f in ("client.key", "client.crt", "enrollment.json", "policy.envelope.json", "state.json"):
                        self.assertIn(f, files)
                    for f in files:
                        self.assertEqual(os.stat(os.path.join(d, f)).st_mode & 0o777, 0o600, (d, f))
        finally:
            if old_home is None:
                os.environ.pop("HOME", None)
            else:
                os.environ["HOME"] = old_home
            shutil.rmtree(home, ignore_errors=True)

    def test_wider_preexisting_state_dirs_are_repaired_and_untrusted_files_ignored(self):
        from traffic_twin.store import StateStore
        base = tempfile.mkdtemp(prefix="tt-rt-store-")
        try:
            root = os.path.join(base, ".traffic-twin")
            leaf = os.path.join(root, "abc")
            os.makedirs(leaf, mode=0o777)
            os.chmod(root, 0o755)
            os.chmod(leaf, 0o775)
            seen = []
            st = StateStore(leaf, seen.append)
            st.ensure()
            self.assertFalse(st.ephemeral)
            self.assertEqual(os.stat(root).st_mode & 0o777, 0o700)
            self.assertEqual(os.stat(leaf).st_mode & 0o777, 0o700)
            st.write_json("state.json", {"kill": False})
            self.assertEqual(st.read_json("state.json"), {"kill": False})
            os.chmod(os.path.join(leaf, "state.json"), 0o666)  # group/world-writable: not trusted
            self.assertIsNone(st.read_json("state.json"))
            self.assertEqual(seen, ["state_file_untrusted"])
            st.write_text("client.key", "KEY")
            os.chmod(os.path.join(leaf, "client.key"), 0o644)  # readable by others: tightened, still ours
            self.assertEqual(st.read_text("client.key"), "KEY")
            self.assertEqual(os.stat(os.path.join(leaf, "client.key")).st_mode & 0o777, 0o600)
            # a symlink planted as a state file is not followed
            os.symlink("/etc/hosts", os.path.join(leaf, "enrollment.json"))
            self.assertIsNone(st.read_text("enrollment.json"))
        finally:
            shutil.rmtree(base, ignore_errors=True)

    def test_restart_with_cached_policy_and_core_down_never_captures(self):
        core = FakeCore(base_policy())
        st = tempfile.mkdtemp(prefix="tt-rt-state-")
        try:
            a = make_agent(core, st).start(wait=20)
            self.assertTrue(core.wait_for(lambda c: a.state == "capturing"))
            a.stop()
            core.close()
            b = make_agent(core, st).start(wait=10)
            try:
                with WsgiRunner(WSGIMiddleware(echo_app(), host=b)) as srv:
                    for _ in range(3):
                        call(srv.port, "POST", "/orders", b"{}", {"Content-Type": "application/json"})
                time.sleep(1.0)
                self.assertNotEqual(b.state, "capturing")
                self.assertEqual(b.counters.snapshot()["exchanges_sampled"], 0)
            finally:
                b.stop()
        finally:
            shutil.rmtree(st, ignore_errors=True)

    def test_short_or_missing_hmac_key_means_no_capture(self):
        for key in ("k1:" + b64url_nopad(os.urandom(31)), None):
            with Env(base_policy(), wait_capturing=False, hmac_key=key) as env:
                self.assertTrue(env.core.wait_for(lambda c: len(c.heartbeats) >= 2))
                self.assertEqual(env.core.heartbeats[-1]["state"], "key_missing")
                self.assertIsNone(env.agent.active())

    def test_h1_policy_planted_in_cache_is_refused_at_startup(self):
        core = FakeCore(base_policy())
        st = tempfile.mkdtemp(prefix="tt-rt-state-")
        only304 = []
        hook_routes(core, lambda h, m, p, b: reply(h, 304) if (only304 and p == "/fleet/v1/policy") else False)
        try:
            a = make_agent(core, st).start(wait=20)
            self.assertTrue(core.wait_for(lambda c: a.state == "capturing"))
            a.stop()
            unsafe = base_policy(issued_seq=2, version=2)
            unsafe["global"]["request"]["headers"]["authorization"] = {"action": "keep"}
            with open(os.path.join(st, "policy.envelope.json"), "w") as f:
                f.write(json.dumps(core.make_envelope(unsafe)))
            only304.append(True)
            n = len(core.heartbeats)
            b = make_agent(core, st).start(wait=10)
            try:
                self.assertTrue(core.wait_for(lambda c: len(c.heartbeats) >= n + 2))
                hbs = core.heartbeats[n:]
                self.assertTrue(all(h["state"] != "capturing" and (h.get("policy") or {}).get("issued_seq") != 2 for h in hbs),
                                [(h["state"], h.get("policy")) for h in hbs])
                self.assertIn("policy_unsafe", codes(core))
            finally:
                b.stop()
        finally:
            core.close()
            shutil.rmtree(st, ignore_errors=True)

    def test_malicious_policies_bad_signature_downgrade_forged_endorsement_oversized(self):
        huge = []
        with hooked_env(base_policy()) as env:
            core = env.core
            def hook(h, m, p, b):
                if not (huge and p == "/fleet/v1/policy"):
                    return False
                huge.append("served")
                try:
                    return reply(h, 200, b'{"pad":"' + b"A" * (20 << 20) + b'"}', {"Content-Type": "application/json"})
                except OSError:  # the client hung up after its cap
                    return True

            env.hook = hook

            def seq():
                return (core.heartbeats[-1].get("policy") or {}).get("issued_seq")

            def settle():
                n = len(core.heartbeats)
                core.wait_for(lambda c: len(c.heartbeats) >= n + 3)

            core.set_policy(base_policy(issued_seq=3, version=3), bump=False)
            self.assertTrue(core.wait_for(lambda c: seq() == 3))
            bad = core.make_envelope(base_policy(issued_seq=4, version=4))
            sig = bytearray(bad["signature"]["sig"].encode())
            sig[3] = ord("A") if sig[3] != ord("A") else ord("B")
            bad["signature"]["sig"] = sig.decode()
            core.envelope = bad
            settle()
            self.assertEqual(seq(), 3, "bad signature accepted")
            core.set_policy(base_policy(issued_seq=2, version=2), bump=False)
            settle()
            self.assertEqual(seq(), 3, "issued_seq downgrade accepted")
            evil = os.urandom(32)
            pub = ed25519.public_key(evil)
            forged = ed25519.sign(evil, b"tt-fleet-key/v1\x00evil-1\x00" + pub)
            core.extra_heartbeat = {"add_signing_keys": [{"kid": "evil-1", "alg": "Ed25519", "public_key": b64url_nopad(pub),
                                                          "endorsed_by": SIGNING_KID, "endorsement": b64url_nopad(forged)}]}
            settle()
            body5 = base_policy(issued_seq=5, version=5)
            core.policy_body = body5
            core.envelope = core.make_envelope(body5, kid="evil-1", seed=evil)
            settle()
            self.assertEqual(seq(), 3, "policy signed with a key with a forged endorsement accepted")
            self.assertIn("signing_key_endorsement_invalid", codes(core))
            core.extra_heartbeat = {}
            huge.append(True)
            settle()
            self.assertIn("served", huge, "the oversized answer was served")
            self.assertEqual(seq(), 3)
            self.assertEqual(core.heartbeats[-1]["state"], "capturing")

    def test_kill_switch_cannot_be_lifted_by_a_server_outside_the_pinned_ca(self):
        swapped = []

        def hook(h, m, p, b):
            if swapped:  # connections opened before the swap: refuse and hang up
                h.close_connection = True
                return reply(h, 503, b"", {"Connection": "close"})
            return False

        with hooked_env(base_policy()) as env:
            core = env.core
            env.hook = hook
            core.kill = True
            self.assertTrue(core.wait_for(lambda c: env.agent.state == "killed"))
            other = Pki()
            d = tempfile.mkdtemp(prefix="tt-rt-pki-")
            chain, key = os.path.join(d, "chain.pem"), os.path.join(d, "key.pem")
            with open(chain, "w") as f:
                f.write(other.server_chain_pem)
            with open(key, "w") as f:
                f.write(other.server_key_pem)
            core.server.socket.context.load_cert_chain(chain, key)
            shutil.rmtree(d, ignore_errors=True)
            swapped.append(True)
            core.kill = False
            n = len(core.heartbeats)
            time.sleep(2.0)
            self.assertLessEqual(len(core.heartbeats), n + 1, "heartbeats reached a server outside the pinned CA")
            self.assertEqual(env.agent.state, "killed")
            self.assertIn("heartbeat_network", {e["code"] for e in env.agent._last_errors}, "TLS to the other CA was refused")

    def test_no_outbound_connection_other_than_tt_core(self):
        seen = []
        orig_cc, orig_gai = socket.create_connection, socket.getaddrinfo

        def cc(address, *a, **kw):
            if threading.current_thread().name.startswith("traffic-twin"):
                seen.append(("connect", address[0], address[1]))
            return orig_cc(address, *a, **kw)

        def gai(host, *a, **kw):
            if threading.current_thread().name.startswith("traffic-twin"):
                seen.append(("dns", host, a[0] if a else None))
            return orig_gai(host, *a, **kw)

        socket.create_connection, socket.getaddrinfo = cc, gai
        try:
            with Env(base_policy()) as env:
                with WsgiRunner(WSGIMiddleware(echo_app(), host=env.agent)) as srv:
                    for _ in range(3):
                        call(srv.port, "POST", "/orders", b'{"a":1}', {"Content-Type": "application/json"})
                env.events(n=3)
                port = env.core.port
        finally:
            socket.create_connection, socket.getaddrinfo = orig_cc, orig_gai
        self.assertTrue(seen, "recorder saw the SDK connections")
        self.assertEqual([s for s in seen if s[1] != "127.0.0.1" or s[2] not in (port, str(port))], [])

    def test_no_opentelemetry_global_registration(self):
        d = tempfile.mkdtemp(prefix="tt-rt-otel-")
        pkg = os.path.join(d, "opentelemetry")
        for sub in ("", "trace", "propagate", "context", "baggage"):
            os.makedirs(os.path.join(pkg, sub), exist_ok=True)
        rec = "import builtins\nACC = builtins.__dict__.setdefault('_rt_otel_access', [])\n"
        with open(os.path.join(pkg, "__init__.py"), "w") as f:
            f.write(rec + "def __getattr__(n):\n    ACC.append('otel.' + n)\n    raise AttributeError(n)\n")
        with open(os.path.join(pkg, "trace", "__init__.py"), "w") as f:
            f.write(rec + (
                "class _SC:\n    is_valid = False\n    trace_id = 0\n    span_id = 0\n"
                "class _Span:\n    def get_span_context(self):\n        ACC.append('span.get_span_context')\n        return _SC()\n"
                "def get_current_span(*a):\n    ACC.append('trace.get_current_span')\n    return _Span()\n"
                "def set_tracer_provider(*a):\n    ACC.append('trace.set_tracer_provider')\n"
                "def __getattr__(n):\n    ACC.append('trace.' + n)\n    raise AttributeError(n)\n"))
        for sub in ("propagate", "context", "baggage"):
            with open(os.path.join(pkg, sub, "__init__.py"), "w") as f:
                f.write(rec + "ACC.append('import:%s')\ndef __getattr__(n):\n    ACC.append('%s.' + n)\n    raise AttributeError(n)\n" % (sub, sub))
        import builtins
        builtins.__dict__["_rt_otel_access"] = []
        sys.path.insert(0, d)
        saved = (ttctx._otel_trace, ttctx._otel_checked)
        ttctx._otel_trace, ttctx._otel_checked = None, False
        try:
            with Env(base_policy()) as env:
                with WsgiRunner(WSGIMiddleware(echo_app(), host=env.agent)) as srv:
                    call(srv.port, "POST", "/orders", b"{}", {"Content-Type": "application/json"})
                env.events(n=1)
            acc = list(builtins.__dict__["_rt_otel_access"])
        finally:
            sys.path.remove(d)
            for m in [m for m in sys.modules if m == "opentelemetry" or m.startswith("opentelemetry.")]:
                del sys.modules[m]
            ttctx._otel_trace, ttctx._otel_checked = saved
            shutil.rmtree(d, ignore_errors=True)
        self.assertIn("trace.get_current_span", acc, "the stub was used")
        self.assertEqual(sorted(set(acc) - {"trace.get_current_span", "span.get_span_context", "otel.trace"}), [])

    def test_policy_answer_beyond_the_cap_is_abandoned(self):
        closed = []

        def hook(h, m, p, b):
            if p != "/fleet/v1/policy" or not streaming:
                return False
            streaming.clear()
            h.send_response(200)
            h.send_header("Content-Type", "application/json")
            h.send_header("Transfer-Encoding", "chunked")
            h.end_headers()
            chunk = b"A" * (64 << 10)
            t0 = time.time()
            try:
                h.wfile.write(b"8\r\n{\"pad\":\"\r\n")
                while time.time() - t0 < 8:
                    h.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                    time.sleep(0.005)
            except OSError:
                closed.append(time.time() - t0)
            h.close_connection = True
            return True

        streaming = []
        with hooked_env(base_policy()) as env:
            env.hook = hook
            streaming.append(True)
            env.core.set_policy(base_policy())
            self.assertTrue(env.core.wait_for(lambda c: bool(closed), 7), "the SDK kept reading past the 8 MiB cap")


class KillSwitchTests(unittest.TestCase):
    def test_kill_switch_stops_the_batch_under_retry(self):
        """The exporter retries a batch it already took from the queue; the kill switch
        clears only the queue, so the batch is delivered after the source reports killed."""
        posts = []
        with hooked_env(base_policy()) as env:
            core = env.core

            def hook(h, m, p, b):
                if p != "/v1/logs":
                    return False
                posts.append(time.time())
                if len(posts) == 1:
                    core.kill = True  # the operator pulls the kill switch while the intake is busy
                    return reply(h, 503, b"", {"Retry-After": "2"})
                return False

            env.hook = hook
            with WsgiRunner(WSGIMiddleware(echo_app(), host=env.agent)) as srv:
                call(srv.port, "POST", "/orders", b'{"a":1}', {"Content-Type": "application/json"})
            self.assertTrue(core.wait_for(lambda c: env.agent.state == "killed", 5))
            time.sleep(4)
            self.assertEqual(len(core.events), 0, "%d event(s) delivered after the source reported killed" % len(core.events))

    def test_exchange_being_sanitized_when_kill_arrives_is_not_exported(self):
        """The sanitize worker thread does not re-check the capture gate after Sanitizer.run:
        an exchange taken from the queue before the kill is enqueued and sent after it."""
        gate, entered = threading.Event(), threading.Event()
        orig_run = Sanitizer.run

        def slow_run(self, *a, **kw):
            entered.set()
            gate.wait(10)  # a large body: sanitization takes a while
            return orig_run(self, *a, **kw)

        with Env(base_policy()) as env:
            Sanitizer.run = slow_run
            try:
                with WsgiRunner(WSGIMiddleware(echo_app(), host=env.agent)) as srv:
                    call(srv.port, "POST", "/orders", b'{"a":1}', {"Content-Type": "application/json"})
                self.assertTrue(entered.wait(5))
                env.core.kill = True
                self.assertTrue(env.core.wait_for(lambda c: env.agent.state == "killed", 5))
            finally:
                gate.set()
                Sanitizer.run = orig_run
            env.agent.flush(3)
            time.sleep(1)
            self.assertEqual(len(env.core.events), 0, "%d event(s) exported after the kill switch" % len(env.core.events))


if __name__ == "__main__":
    unittest.main()
