"""The zero-code start (``python -m traffic_twin run -- <server> ...``) captures INBOUND traffic of
ASGI/WSGI apps by itself, and says so when it cannot."""

import json
import os
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

from .fakecore import HMAC_KEY, FakeCore
from .harness import call, shop_policy

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(os.path.dirname(HERE), "src")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def have(*mods):
    for m in mods:
        try:
            __import__(m)
        except ImportError:
            return False
    return True


class Run:
    """A program started with ``python -m traffic_twin run -- ...`` against a fake tt-core."""

    def __init__(self, policy=None, app_files=None, **extra_env):
        self.core = FakeCore(policy if policy is not None else shop_policy())
        self.dir = tempfile.mkdtemp(prefix="tt-auto-")
        for name, src in (app_files or {}).items():
            with open(os.path.join(self.dir, name), "w") as f:
                f.write(textwrap.dedent(src))
        self.env = dict(os.environ, PYTHONPATH=SRC, TT_ENROLL_URL=self.core.url, TT_ENROLL_TOKEN=self.core.token,
                        TT_HMAC_KEY=HMAC_KEY, TT_SERVICE_NAME="shop-api", TT_STATE_DIR=os.path.join(self.dir, "state"),
                        TT_HEARTBEAT_INTERVAL_MS="500", TT_POLICY_POLL_INTERVAL_MS="500", TT_EXPORT_FLUSH_MS="100")
        for k in ("TT_OUTBOUND", "TT_DEBUG", "TT_DISABLED"):
            self.env.pop(k, None)
        if self.core.ca_file_if_needed():
            self.env["TT_ENROLL_CA_FILE"] = self.core.ca_file_if_needed()
        self.env.update(extra_env)
        self.proc = None
        self.err = ""

    def start(self, *cmd):
        self.proc = subprocess.Popen([sys.executable, "-m", "traffic_twin", "run", "--"] + list(cmd), cwd=self.dir, env=self.env,
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        return self

    def wait_port(self, port, timeout=40.0):
        end = time.time() + timeout
        while time.time() < end:
            if self.proc.poll() is not None:
                raise AssertionError("the server exited: " + self.proc.stderr.read())
            try:
                socket.create_connection(("127.0.0.1", port), 0.2).close()
                return
            except OSError:
                time.sleep(0.1)
        raise AssertionError("the server did not listen")

    def wait_capturing(self, timeout=40.0):
        ok = self.core.wait_for(lambda c: any(h.get("state") == "capturing" for h in c.heartbeats), timeout)
        assert ok, "the source never reached capturing"

    def inbound_events(self, pred, timeout=15.0):
        self.core.wait_for(lambda c: any(pred(e["event"]) for e in c.events), timeout)
        return [e["event"] for e in self.core.events if pred(e["event"])]

    def stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(5)
        if self.proc is not None and self.proc.stderr is not None:
            self.err += self.proc.stderr.read()
            self.proc.stderr.close()
        self.core.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.stop()


FASTAPI_APP = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/orders/{order_id}")
async def get_order(order_id: str):
    return {"id": order_id, "status": "SHIPPED"}
"""

FLASK_APP = """
from flask import Flask, jsonify
app = Flask(__name__)

@app.route("/orders/<order_id>")
def get_order(order_id):
    return jsonify({"id": order_id, "status": "SHIPPED"})
"""

PLAIN_ASGI = """
async def app(scope, receive, send):
    if scope["type"] != "http":
        return
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": b'{"status":"OK"}'})
"""

PLAIN_WSGI = """
def app(environ, start_response):
    start_response("200 OK", [("Content-Type", "application/json")])
    return [b'{"status":"OK"}']
"""


class InboundViaServers(unittest.TestCase):
    def check_order_event(self, r, port):
        r.wait_port(port)
        r.wait_capturing()
        self.assertEqual(call(port, "GET", "/orders/ORD-7")[0], 200)
        evs = r.inbound_events(lambda e: e.get("dir") == "inbound" and e.get("op") == "GET /orders/{id}")
        self.assertTrue(evs, "no inbound event; stderr: " + (r.proc.stderr.read() if r.proc.poll() is not None else ""))
        self.assertEqual(evs[0]["route_source"], "framework")
        self.assertNotIn("inbound not captured", r.err)

    @unittest.skipUnless(have("fastapi", "uvicorn"), "fastapi/uvicorn not installed")
    def test_fastapi_with_uvicorn_command(self):
        port = free_port()
        with Run(app_files={"app.py": FASTAPI_APP}).start(sys.executable, "-m", "uvicorn", "app:app", "--port", str(port), "--log-level", "warning") as r:
            self.check_order_event(r, port)

    @unittest.skipUnless(have("flask"), "flask not installed")
    def test_flask_with_the_flask_command(self):
        port = free_port()
        with Run(app_files={"app.py": FLASK_APP}).start(sys.executable, "-m", "flask", "--app", "app", "run", "--port", str(port)) as r:
            self.check_order_event(r, port)

    @unittest.skipUnless(have("flask", "gunicorn"), "flask/gunicorn not installed")
    def test_flask_with_gunicorn(self):
        port = free_port()
        with Run(app_files={"app.py": FLASK_APP}).start(sys.executable, "-m", "gunicorn", "app:app", "-b", "127.0.0.1:%d" % port) as r:
            self.check_order_event(r, port)

    @unittest.skipUnless(have("uvicorn"), "uvicorn not installed")
    def test_plain_asgi_callable_with_uvicorn(self):
        port = free_port()
        with Run(app_files={"app.py": PLAIN_ASGI}).start(sys.executable, "-m", "uvicorn", "app:app", "--port", str(port), "--log-level", "warning") as r:
            r.wait_port(port)
            r.wait_capturing()
            self.assertEqual(call(port, "GET", "/anything")[0], 200)
            self.assertTrue(r.inbound_events(lambda e: e.get("dir") == "inbound"))

    @unittest.skipUnless(have("gunicorn"), "gunicorn not installed")
    def test_plain_wsgi_callable_with_gunicorn(self):
        port = free_port()
        with Run(app_files={"app.py": PLAIN_WSGI}).start(sys.executable, "-m", "gunicorn", "app:app", "-b", "127.0.0.1:%d" % port) as r:
            r.wait_port(port)
            r.wait_capturing()
            self.assertEqual(call(port, "GET", "/anything")[0], 200)
            self.assertTrue(r.inbound_events(lambda e: e.get("dir") == "inbound"))

    @unittest.skipUnless(have("uvicorn"), "uvicorn not installed")
    def test_an_app_factory_is_left_alone(self):
        port = free_port()
        src = "from fastapi import FastAPI\ndef create():\n    a = FastAPI()\n    @a.get('/orders/{order_id}')\n    async def g(order_id: str):\n        return {'id': order_id, 'status': 'S'}\n    return a\n"
        if not have("fastapi"):
            self.skipTest("fastapi not installed")
        with Run(app_files={"app.py": src}).start(sys.executable, "-m", "uvicorn", "app:create", "--factory", "--port", str(port), "--log-level", "warning") as r:
            self.check_order_event(r, port)


class InstallIsIdempotent(unittest.TestCase):
    @unittest.skipUnless(have("fastapi", "uvicorn"), "fastapi/uvicorn not installed")
    def test_explicit_install_together_with_the_zero_code_start_captures_once(self):
        port = free_port()
        src = FASTAPI_APP + "\nimport traffic_twin\napp = traffic_twin.install(app)\n"
        with Run(app_files={"app.py": src}).start(sys.executable, "-m", "uvicorn", "app:app", "--port", str(port), "--log-level", "warning") as r:
            r.wait_port(port)
            r.wait_capturing()
            call(port, "GET", "/orders/ORD-1")
            evs = r.inbound_events(lambda e: e.get("dir") == "inbound" and e.get("op") == "GET /orders/{id}")
            time.sleep(1.0)
            r.core.wait_for(lambda c: False, 0.5)
            evs = [e["event"] for e in r.core.events if e["event"].get("dir") == "inbound" and e["event"].get("op") == "GET /orders/{id}"]
            self.assertEqual(len(evs), 1)


class DjangoAndOutbound(unittest.TestCase):
    @unittest.skipUnless(have("django"), "django not installed")
    def test_django_applications_are_wrapped(self):
        script = textwrap.dedent("""
            import traffic_twin.auto
            from django.conf import settings
            settings.configure(ROOT_URLCONF=__name__, ALLOWED_HOSTS=["*"], SECRET_KEY="t")
            import django
            django.setup()
            urlpatterns = []
            from django.core.wsgi import get_wsgi_application
            from django.core.asgi import get_asgi_application
            from traffic_twin.capture.wsgi import WSGIMiddleware
            from traffic_twin.capture.asgi import ASGIMiddleware
            assert isinstance(get_wsgi_application(), WSGIMiddleware)
            assert isinstance(get_asgi_application(), ASGIMiddleware)
            print("ok")
        """)
        env = dict(os.environ, PYTHONPATH=SRC)
        for k in list(env):
            if k.startswith("TT_"):
                del env[k]
        p = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
        self.assertEqual((p.returncode, p.stdout.strip()), (0, "ok"), p.stderr)

    @unittest.skipUnless(have("httpx"), "httpx not installed")
    def test_httpx_is_captured_without_tt_outbound(self):
        port = free_port()
        script = textwrap.dedent("""
            import http.server, threading, time
            class H(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    b = b'{"status":"OK"}'
                    self.send_response(200); self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
                def log_message(self, *a): pass
            srv = http.server.ThreadingHTTPServer(("127.0.0.1", %d), H)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            import httpx
            time.sleep(6)
            httpx.get("http://127.0.0.1:%d/v1/shipments?orderId=ORD-9")
            time.sleep(2)
        """ % (port, port))
        with Run(policy=shop_policy(carrier_base="http://127.0.0.1:%d" % port), app_files={"job.py": script}).start(sys.executable, "job.py") as r:
            r.wait_capturing()
            evs = r.inbound_events(lambda e: e.get("dir") == "outbound" and e.get("service") == "carrier", timeout=25)
            self.assertTrue(evs)

    @unittest.skipUnless(have("httpx"), "httpx not installed")
    def test_tt_outbound_off_turns_the_outbound_side_off(self):
        port = free_port()
        script = textwrap.dedent("""
            import http.server, threading, time
            class H(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers()
                def log_message(self, *a): pass
            srv = http.server.ThreadingHTTPServer(("127.0.0.1", %d), H)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            import httpx
            time.sleep(5)
            httpx.get("http://127.0.0.1:%d/v1/shipments?orderId=ORD-9")
            time.sleep(2)
        """ % (port, port))
        with Run(policy=shop_policy(carrier_base="http://127.0.0.1:%d" % port), app_files={"job.py": script}, TT_OUTBOUND="off").start(sys.executable, "job.py") as r:
            r.wait_capturing()
            time.sleep(8)
            self.assertFalse([e for e in r.core.events if e["event"].get("dir") == "outbound"])


class InboundNotCaptured(unittest.TestCase):
    def test_a_program_without_a_web_app_warns_once_and_reports_the_problem(self):
        with Run(TT_INBOUND_GRACE_MS="300") as r:
            r.start(sys.executable, "-c", "import time; time.sleep(5)")
            r.wait_capturing()
            ok = r.core.wait_for(lambda c: any(any(le.get("code") == "inbound_not_captured" for le in h.get("last_errors", [])) for h in c.heartbeats), 15)
            self.assertTrue(ok, "the problem inbound_not_captured never reached tt-core")
            r.proc.wait(30)
            err = r.proc.stderr.read()
        self.assertEqual(err.count("inbound not captured"), 1, err)
        self.assertIn("traffic_twin.install(app)", err)

    @unittest.skipUnless(have("uvicorn"), "uvicorn not installed")
    def test_a_wrapped_app_never_reports_it(self):
        port = free_port()
        with Run(app_files={"app.py": PLAIN_ASGI}, TT_INBOUND_GRACE_MS="2000").start(sys.executable, "-m", "uvicorn", "app:app", "--port", str(port), "--log-level", "warning") as r:
            r.wait_port(port)
            r.wait_capturing()
            time.sleep(3)
            self.assertFalse(any(any(le.get("code") == "inbound_not_captured" for le in h.get("last_errors", [])) for h in r.core.heartbeats))
        self.assertNotIn("inbound not captured", r.err)


if __name__ == "__main__":
    unittest.main()
