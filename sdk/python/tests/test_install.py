"""install() helpers (Flask, FastAPI, Django, generic callables) and the sitecustomize auto start."""

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import unittest

import traffic_twin
from traffic_twin.capture.asgi import ASGIMiddleware
from traffic_twin.capture.wsgi import WSGIMiddleware
from traffic_twin.runtime import install

from .fakecore import HMAC_KEY, FakeCore
from .harness import Env, WsgiRunner, call, shop_policy

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(os.path.dirname(HERE), "src")


def plain_wsgi(environ, start_response):
    start_response("200 OK", [])
    return [b""]


async def plain_asgi(scope, receive, send):
    pass


class DetectionTest(unittest.TestCase):
    def test_generic_callables(self):
        self.assertIsInstance(install(plain_wsgi, start_agent=False), WSGIMiddleware)
        self.assertIsInstance(install(plain_asgi, start_agent=False), ASGIMiddleware)
        self.assertIsInstance(install(plain_wsgi, kind="wsgi", start_agent=False), WSGIMiddleware)

        class CallableASGI:
            async def __call__(self, scope, receive, send):
                pass

        self.assertIsInstance(install(CallableASGI(), start_agent=False), ASGIMiddleware)

    def test_install_never_raises_without_configuration(self):
        for k in list(os.environ):
            if k.startswith("TT_"):
                self.skipTest("TT_* set in the environment")
        a = traffic_twin.start()
        try:
            self.assertIsNone(a.active())  # nothing configured: nothing captured
            self.assertEqual(plain_wsgi({}, lambda *x: None), [b""])
            wrapped = install(plain_wsgi, start_agent=False)
            self.assertEqual(list(wrapped({"REQUEST_METHOD": "GET"}, lambda *x: None)), [b""])
        finally:
            traffic_twin.stop()
        self.assertIsNone(traffic_twin.get_agent())


class FrameworkInstallTest(unittest.TestCase):
    def test_flask(self):
        try:
            import flask
        except ImportError:
            self.skipTest("flask not installed")
        app = flask.Flask("t")
        out = install(app, start_agent=False)
        self.assertIs(out, app)
        self.assertIsInstance(app.wsgi_app, WSGIMiddleware)
        self.assertEqual(app.wsgi_app.framework, "flask")

    def test_fastapi(self):
        try:
            import fastapi
        except ImportError:
            self.skipTest("fastapi not installed")
        app = fastapi.FastAPI()
        self.assertIs(install(app, start_agent=False), app)
        self.assertTrue(any(m.cls is ASGIMiddleware for m in app.user_middleware))

    def test_django_wsgi_route(self):
        try:
            import django
            from django.conf import settings
        except ImportError:
            self.skipTest("django not installed")
        if not settings.configured:
            settings.configure(ROOT_URLCONF=__name__, ALLOWED_HOSTS=["*"], SECRET_KEY="test", DEBUG=False, USE_TZ=True)
            django.setup()
        from django.core.wsgi import get_wsgi_application

        pol = shop_policy()
        pol["services"][0]["ops"].append({"op": "GET /orders/{pk}/lines/{n}", "request": {"path": {"pk": {"action": "hmac", "domain": "order"}}}})
        with Env(pol) as env:
            app = get_wsgi_application()
            wrapped = WSGIMiddleware(app, host=env.agent, framework="django")
            self.assertIsInstance(install(app, start_agent=False), WSGIMiddleware)
            with WsgiRunner(wrapped) as srv:
                st, _h, body = call(srv.port, "GET", "/orders/42/lines/3/")
                self.assertEqual((st, json.loads(body)), (200, {"pk": 42}))
                re_st, _h, _b = call(srv.port, "GET", "/legacy/2026/")
                self.assertEqual(re_st, 200)
            e = env.events(lambda e: e["op"] == "GET /orders/{pk}/lines/{n}")[0]
            self.assertEqual(e["route_source"], "framework")
            self.assertTrue(e["req"]["path"].startswith("/orders/{tk1:k1:"))
            # a re_path route cannot be normalized (3.4): raw path, no framework route
            raw = env.events(lambda e: e["route_source"] == "raw")
            self.assertTrue(raw)


# Django URL configuration of the test above (ROOT_URLCONF = this module)
try:
    from django.http import JsonResponse
    from django.urls import path, re_path

    def _order_line(request, pk, n):
        return JsonResponse({"pk": pk})

    def _legacy(request, year):
        return JsonResponse({"year": year})

    urlpatterns = [path("orders/<int:pk>/lines/<int:n>/", _order_line), re_path(r"^legacy/(?P<year>[0-9]{4})/$", _legacy)]
except ImportError:
    urlpatterns = []


class AutoStartTest(unittest.TestCase):
    def test_sitecustomize_bootstrap_chains_and_starts_the_agent(self):
        core = FakeCore(shop_policy())
        state = tempfile.mkdtemp()
        other = tempfile.mkdtemp()
        marker = os.path.join(other, "marker")
        with open(os.path.join(other, "sitecustomize.py"), "w") as f:
            f.write("open(%r, 'w').write('chained')\n" % marker)
        script = ("import time, traffic_twin\n"
                  "a = traffic_twin.get_agent()\n"
                  "assert a is not None, 'agent not started'\n"
                  "end = time.time() + 20\n"
                  "while time.time() < end and a.state != 'capturing': time.sleep(0.05)\n"
                  "print(a.state)\n")
        env = dict(os.environ, PYTHONPATH=SRC + os.pathsep + other, TT_ENROLL_URL=core.url, TT_ENROLL_TOKEN=core.token,
                   TT_HMAC_KEY=HMAC_KEY, TT_SERVICE_NAME="shop-api", TT_STATE_DIR=state)
        if core.ca_file_if_needed():
            env["TT_ENROLL_CA_FILE"] = core.ca_file_if_needed()
        try:
            p = subprocess.run([sys.executable, "-m", "traffic_twin", "run", "--", sys.executable, "-c", script],
                               env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=90)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stdout.strip(), "capturing")
            self.assertTrue(os.path.exists(marker), "the application's own sitecustomize still runs")
            self.assertEqual(len(core.enrollments), 1)
        finally:
            core.close()

    def test_import_auto_never_raises_when_unconfigured(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith("TT_")}
        env["PYTHONPATH"] = SRC
        p = subprocess.run([sys.executable, "-c", "import traffic_twin.auto, traffic_twin; print(traffic_twin.status()['state'])"],
                           env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.strip(), "no_policy")


if __name__ == "__main__":
    unittest.main()
