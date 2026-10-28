"""WSGI capture: a tiny WSGI app behind wsgiref, a fake tt-core with mTLS intake and Fleet."""

import json
import unittest

from traffic_twin.capture.wsgi import WSGIMiddleware

from .fakecore import base_policy
from .harness import Env, Upstream, WsgiRunner, call, is_canonical, shop_policy


def tiny_app(environ, start_response):
    method, path = environ["REQUEST_METHOD"], environ["PATH_INFO"]
    if method == "POST" and path == "/orders":
        body = environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH") or 0))
        out = json.dumps({"id": "ORD-2026-000184", "status": "CREATED", "total": 73.40, "echo": len(body)}).encode()
        start_response("201 Created", [("Content-Type", "application/json; charset=utf-8"), ("Content-Length", str(len(out))),
                                       ("Set-Cookie", "session=abc123def456; Path=/")])
        return [out]
    if method == "GET" and path.startswith("/orders/"):
        out = json.dumps({"id": path.split("/")[-1], "status": "SHIPPED"}).encode()
        start_response("200 OK", [("Content-Type", "application/json")])
        return [out]
    if path == "/stream":
        def gen():
            for i in range(3):
                yield b"line-%d\n" % i
        start_response("200 OK", [("Content-Type", "text/plain")])
        return gen()
    if path == "/boom":
        raise RuntimeError("app failure")
    if path == "/ignore-body":
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"ok"]
    start_response("404 Not Found", [("Content-Type", "application/json")])
    return [b'{"error":{"code":"NOT_FOUND"}}']


class WsgiCaptureTest(unittest.TestCase):
    def test_event_content_and_untouched_traffic(self):
        with Env() as env:
            app = WSGIMiddleware(tiny_app, host=env.agent)
            with WsgiRunner(app) as srv, WsgiRunner(tiny_app) as plain:
                payload = json.dumps({"items": [{"sku": "TSHIRT-RED-M", "qty": 2}], "email": "giulia.neri@example.com"}).encode()
                hdr = {"Content-Type": "application/json", "Cookie": "sid=9f8e7d6c5b4a"}
                got = call(srv.port, "POST", "/orders?promo=AUTUMN10", payload, hdr)
                ref = call(plain.port, "POST", "/orders?promo=AUTUMN10", payload, hdr)
                self.assertEqual(got[0], ref[0])
                self.assertEqual(got[2], ref[2])  # byte-identical response
                self.assertEqual(got[1].get("set-cookie"), ref[1].get("set-cookie"))
                evs = env.events(lambda e: e["op"] == "POST /orders")
                self.assertEqual(len(evs), 1)
                e = evs[0]
                self.assertEqual((e["dir"], e["service"], e["route_source"], e["status"]), ("inbound", "shop-api", "policy", 201))
                self.assertEqual(e["source"]["kind"], "sdk-python")
                self.assertEqual(e["resp"]["body"]["id"], env.token("order", "ORD-2026-000184"))
                self.assertEqual(e["resp"]["body"]["status"], "keep:CREATED")
                self.assertEqual(e["resp"]["body"]["total"], "num:50-100")
                self.assertEqual(e["resp"]["body"]["echo"], "drop:int")
                self.assertEqual(e["req"]["body"]["email"], "drop:str:email")
                self.assertEqual(e["req"]["body"]["items"], [{"qty": "drop:int", "sku": "drop:str:l32"}])
                self.assertEqual(e["req"]["query"], {"promo": ["drop:str:l8"]})
                self.assertEqual(e["req"]["cookies"], {"sid": ["drop:str:l32"]})
                self.assertEqual(e["resp"]["cookies"], {"session": ["drop:str:l32"]})
                self.assertEqual(e["req"]["headers"]["content-type"], ["keep:application/json"])
                self.assertEqual(e["req"]["path"], "/orders")
                self.assertEqual(len(e["trace_id"]), 32)
                self.assertEqual(len(e["span_id"]), 16)
                # the intake accepts only the canonical form
                self.assertTrue(all(is_canonical(s) for s in env.core.event_strings))
                # no input value anywhere in what left the process
                blob = "".join(env.core.event_strings)
                for secret in ("giulia.neri", "TSHIRT-RED-M", "AUTUMN10", "9f8e7d6c5b4a", "ORD-2026-000184", "abc123def456"):
                    self.assertNotIn(secret, blob)
                # OTLP mapping
                rec = env.core.events[0]["record"]
                self.assertEqual(rec["eventName"], "tt.http.exchange")
                self.assertEqual(env.core.otlp_requests[0]["resourceLogs"][0]["resource"]["attributes"][0],
                                 {"key": "service.name", "value": {"stringValue": "shop-api"}})
            self.assertEqual(env.agent.counters.get("sanitizer_errors"), 0)

    def test_path_param_template_and_streaming_and_errors(self):
        with Env() as env:
            app = WSGIMiddleware(tiny_app, host=env.agent)
            with WsgiRunner(app) as srv:
                self.assertEqual(call(srv.port, "GET", "/orders/ORD-9")[0], 200)
                st, _h, body = call(srv.port, "GET", "/stream")
                self.assertEqual(body, b"line-0\nline-1\nline-2\n")
                self.assertEqual(call(srv.port, "GET", "/missing/for-sure")[0], 404)
                call(srv.port, "GET", "/boom")  # wsgiref answers 500; the app exception must propagate unchanged
                ev = env.events(lambda e: e["op"] == "GET /orders/{id}")[0]
                self.assertEqual(ev["req"]["path"], "/orders/{%s}" % env.token("order", "ORD-9"))
                stream = env.events(lambda e: e["op"] == "GET /stream")[0]
                self.assertEqual(stream["resp"]["size"], "l32")
                self.assertEqual(stream["resp"]["body"], "drop:bytes:l32")
                miss = env.events(lambda e: e["op"].startswith("GET /missing"))[0]
                self.assertEqual(miss["status"], 404)
                self.assertEqual(miss["resp"]["body"], {"error": {"code": "drop:str:l32"}})
                boom = env.events(lambda e: e["op"] == "GET /boom")[0]
                self.assertEqual(boom["status"], 500)

    def test_unread_request_body_is_trunc_size(self):
        with Env() as env:
            app = WSGIMiddleware(tiny_app, host=env.agent)
            with WsgiRunner(app) as srv:
                call(srv.port, "POST", "/ignore-body", b'{"a":"secret-value-123"}', {"Content-Type": "application/json"})
                e = env.events(lambda e: e["op"].endswith("/ignore-body"))[0]
                self.assertEqual(e["req"]["body"], "trunc:size")
                self.assertEqual(e["req"]["size"], "lmax")

    def test_not_sampled_when_rate_is_zero(self):
        pol = shop_policy()
        pol["sampling"]["rate_bp"] = 0
        with Env(pol) as env:
            app = WSGIMiddleware(tiny_app, host=env.agent)
            with WsgiRunner(app) as srv:
                for _ in range(5):
                    call(srv.port, "GET", "/orders/ORD-1")
                env.agent.flush()
            self.assertEqual(env.core.events, [])
            self.assertEqual(env.agent.counters.get("exchanges_sampled"), 0)
            self.assertEqual(env.agent.counters.get("exchanges_seen"), 5)

    def test_subject_sampling_is_stable_per_user(self):
        import base64
        pol = shop_policy()
        pol["sampling"]["rate_bp"] = 5000
        pol["identity"] = {"subject": {"from": "header", "name": "authorization", "jwt_claim": "sub"}}
        with Env(pol) as env:
            app = WSGIMiddleware(tiny_app, host=env.agent)

            def jwt(sub):
                b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
                return "Bearer %s.%s.sig" % (b({"alg": "none"}), b({"sub": sub}))

            with WsgiRunner(app) as srv:
                users = ["user-%d" % i for i in range(40)]
                for rnd in range(2):
                    for u in users:
                        call(srv.port, "GET", "/orders/ORD-1", headers={"Authorization": jwt(u)})
                env.agent.flush()
                evs = env.events(n=1)
                from collections import Counter
                per_subject = Counter(e["subject"] for e in evs)
                # every sampled user appears in both rounds, every other user in neither
                self.assertTrue(per_subject)
                self.assertTrue(all(c == 2 for c in per_subject.values()), per_subject)
                self.assertTrue(0 < len(per_subject) < 40)
                self.assertTrue(all(e["sampled_by"] == "subject" for e in evs))

    def test_baggage_is_trusted_only_on_internal_services(self):
        for internal, want in ((True, {"1": True, "0": False}), (False, {"1": False, "0": False})):
            pol = shop_policy()
            pol["sampling"] = {"rate_bp": 0, "trust_baggage": True, "propagate_to": []}
            pol["services"][0]["match"] = {"inbound": True, "internal": internal}
            with Env(pol) as env:
                app = WSGIMiddleware(tiny_app, host=env.agent)
                with WsgiRunner(app) as srv:
                    for v in ("1", "0"):
                        call(srv.port, "GET", "/orders/ORD-%s" % v, headers={"baggage": "userId=alice, tt.s=%s;prop=x" % v})
                    env.agent.flush()
                evs = env.events(n=1, timeout=3.0 if not want["1"] else 10.0)
                if want["1"]:
                    self.assertEqual([e["req"]["path"] for e in evs], ["/orders/{%s}" % env.token("order", "ORD-1")])
                    self.assertEqual(evs[0]["sampled_by"], "baggage")
                else:  # an external client must not be able to force the capture
                    self.assertEqual(evs, [])

    def test_framework_route_flask(self):
        try:
            import flask  # noqa
        except ImportError:
            self.skipTest("flask not installed")
        from traffic_twin import install
        pol = shop_policy()
        pol["services"][0]["ops"].append({"op": "GET /v2/items/{n}", "request": {"path": {"n": {"action": "keep"}}}})
        with Env(pol) as env:
            app = flask.Flask("t")

            @app.route("/api/items/<int:item_id>")
            def item(item_id):
                return {"id": item_id}

            bp = flask.Blueprint("bp", __name__, url_prefix="/v2")

            @bp.route("/items/<int:n>")
            def item2(n):
                return {"n": n}

            app.register_blueprint(bp)
            app.wsgi_app = WSGIMiddleware(app.wsgi_app, host=env.agent, framework="flask", framework_app=app)
            with WsgiRunner(app) as srv:
                self.assertEqual(call(srv.port, "GET", "/v2/items/7")[0], 200)
                self.assertEqual(call(srv.port, "GET", "/api/items/5")[0], 200)
                e = env.events(lambda e: e["op"] == "GET /v2/items/{n}")[0]
                self.assertEqual(e["route_source"], "framework")
                self.assertEqual(e["req"]["path"], "/v2/items/{keep:7}")


if __name__ == "__main__":
    unittest.main()
