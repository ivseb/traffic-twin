"""Outbound capture: urllib handler, requests adapter, httpx transports, the opt-in
http.client patch (and that it is reversible), correlation with the inbound exchange."""

import asyncio
import http.client
import json
import socket
import unittest
import urllib.request

from traffic_twin import context as ctxmod
from traffic_twin.capture import outbound as ob
from traffic_twin.capture.wsgi import WSGIMiddleware

from .harness import Env, Upstream, WsgiRunner, call, shop_policy


def outbound(e):
    return e["dir"] == "outbound"


class OutboundBase(unittest.TestCase):
    def setUp(self):
        self.up = Upstream()
        self.env = Env(shop_policy(carrier_base=self.up.base)).__enter__()
        self.addCleanup(self.up.close)
        self.addCleanup(self.env.__exit__, None, None, None)

    def one(self, pred=lambda e: True):
        evs = self.env.events(lambda e: outbound(e) and pred(e))
        self.assertEqual(len(evs), 1, evs)
        return evs[0]

    def check_get_shipments(self, e, with_header=None):
        self.assertEqual((e["service"], e["op"], e["status"], e["route_source"]), ("carrier", "GET /v1/shipments", 200, "policy"))
        self.assertEqual(e["req"]["query"], {"orderId": [self.env.token("order", "ORD-2026-000184")]})
        self.assertEqual(e["resp"]["body"], {"shipmentId": "drop:str:l8", "status": "keep:IN_TRANSIT"})
        self.assertEqual(e["sampled_by"], "random")
        blob = "".join(self.env.core.event_strings)
        self.assertNotIn("ORD-2026-000184", blob)
        self.assertNotIn("SHP-77", blob)


class UrllibTest(OutboundBase):
    def test_handler(self):
        opener = urllib.request.build_opener(ob.make_urllib_handler(self.env.agent)())
        with opener.open(self.up.base + "/v1/shipments?orderId=ORD-2026-000184") as r:
            self.assertEqual(json.loads(r.read())["status"], "IN_TRANSIT")
        self.check_get_shipments(self.one())

    def test_http_error_is_captured_with_its_body(self):
        opener = urllib.request.build_opener(ob.make_urllib_handler(self.env.agent)())
        with self.assertRaises(urllib.error.HTTPError) as cm:
            opener.open(self.up.base + "/v1/nothing")
        self.assertEqual(json.loads(cm.exception.read())["error"]["code"], "NOT_FOUND")
        e = self.one()
        self.assertEqual(e["status"], 404)

    def test_global_install_is_reversible(self):
        before = getattr(urllib.request, "_opener", None)
        undo = ob.install_urllib(self.env.agent)
        try:
            urllib.request.urlopen(self.up.base + "/v1/shipments?orderId=ORD-2026-000184").read()
        finally:
            undo()
        self.assertIs(getattr(urllib.request, "_opener", None), before)
        self.check_get_shipments(self.one())


class HttpClientTest(OutboundBase):
    def setUp(self):
        super().setUp()
        self.orig = {n: getattr(http.client.HTTPConnection, n) for n in ("putrequest", "putheader", "endheaders", "send", "getresponse")}
        self.undo = ob.install_http_client(self.env.agent)
        self.addCleanup(self.restore)

    def restore(self):
        self.undo()

    def conn(self):
        return http.client.HTTPConnection("127.0.0.1", self.up.port, timeout=10)

    def test_get_and_reversibility(self):
        c = self.conn()
        c.request("GET", "/v1/shipments?orderId=ORD-2026-000184", headers={"Accept": "application/json"})
        r = c.getresponse()
        self.assertEqual(json.loads(r.read())["shipmentId"], "SHP-77")
        c.close()
        e = self.one()
        self.check_get_shipments(e)
        self.assertEqual(e["req"]["headers"]["accept"], ["drop:str:l32"])
        self.assertIn("host", e["req"]["headers"])  # headers as sent on the wire, not only the ones the caller set
        self.undo()
        for n, f in self.orig.items():
            self.assertIs(getattr(http.client.HTTPConnection, n), f, n)
        self.undo = lambda: None

    def test_post_with_content_length(self):
        body = json.dumps({"orderId": "ORD-2026-000184", "note": "fragile"}).encode()
        c = self.conn()
        c.request("POST", "/v1/shipments", body=body, headers={"Content-Type": "application/json"})
        c.getresponse().read()
        c.close()
        e = self.one(lambda e: e["op"] == "POST /v1/shipments")
        self.assertEqual(e["req"]["body"], {"note": "drop:str:l8", "orderId": self.env.token("order", "ORD-2026-000184")})
        self.assertEqual(e["status"], 201)
        self.assertEqual(self.up.seen[-1]["body"], body)  # the upstream received exactly the bytes

    def test_post_chunked_request_body(self):
        parts = [b'{"orderId":"ORD-2026-', b'000184"}']
        c = self.conn()
        c.request("POST", "/v1/shipments", body=iter(parts), headers={"Content-Type": "application/json", "Transfer-Encoding": "chunked"}, encode_chunked=True)
        c.getresponse().read()
        c.close()
        e = self.one(lambda e: e["op"] == "POST /v1/shipments")
        self.assertEqual(e["req"]["body"], {"orderId": self.env.token("order", "ORD-2026-000184")})
        self.assertEqual(self.up.seen[-1]["body"], b"".join(parts))

    def test_gzip_and_chunked_responses(self):
        for path, want in (("/gz", "GZIPPED"), ("/chunked", "CHUNKED")):
            c = self.conn()
            c.request("GET", path)
            raw = c.getresponse().read()
            c.close()
            self.assertTrue(raw)
        evs = self.env.events(outbound, n=2)
        self.assertEqual(len(evs), 2)
        for e in evs:
            self.assertEqual(e["resp"]["body"], {"status": "drop:str:l8"})  # decoded gzip / de-chunked body

    def test_body_not_read_is_not_consumed(self):
        c = self.conn()
        c.request("GET", "/v1/shipments?orderId=X")
        r = c.getresponse()
        r.close()
        c.close()
        e = self.one()
        self.assertEqual(e["resp"]["body"], "trunc:size")

    def test_connection_refused_is_a_net_error(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.env.core.set_policy(shop_policy(carrier_base="http://127.0.0.1:%d" % port))
        self.env.core.wait_for(lambda c: False, 1.5)  # next policy poll (0.5 s)
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        with self.assertRaises(ConnectionRefusedError):
            c.request("GET", "/v1/shipments?orderId=Y")
        e = self.one()
        self.assertEqual((e["net_error"], e.get("status"), "resp" in e), ("refused", None, False))

    def test_internal_traffic_is_never_captured(self):
        # the exporter and the Fleet client use http.client while the patch is on
        c = self.conn()
        c.request("GET", "/v1/shipments?orderId=ORD-2026-000184")
        c.getresponse().read()
        c.close()
        self.env.events(outbound)
        self.env.core.wait_for(lambda c: len(c.heartbeats) >= 3, 5)
        self.env.agent.flush()
        self.assertTrue(all(e["event"]["service"] == "carrier" for e in self.env.core.events), [e["event"]["service"] for e in self.env.core.events])


class InboundCorrelationTest(OutboundBase):
    def test_outbound_shares_trace_and_inherits_sampling(self):
        undo = ob.install_http_client(self.env.agent)
        self.addCleanup(undo)

        def app(environ, start_response):
            c = http.client.HTTPConnection("127.0.0.1", self.up.port)
            c.request("GET", "/v1/shipments?orderId=ORD-2026-000184")
            c.getresponse().read()
            c.close()
            start_response("200 OK", [("Content-Type", "application/json")])
            return [b'{"ok":true}']

        with WsgiRunner(WSGIMiddleware(app, host=self.env.agent)) as srv:
            call(srv.port, "GET", "/orders/ORD-1")
        evs = self.env.events(n=2)
        inb = [e for e in evs if e["dir"] == "inbound"][0]
        out = [e for e in evs if e["dir"] == "outbound"][0]
        self.assertEqual(out["trace_id"], inb["trace_id"])
        self.assertEqual(out["parent_span_id"], inb["span_id"])
        self.assertEqual(out["sampled_by"], "inherited")
        # tt does not add traceparent to the app's calls
        self.assertNotIn("traceparent", {k.lower() for k in self.up.seen[-1]["headers"]})

    def test_not_sampled_inbound_means_not_captured_outbound(self):
        pol = shop_policy(carrier_base=self.up.base)
        pol["sampling"]["rate_bp"] = 0
        self.env.core.set_policy(pol)
        self.env.core.wait_for(lambda c: False, 1.5)
        undo = ob.install_http_client(self.env.agent)
        self.addCleanup(undo)

        def app(environ, start_response):
            c = http.client.HTTPConnection("127.0.0.1", self.up.port)
            c.request("GET", "/v1/shipments?orderId=Z")
            c.getresponse().read()
            c.close()
            start_response("200 OK", [])
            return [b""]

        with WsgiRunner(WSGIMiddleware(app, host=self.env.agent)) as srv:
            call(srv.port, "GET", "/orders/ORD-1")
        self.env.agent.flush()
        self.assertEqual(self.env.core.events, [])

    def test_baggage_only_to_declared_internal_hosts_never_to_policy_bases(self):
        pol = shop_policy(carrier_base=self.up.base)
        pol["sampling"]["propagate_to"] = ["localhost", "127.0.0.1"]
        self.env.core.set_policy(pol)
        self.env.core.wait_for(lambda c: False, 1.5)
        opener = urllib.request.build_opener(ob.make_urllib_handler(self.env.agent)())

        def app(environ, start_response):
            opener.open(self.up.base + "/v1/shipments?orderId=Z").read()           # external base: never
            opener.open("http://localhost:%d/other" % self.up.port).read() if False else None
            try:
                opener.open("http://localhost:%d/v1/x" % self.up.port).read()      # declared internal host
            except Exception:
                pass
            start_response("200 OK", [])
            return [b""]

        with WsgiRunner(WSGIMiddleware(app, host=self.env.agent)) as srv:
            call(srv.port, "GET", "/orders/ORD-1")
        by_path = {s["path"]: {k.lower(): v for k, v in s["headers"].items()} for s in self.up.seen}
        self.assertNotIn("baggage", by_path["/v1/shipments?orderId=Z"])
        if "/v1/x" in by_path:
            self.assertEqual(by_path["/v1/x"].get("baggage"), "tt.s=1")


try:
    import requests  # noqa: F401
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False


@unittest.skipUnless(HAVE_REQUESTS, "requests not installed")
class RequestsTest(OutboundBase):
    def test_adapter(self):
        s = requests.Session()
        s.mount("http://", ob.make_requests_adapter(self.env.agent)())
        r = s.get(self.up.base + "/v1/shipments", params={"orderId": "ORD-2026-000184"})
        self.assertEqual(r.json()["status"], "IN_TRANSIT")
        self.check_get_shipments(self.one())

    def test_adapter_gzip_response_decoded_by_requests_is_still_one_event(self):
        s = requests.Session()
        s.mount("http://", ob.make_requests_adapter(self.env.agent)())
        self.assertEqual(s.get(self.up.base + "/gz").json(), {"status": "GZIPPED"})
        e = self.one()
        self.assertEqual(e["resp"]["body"], {"status": "drop:str:l8"})

    def test_global_install_and_no_double_capture_with_http_client_patch(self):
        undo_hc = ob.install_http_client(self.env.agent)
        undo_rq = ob.install_requests(self.env.agent)
        try:
            requests.get(self.up.base + "/v1/shipments", params={"orderId": "ORD-2026-000184"})
            requests.post(self.up.base + "/v1/shipments", json={"orderId": "ORD-2026-000184"})
        finally:
            undo_rq()
            undo_hc()
        evs = self.env.events(outbound, n=2)
        self.assertEqual(sorted(e["op"] for e in evs), ["GET /v1/shipments", "POST /v1/shipments"])
        self.assertFalse(requests.Session().adapters["http://"].__class__.__name__ == "TrafficTwinAdapter")

    def test_connection_error(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.env.core.set_policy(shop_policy(carrier_base="http://127.0.0.1:%d" % port))
        self.env.core.wait_for(lambda c: False, 1.5)
        sess = requests.Session()
        sess.mount("http://", ob.make_requests_adapter(self.env.agent)())
        with self.assertRaises(requests.ConnectionError):
            sess.get("http://127.0.0.1:%d/v1/shipments" % port, params={"orderId": "q"})
        self.assertEqual(self.one()["net_error"], "refused")


try:
    import httpx  # noqa: F401
    HAVE_HTTPX = True
except ImportError:
    HAVE_HTTPX = False


@unittest.skipUnless(HAVE_HTTPX, "httpx not installed")
class HttpxTest(OutboundBase):
    def test_sync_transport(self):
        T, _A = ob.make_httpx_transports(self.env.agent)
        with httpx.Client(transport=T(httpx.HTTPTransport())) as c:
            r = c.get(self.up.base + "/v1/shipments", params={"orderId": "ORD-2026-000184"})
            self.assertEqual(r.json()["status"], "IN_TRANSIT")
            c.post(self.up.base + "/v1/shipments", json={"orderId": "ORD-2026-000184"})
        evs = self.env.events(outbound, n=2)
        get = [e for e in evs if e["op"] == "GET /v1/shipments"][0]
        self.check_get_shipments(get)
        post = [e for e in evs if e["op"] == "POST /v1/shipments"][0]
        self.assertEqual(post["req"]["body"], {"orderId": self.env.token("order", "ORD-2026-000184")})

    def test_async_transport_and_streamed_gzip(self):
        _T, A = ob.make_httpx_transports(self.env.agent)

        async def run():
            async with httpx.AsyncClient(transport=A(httpx.AsyncHTTPTransport())) as c:
                r = await c.get(self.up.base + "/v1/shipments", params={"orderId": "ORD-2026-000184"})
                self.assertEqual(r.json()["status"], "IN_TRANSIT")
                g = await c.get(self.up.base + "/gz")
                self.assertEqual(g.json(), {"status": "GZIPPED"})

        asyncio.run(run())
        evs = self.env.events(outbound, n=2)
        self.assertEqual(len(evs), 2)
        gz = [e for e in evs if e["op"].startswith("GET /{")][0]
        self.assertEqual(gz["resp"]["body"], {"status": "drop:str:l8"})  # encoded bytes, decoded by the sanitizer

    def test_global_install_reversible(self):
        orig_s, orig_a = httpx.HTTPTransport.handle_request, httpx.AsyncHTTPTransport.handle_async_request
        undo = ob.install_httpx(self.env.agent)
        try:
            httpx.get(self.up.base + "/v1/shipments", params={"orderId": "ORD-2026-000184"})
            asyncio.run(self._aget())
        finally:
            undo()
        self.assertIs(httpx.HTTPTransport.handle_request, orig_s)
        self.assertIs(httpx.AsyncHTTPTransport.handle_async_request, orig_a)
        self.assertEqual(len(self.env.events(outbound, n=2)), 2)

    async def _aget(self):
        async with httpx.AsyncClient() as c:
            await c.get(self.up.base + "/v1/shipments", params={"orderId": "ORD-2026-000184"})

    def test_connect_error(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.env.core.set_policy(shop_policy(carrier_base="http://127.0.0.1:%d" % port))
        self.env.core.wait_for(lambda c: False, 1.5)
        T, _A = ob.make_httpx_transports(self.env.agent)
        with httpx.Client(transport=T(httpx.HTTPTransport())) as c:
            with self.assertRaises(httpx.ConnectError):
                c.get("http://127.0.0.1:%d/v1/shipments?orderId=q" % port)
        self.assertEqual(self.one()["net_error"], "refused")


if __name__ == "__main__":
    unittest.main()
