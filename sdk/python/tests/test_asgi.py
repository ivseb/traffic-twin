"""ASGI capture: a tiny ASGI app driven directly, plus FastAPI/Starlette with uvicorn if installed."""

import asyncio
import json
import threading
import time
import unittest

from traffic_twin.capture.asgi import ASGIMiddleware

from .harness import Env, call, shop_policy


async def tiny_asgi(scope, receive, send):
    if scope["type"] != "http":
        return
    body = b""
    while True:
        m = await receive()
        body += m.get("body", b"")
        if not m.get("more_body"):
            break
    path = scope["path"]
    if scope["method"] == "POST" and path == "/orders":
        out = json.dumps({"id": "ORD-2026-000184", "status": "CREATED", "total": 73.4, "echo": len(body)}).encode()
        await send({"type": "http.response.start", "status": 201,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(out)).encode())]})
        await send({"type": "http.response.body", "body": out})
    elif path == "/stream":
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
        for i in range(3):
            await send({"type": "http.response.body", "body": b"part-%d;" % i, "more_body": True})
        await send({"type": "http.response.body", "body": b""})
    elif path == "/boom":
        raise RuntimeError("app failure")
    else:
        await send({"type": "http.response.start", "status": 404, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": b'{"error":{"code":"NOT_FOUND"}}'})


async def drive(app, method, path, body=b"", headers=(), query=b"", chunks=None):
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method, "scheme": "http",
             "path": path, "raw_path": path.encode(), "query_string": query, "root_path": "", "headers": list(headers),
             "server": ("127.0.0.1", 80), "client": ("127.0.0.1", 5000)}
    parts = chunks if chunks is not None else [body]
    queue = [{"type": "http.request", "body": p, "more_body": i < len(parts) - 1} for i, p in enumerate(parts)]
    sent = []

    async def receive():
        return queue.pop(0) if queue else {"type": "http.disconnect"}

    async def send(m):
        sent.append(m)

    await app(scope, receive, send)
    return sent


class AsgiCaptureTest(unittest.TestCase):
    def test_event_content_and_identical_messages(self):
        with Env() as env:
            mw = ASGIMiddleware(tiny_asgi, host=env.agent)
            hdr = [(b"content-type", b"application/json"), (b"cookie", b"sid=9f8e7d6c5b4a"), (b"x-request-id", b"req-1")]
            payload = json.dumps({"email": "giulia.neri@example.com", "items": [{"sku": "A-1", "qty": 2}]}).encode()
            ref = asyncio.run(drive(tiny_asgi, "POST", "/orders", headers=hdr, query=b"promo=AUTUMN10", chunks=[payload[:10], payload[10:]]))
            got = asyncio.run(drive(mw, "POST", "/orders", headers=hdr, query=b"promo=AUTUMN10", chunks=[payload[:10], payload[10:]]))
            self.assertEqual(got, ref)  # the app and the server see exactly the same messages
            e = env.events(lambda e: e["op"] == "POST /orders")[0]
            self.assertEqual(e["resp"]["body"]["id"], env.token("order", "ORD-2026-000184"))
            self.assertEqual(e["resp"]["body"]["total"], "num:50-100")
            self.assertEqual(e["req"]["body"]["items"], [{"qty": "drop:int", "sku": "drop:str:l8"}])
            self.assertEqual(e["req"]["size"], "l128")  # total across the two chunks
            self.assertEqual(e["req"]["cookies"], {"sid": ["drop:str:l32"]})
            self.assertEqual(e["req"]["headers"]["x-request-id"], ["drop:str:l8"])
            blob = "".join(env.core.event_strings)
            for secret in ("giulia.neri", "9f8e7d6c5b4a", "AUTUMN10", "ORD-2026-000184"):
                self.assertNotIn(secret, blob)

    def test_stream_error_and_lifespan(self):
        with Env() as env:
            mw = ASGIMiddleware(tiny_asgi, host=env.agent)
            sent = asyncio.run(drive(mw, "GET", "/stream"))
            self.assertEqual(b"".join(m.get("body", b"") for m in sent), b"part-0;part-1;part-2;")
            with self.assertRaises(RuntimeError):
                asyncio.run(drive(mw, "GET", "/boom"))
            stream = env.events(lambda e: e["op"] == "GET /stream")[0]
            self.assertEqual(stream["resp"]["size"], "l32")
            boom = env.events(lambda e: e["op"] == "GET /boom")[0]
            self.assertEqual(boom["status"], 500)
            called = []

            async def life(scope, receive, send):
                called.append(scope["type"])

            asyncio.run(ASGIMiddleware(life, host=env.agent)({"type": "lifespan"}, None, None))
            self.assertEqual(called, ["lifespan"])

    def test_context_is_bound_to_tasks(self):
        from traffic_twin import context as c

        seen = []

        async def app(scope, receive, send):
            async def inner():
                seen.append(c.current.get())
            await asyncio.create_task(inner())
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        with Env() as env:
            asyncio.run(drive(ASGIMiddleware(app, host=env.agent), "GET", "/stream"))
            self.assertEqual(len(seen), 1)
            self.assertTrue(seen[0].sampled)
            ev = env.events()[0]
            self.assertEqual(ev["trace_id"], seen[0].trace_id)

    def test_traceparent_is_read_not_injected(self):
        with Env() as env:
            tid, sid = "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"
            hdr = [(b"traceparent", ("00-%s-%s-01" % (tid, sid)).encode())]
            asyncio.run(drive(ASGIMiddleware(tiny_asgi, host=env.agent), "GET", "/stream", headers=hdr))
            ev = env.events(lambda e: e["op"] == "GET /stream")[0]
            self.assertEqual(ev["trace_id"], tid)
            self.assertEqual(ev["parent_span_id"], sid)
            self.assertNotEqual(ev["span_id"], sid)
            self.assertEqual(ev["sampled_by"], "trace")


class FastApiTest(unittest.TestCase):
    def test_fastapi_with_uvicorn(self):
        try:
            import fastapi, uvicorn  # noqa
        except ImportError:
            self.skipTest("fastapi/uvicorn not installed")
        with Env() as env:
            from fastapi import FastAPI

            app = FastAPI()

            @app.get("/orders/{order_id}")
            async def get_order(order_id: str):
                return {"id": order_id, "status": "SHIPPED"}

            @app.get("/v1/sync/{n:path}")
            def sync_route(n: str):
                return {"n": n}

            app.add_middleware(ASGIMiddleware, host=env.agent, framework="fastapi", framework_app=app)
            server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error"))
            t = threading.Thread(target=server.run, daemon=True)
            t.start()
            while not server.started:
                time.sleep(0.02)
            port = server.servers[0].sockets[0].getsockname()[1]
            try:
                st, _h, body = call(port, "GET", "/orders/ORD-5")
                self.assertEqual((st, json.loads(body)["id"]), (200, "ORD-5"))
                self.assertEqual(call(port, "GET", "/v1/sync/a/b")[0], 200)
                e = env.events(lambda e: e["op"] == "GET /orders/{id}")[0]
                self.assertEqual(e["route_source"], "framework")
                self.assertEqual(e["req"]["path"], "/orders/{%s}" % env.token("order", "ORD-5"))
                # {n:path} cannot be normalized (3.4): the sanitizer falls back to the raw path
                raw = env.events(lambda e: e["route_source"] == "raw")
                self.assertTrue(raw)
            finally:
                server.should_exit = True
                t.join(5)


if __name__ == "__main__":
    unittest.main()
