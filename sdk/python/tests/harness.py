"""Shared test harness: a fake tt-core, an agent enrolled against it, tiny apps."""

from __future__ import annotations

import http.client
import http.server
import os
import sys
import json
import shutil
import socketserver
import tempfile
import threading
import wsgiref.simple_server
from typing import Any, Callable, Dict, List, Optional

from traffic_twin.agent import Agent, AgentOptions
from traffic_twin.jsonlex import parse_json, to_out, write_canonical
from traffic_twin.sanitizer import Sanitizer
from traffic_twin.policy import Policy, parse_key_ring, select_key

from .fakecore import HMAC_KEY, FakeCore, base_policy


def shop_policy(carrier_base: Optional[str] = None, **over: Any) -> Dict[str, Any]:
    """Invented e-commerce policy: orders inbound, a carrier API outbound."""
    keep = {"action": "keep"}
    services: List[Dict[str, Any]] = [{
        "name": "shop-api", "match": {"inbound": True, "internal": False},
        "ops": [
            {"op": "POST /orders", "response": {"body": [
                {"path": "$.id", "action": {"action": "hmac", "domain": "order"}},
                {"path": "$.status", "action": keep},
                {"path": "$.total", "action": {"action": "bucket", "kind": "num", "bounds": [0, 50, 100, 250]}}]}},
            {"op": "GET /orders/{id}", "request": {"path": {"id": {"action": "hmac", "domain": "order"}}}},
        ],
    }]
    if carrier_base:
        services.append({
            "name": "carrier", "match": {"base": carrier_base},
            "ops": [{"op": "GET /v1/shipments", "request": {"query": {"orderId": {"action": "hmac", "domain": "order"}}},
                     "response": {"body": [{"path": "$.status", "action": keep}]}},
                    {"op": "POST /v1/shipments", "request": {"body": [{"path": "$.orderId", "action": {"action": "hmac", "domain": "order"}}]},
                     "response": {"body": [{"path": "$.shipmentId", "action": {"action": "hmac", "domain": "shipment"}}]}}],
        })
    seg = {"auto_words": False, "allow": ["v1", "stream", "ignore-body", "boom", "missing", "for-sure"], "hosts_allow": []}
    over.setdefault("segments", seg)
    return base_policy(services=services, **over)


class Env:
    """``with Env(policy) as env``: fake core + enrolled agent, capturing."""

    def __init__(self, policy: Optional[Dict[str, Any]] = None, wait_capturing: bool = True, **agent_kw: Any) -> None:
        self.core = FakeCore(policy if policy is not None else shop_policy())
        self.state_dir = tempfile.mkdtemp(prefix="tt-state-")
        self.agent_kw = agent_kw
        self.wait_capturing = wait_capturing
        self.agent: Optional[Agent] = None
        if sys.version_info < (3, 10):
            # Python 3.9 cannot read the chain a server presents: enrollment then needs the root as a file.
            self.ca_path = os.path.join(self.state_dir + "-ca.pem")
            with open(self.ca_path, "w") as f:
                f.write(self.core.pki.ca_pem)
            self.agent_kw.setdefault("ca_file", self.ca_path)

    def make_agent(self) -> Agent:
        kw = dict(enroll_url=self.core.url, enroll_token=self.core.token, hmac_key=HMAC_KEY, service_name="shop-api",
                  state_dir=self.state_dir, export_flush_s=0.1, heartbeat_interval_s=0.5, policy_poll_interval_s=0.5)
        kw.update(self.agent_kw)
        return Agent(AgentOptions(**kw))

    def __enter__(self) -> "Env":
        self.agent = self.make_agent().start(wait=30)
        if self.wait_capturing:
            assert self.core.wait_for(lambda c: c.heartbeats and self.agent.state == "capturing"), self.agent.status()
        return self

    def __exit__(self, *exc: Any) -> None:
        try:
            if self.agent:
                self.agent.stop()
        finally:
            self.core.close()
            shutil.rmtree(self.state_dir, ignore_errors=True)

    def events(self, pred: Callable[[Dict[str, Any]], bool] = lambda e: True, n: int = 1, timeout: float = 10.0) -> List[Dict[str, Any]]:
        def have(c: FakeCore) -> bool:
            return len([e for e in c.events if pred(e["event"])]) >= n

        self.agent.flush()
        self.core.wait_for(have, timeout)
        return [e["event"] for e in self.core.events if pred(e["event"])]

    def token(self, domain: str, value: str) -> str:
        """The HMAC token the sanitizer must produce for (domain, value), computed on the test side."""
        p = Policy(parse_json_plain(self.core.policy_body))
        kid, key = select_key(parse_key_ring(HMAC_KEY), p)
        return Sanitizer(p, kid, key).token(domain, value.encode())


def parse_json_plain(obj: Any) -> Any:
    from traffic_twin.jsonlex import parse_plain

    return parse_plain(json.dumps(obj).encode(), True)


def is_canonical(s: str) -> bool:
    return write_canonical(to_out(parse_json(s.encode()))) == s


class QuietWSGIHandler(wsgiref.simple_server.WSGIRequestHandler):
    def log_message(self, *a: Any) -> None:
        pass


class ThreadedWSGIServer(socketserver.ThreadingMixIn, wsgiref.simple_server.WSGIServer):
    daemon_threads = True


class WsgiRunner:
    def __init__(self, app: Callable) -> None:
        self.server = wsgiref.simple_server.make_server("127.0.0.1", 0, app, server_class=ThreadedWSGIServer, handler_class=QuietWSGIHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def __enter__(self) -> "WsgiRunner":
        return self

    def __exit__(self, *a: Any) -> None:
        self.close()


def call(port: int, method: str = "GET", path: str = "/", body: Optional[bytes] = None,
         headers: Optional[Dict[str, str]] = None, host: str = "127.0.0.1"):
    """Plain client for the app under test (uses an unpatched http.client path)."""
    c = http.client.HTTPConnection(host, port, timeout=10)
    try:
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        return r.status, dict((k.lower(), v) for k, v in r.getheaders()), r.read()
    finally:
        c.close()


class UpstreamHandler(http.server.BaseHTTPRequestHandler):
    """The invented carrier API."""

    protocol_version = "HTTP/1.1"
    seen: List[Dict[str, Any]] = []

    def log_message(self, *a: Any) -> None:
        pass

    def _reply(self, status: int, obj: Any, extra: Optional[Dict[str, str]] = None) -> None:
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self.seen.append({"method": "GET", "path": self.path, "headers": dict(self.headers)})
        if self.path.startswith("/v1/shipments"):
            return self._reply(200, {"status": "IN_TRANSIT", "shipmentId": "SHP-77"})
        if self.path.startswith("/gz"):
            import gzip as _gz
            body = _gz.compress(json.dumps({"status": "GZIPPED"}).encode())
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/chunked"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for part in (b'{"status":', b'"CHUNKED"}'):
                self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
            self.wfile.write(b"0\r\n\r\n")
            return
        self._reply(404, {"error": {"code": "NOT_FOUND"}})

    def do_POST(self) -> None:
        n = int(self.headers.get("Content-Length") or 0)
        te = self.headers.get("Transfer-Encoding", "")
        if "chunked" in te.lower():
            data = b""
            while True:
                size = int(self.rfile.readline().strip() or b"0", 16)
                if size == 0:
                    self.rfile.readline()
                    break
                data += self.rfile.read(size)
                self.rfile.readline()
        else:
            data = self.rfile.read(n)
        self.seen.append({"method": "POST", "path": self.path, "headers": dict(self.headers), "body": data})
        self._reply(201, {"shipmentId": "SHP-%d" % len(data)})


class _QuietServer(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass


class Upstream:
    def __init__(self) -> None:
        UpstreamHandler.seen = []
        self.server = _QuietServer(("127.0.0.1", 0), UpstreamHandler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.base = "http://127.0.0.1:%d" % self.port
        self.seen = UpstreamHandler.seen
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def __enter__(self) -> "Upstream":
        return self

    def __exit__(self, *a: Any) -> None:
        self.close()
