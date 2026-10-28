"""A fake tt-core intake listener for tests: Fleet source endpoints (enroll, heartbeat,
policy, renew) and OTLP/HTTP JSON intake, TLS with the root in the chain, mTLS checked on
every route except enroll. Invented data only."""

from __future__ import annotations

import gzip
import hashlib
import http.server
import json
import os
import socketserver
import ssl
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional

from traffic_twin import ed25519
from traffic_twin.jsonlex import parse_json, to_out, write_canonical
from traffic_twin.policy import b64url_nopad

from .pki import Pki

SIGNING_KID = "policy-test-1"
HMAC_KEY = "k1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"


def canonical_bytes(obj: Any) -> bytes:
    return write_canonical(to_out(parse_json(json.dumps(obj).encode()))).encode()


def iso(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def base_policy(**over: Any) -> Dict[str, Any]:
    now = time.time()
    p = {
        "format": "tt.policy.body/v1", "policy_id": "p-shop", "version": 1, "issued_seq": 1,
        "created_at": iso(now - 60), "not_after": iso(now + 30 * 86400),
        "targets": {"groups": ["shop"]},
        "hmac": {"kid": "k1", "accept_kids": [], "epoch": "2026-10"},
        "sampling": {"rate_bp": 10000, "trust_baggage": False, "propagate_to": []},
        "segments": {"auto_words": False, "allow": ["v1"], "hosts_allow": []},
        "limits": {"max_body_bytes": 1048576, "max_depth": 32, "max_array": 32, "max_keys": 256, "keep_max_bytes": 64},
        "global": {"request": {"headers": {"content-type": {"action": "keep"}}},
                   "response": {"headers": {"content-type": {"action": "keep"}}}},
        "services": [],
    }
    p.update(over)
    return p


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):  # TLS probes that never send a request
        pass


class FakeCore:
    def __init__(self, policy: Optional[Dict[str, Any]] = None, group: str = "shop") -> None:
        self.pki = Pki()
        self.signer_seed = os.urandom(32)
        self.public_key = b64url_nopad(ed25519.public_key(self.signer_seed))
        self.group = group
        self.lock = threading.Lock()
        self.events: List[Dict[str, Any]] = []
        self.event_strings: List[str] = []
        self.otlp_requests: List[Dict[str, Any]] = []
        self.heartbeats: List[Dict[str, Any]] = []
        self.enrollments: List[Dict[str, Any]] = []
        self.policy_fetches = 0
        self.kill = False
        self.min_issued_seq = 0
        self.fail_logs = 0
        self.fail_logs_status = 503
        self.sampling_override_bp: Optional[int] = None
        self.extra_heartbeat: Dict[str, Any] = {}
        self.heartbeat_status = 200
        self.policy_status = 200
        self.envelope: Optional[Dict[str, Any]] = None
        self.policy_body = policy if policy is not None else base_policy()
        self.token = "tte_" + b64url_nopad(os.urandom(24)) + "." + self.pki.pin
        self.envelope = self.make_envelope(self.policy_body) if self.policy_body else None
        self._tmp = tempfile.mkdtemp(prefix="tt-fakecore-")
        chain = os.path.join(self._tmp, "chain.pem")
        key = os.path.join(self._tmp, "key.pem")
        ca = os.path.join(self._tmp, "ca.pem")
        for path, text in ((chain, self.pki.server_chain_pem), (key, self.pki.server_key_pem), (ca, self.pki.ca_pem)):
            with open(path, "w") as f:
                f.write(text)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(chain, key)
        ctx.load_verify_locations(ca)
        ctx.verify_mode = ssl.CERT_OPTIONAL
        core = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a: Any) -> None:
                pass

            def _send(self, status: int, obj: Any = None, headers: Optional[Dict[str, str]] = None) -> None:
                body = b"" if obj is None else json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def _body(self) -> bytes:
                n = int(self.headers.get("Content-Length") or 0)
                data = self.rfile.read(n) if n else b""
                if self.headers.get("Content-Encoding") == "gzip":
                    data = gzip.decompress(data)
                return data

            def do_GET(self) -> None:
                self._route("GET")

            def do_POST(self) -> None:
                self._route("POST")

            def _route(self, method: str) -> None:
                body = self._body()
                path = self.path.split("?")[0]
                if path == "/fleet/v1/enroll" and method == "POST":
                    return self._enroll(body)
                if not self.connection.getpeercert():
                    return self._send(401, {"code": "mtls", "message": "client certificate required"})
                if path == "/fleet/v1/heartbeat" and method == "POST":
                    with core.lock:
                        core.heartbeats.append(json.loads(body))
                    if core.heartbeat_status != 200:
                        return self._send(core.heartbeat_status, {"code": "x", "message": "x"})
                    resp = {"next_heartbeat_s": 30, "kill": core.kill, "min_issued_seq": core.min_issued_seq,
                            "policy_current": ({"policy_id": core.envelope["policy_id"], "version": core.envelope["version"],
                                                "issued_seq": core.envelope["issued_seq"], "hash": core.envelope["hash"]}
                                               if core.envelope else None),
                            "sampling_override_bp": core.sampling_override_bp}
                    resp.update(core.extra_heartbeat)
                    return self._send(200, resp)
                if path == "/fleet/v1/policy" and method == "GET":
                    core.policy_fetches += 1
                    if core.policy_status != 200:
                        return self._send(core.policy_status, {"code": "x", "message": "x"})
                    if core.envelope is None:
                        return self._send(404, {"code": "none", "message": "no policy"})
                    etag = '"%s"' % core.envelope["hash"]
                    if self.headers.get("If-None-Match") == etag:
                        self.send_response(304)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    return self._send(200, core.envelope, {"ETag": etag})
                if path == "/fleet/v1/renew" and method == "POST":
                    cert, key_pem = core.pki.issue_client("src-renewed")
                    return self._send(200, {"client_cert": cert, "client_key": key_pem, "not_after": iso(time.time() + 86400)})
                if path == "/v1/logs" and method == "POST":
                    if core.fail_logs > 0:
                        core.fail_logs -= 1
                        return self._send(core.fail_logs_status, {"code": "busy"}, {"Retry-After": "0"})
                    doc = json.loads(body)
                    with core.lock:
                        core.otlp_requests.append(doc)
                        for rl in doc["resourceLogs"]:
                            for sl in rl["scopeLogs"]:
                                for lr in sl["logRecords"]:
                                    s = lr["body"]["stringValue"]
                                    core.event_strings.append(s)
                                    core.events.append({"event": json.loads(s), "record": lr, "resource": rl["resource"]})
                    return self._send(200, {})
                self._send(404, {"code": "not_found", "message": "no route"})

            def _enroll(self, body: bytes) -> None:
                j = json.loads(body)
                if j.get("token") != core.token:
                    return self._send(401, {"code": "token", "message": "unknown token"})
                core.enrollments.append(j)
                source_id = "src-" + os.urandom(6).hex()
                cert, key_pem = core.pki.issue_client(source_id)
                base = "https://127.0.0.1:%d" % core.port
                self._send(201, {
                    "source_id": source_id, "group": core.group, "service_name": j["source"]["service_name"],
                    "client_cert": cert, "client_key": key_pem, "ca_chain": core.pki.ca_pem,
                    "policy_signing_keys": [{"kid": SIGNING_KID, "alg": "Ed25519", "public_key": core.public_key}],
                    "intake_url": base + "/v1/logs", "fleet_url": base, "policy_max_age_s": 86400,
                    "heartbeat_interval_s": 30, "policy_poll_interval_s": 60})

        self.server = _Server(("127.0.0.1", 0), Handler)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.url = "https://127.0.0.1:%d" % self.port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def ca_file_if_needed(self):
        """Path of the root CA PEM for interpreters that cannot read the presented chain (Python 3.9), else None."""
        import sys
        if sys.version_info >= (3, 10):
            return None
        return os.path.join(self._tmp, "ca.pem")

    def make_envelope(self, body: Dict[str, Any], kid: str = SIGNING_KID, seed: Optional[bytes] = None) -> Dict[str, Any]:
        raw = canonical_bytes(body)
        sig = ed25519.sign(seed or self.signer_seed, b"tt.policy.body/v1\x00" + raw)
        return {"format": "tt.policy.compiled/v1", "policy_id": body["policy_id"], "version": body["version"],
                "issued_seq": body["issued_seq"], "hash": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "body_b64": b64url_nopad(raw), "signature": {"alg": "Ed25519", "kid": kid, "sig": b64url_nopad(sig)}}

    def set_policy(self, body: Optional[Dict[str, Any]], bump: bool = True) -> None:
        """Publishes a policy; ``issued_seq`` and ``version`` grow unless ``bump`` is False."""
        if body and bump:
            cur = self.policy_body["issued_seq"] if self.policy_body else 0
            body = dict(body, issued_seq=cur + 1, version=cur + 1)
        self.policy_body = body
        self.envelope = self.make_envelope(body) if body else None

    def wait_for(self, pred, timeout: float = 15.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            if pred(self):
                return True
            time.sleep(0.02)
        return False

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        import shutil

        shutil.rmtree(self._tmp, ignore_errors=True)
