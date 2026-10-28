"""Fleet API client (api/fleet-api.v1.openapi.yaml): enrollment with a ``tte_`` token and CA
pin, then mTLS calls for heartbeat, policy and certificate renewal.

The standard library cannot build a PKCS#10 CSR, so enrollment always uses the no-CSR
path of the API: tt-core generates the key pair, returns ``client_key`` once over the
pinned TLS channel and does not persist it; the SDK keeps it in a 0600 file.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import re
import socket
import ssl
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from . import context as ctxmod

TOKEN_RE = re.compile(r"tte_[A-Za-z0-9_-]{32,128}\.([A-Za-z0-9_-]{43})")
_SRC_ID = re.compile(r"src-[0-9A-Za-z]{1,32}")
_GROUP = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
_SVC = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}")
_KID = re.compile(r"[A-Za-z0-9._-]{1,64}")
_PUB = re.compile(r"[A-Za-z0-9_-]{43}")
_PEM_BLOCK = re.compile(r"-----BEGIN ([A-Z ]+)-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END \1-----")


class FleetError(Exception):
    def __init__(self, code: str, status: Optional[int] = None) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def pem_blocks(text: str, label: str) -> List[bytes]:
    """DER bytes of every PEM block with the given label."""
    out = []
    for m in _PEM_BLOCK.finditer(text or ""):
        if m.group(1) == label:
            try:
                out.append(base64.b64decode(re.sub(r"\s+", "", m.group(2)), validate=True))
            except ValueError:
                pass
    return out


def to_pem(label: str, der: bytes) -> str:
    b = base64.b64encode(der).decode("ascii")
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, "\n".join(b[i:i + 64] for i in range(0, len(b), 64)), label)


def pin_of(der: bytes) -> str:
    """base64url(SHA-256(DER of the root certificate)), no padding."""
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode("ascii")


def token_pin(token: str) -> Optional[str]:
    m = TOKEN_RE.fullmatch(token or "")
    return m.group(1) if m else None


def _chain_der(sock: ssl.SSLSocket) -> List[bytes]:
    """The certificate chain the server presented (DER), without verifying it."""
    f = getattr(sock, "get_unverified_chain", None)  # Python 3.13+
    obj = sock
    if f is None:
        obj = getattr(sock, "_sslobj", None)  # Python 3.10-3.12 (private)
        f = getattr(obj, "get_unverified_chain", None)
    if f is None:
        return []
    out: List[bytes] = []
    for c in f() or []:
        if isinstance(c, (bytes, bytearray)):
            out.append(bytes(c))
        else:
            try:
                import _ssl  # type: ignore

                out.append(c.public_bytes(_ssl.ENCODING_DER))
            except Exception:
                pass
    return out


def _host_port(url: urllib.parse.SplitResult) -> Tuple[str, int]:
    host = url.hostname or ""
    return host, url.port or 443


def fetch_pinned_root(url: str, pin: str, timeout: float = 10.0, ca_file: Optional[str] = None) -> str:
    """Opens a TLS connection without trusting anything, searches the chain the server
    presents for the certificate whose SHA-256 is the pin and returns it as PEM, to be
    used as the only trust anchor for the real request.

    Python 3.9 cannot read the presented chain: pass ``ca_file`` (a PEM with the root) and
    only the pin is checked.
    """
    if ca_file:
        try:
            with open(ca_file, "r", encoding="utf-8") as f:
                for der in pem_blocks(f.read(), "CERTIFICATE"):
                    if pin_of(der) == pin:
                        return to_pem("CERTIFICATE", der)
        except OSError:
            pass
        raise FleetError("enroll_pin_mismatch")
    u = urllib.parse.urlsplit(url)
    host, port = _host_port(u)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host if not _is_ip(host) else None) as s:
                chain = _chain_der(s)
    except socket.timeout:
        raise FleetError("enroll_tls_timeout") from None
    except (OSError, ssl.SSLError):
        raise FleetError("enroll_tls_error") from None
    if not chain:
        raise FleetError("enroll_chain_unavailable")
    for der in chain:
        if pin_of(der) == pin:
            return to_pem("CERTIFICATE", der)
    raise FleetError("enroll_pin_mismatch")


def _is_ip(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except OSError:
        return False


def client_context(ca_pem: str, cert_file: Optional[str] = None, key_file: Optional[str] = None) -> ssl.SSLContext:
    """TLS client context trusting only ``ca_pem``; with a certificate it is an mTLS context."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cadata=ca_pem)
    if cert_file and key_file:
        ctx.load_cert_chain(cert_file, key_file)
    return ctx


class HttpResult:
    __slots__ = ("status", "headers", "body")

    def __init__(self, status: int, headers: Dict[str, str], body: bytes) -> None:
        self.status = status
        self.headers = headers
        self.body = body

    def json(self) -> Any:
        try:
            return json.loads(self.body.decode("utf-8"))
        except ValueError:
            return None


class HttpsClient:
    """Minimal HTTPS client (one connection, kept alive, reopened on error) used by the
    exporter and the Fleet client. Requests made here are never captured."""

    def __init__(self, base_url: str, ctx: ssl.SSLContext, timeout: float = 15.0) -> None:
        u = urllib.parse.urlsplit(base_url)
        if u.scheme != "https":
            raise FleetError("https_required")
        self.host, self.port = _host_port(u)
        self.base_path = u.path.rstrip("/")
        self.ctx = ctx
        self.timeout = timeout
        self._conn: Optional[http.client.HTTPSConnection] = None
        self._dead = False

    def shutdown(self) -> None:
        """Closes for good: a late request from a thread that is still winding down fails
        instead of opening a new connection."""
        self._dead = True
        self.close()

    def close(self) -> None:
        c, self._conn = self._conn, None
        if c is not None:
            try:
                c.close()
            except Exception:
                pass

    def request(self, method: str, path: str, headers: Optional[Dict[str, str]] = None,
                body: Optional[bytes] = None, max_response: int = 1 << 20, absolute: bool = False) -> HttpResult:
        for attempt in (0, 1):
            if self._dead:
                raise OSError("client closed")
            if self._conn is None:
                self._conn = http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=self.timeout)
            conn = self._conn
            try:
                conn.request(method, path if absolute else self.base_path + path, body=body, headers=headers or {})
                resp = conn.getresponse()
                data = resp.read(max_response + 1)
                if len(data) > max_response:
                    data = data[:max_response]
                    self.close()
                hdrs = {k.lower(): v for k, v in resp.getheaders()}
                if hdrs.get("connection", "").lower() == "close":
                    self.close()
                return HttpResult(resp.status, hdrs, data)
            except (http.client.HTTPException, ConnectionError, ssl.SSLError, socket.timeout, OSError):
                self.close()
                if attempt == 1:
                    raise
                # a kept-alive connection may have been closed by the server: retry once
        raise OSError("unreachable")  # pragma: no cover


def _https_url(v: Any) -> bool:
    try:
        return isinstance(v, str) and urllib.parse.urlsplit(v).scheme == "https" and bool(urllib.parse.urlsplit(v).hostname)
    except ValueError:
        return False


def parse_enrollment(j: Any, pin: str, enroll_url: str) -> Dict[str, Any]:
    """Validates the enrollment response and returns the record kept in the state dir."""
    if not isinstance(j, dict):
        raise FleetError("enroll_bad_response")
    keys = []
    for k in j.get("policy_signing_keys") or []:
        if (isinstance(k, dict) and isinstance(k.get("kid"), str) and _KID.fullmatch(k["kid"]) and k.get("alg") == "Ed25519"
                and isinstance(k.get("public_key"), str) and _PUB.fullmatch(k["public_key"])):
            keys.append({"kid": k["kid"], "alg": "Ed25519", "public_key": k["public_key"]})

    def num(name: str, d: int) -> int:
        v = j.get(name)
        return v if isinstance(v, int) and not isinstance(v, bool) and v > 0 else d

    e = {
        "source_id": str(j.get("source_id", "")),
        "group": str(j.get("group", "")),
        "service_name": str(j.get("service_name", "")),
        "client_cert": str(j.get("client_cert", "")),
        "ca_chain": str(j.get("ca_chain", "")),
        "not_after": j.get("not_after") if isinstance(j.get("not_after"), str) else None,
        "policy_signing_keys": keys,
        "intake_url": str(j.get("intake_url", "")),
        "fleet_url": str(j.get("fleet_url", "")),
        "policy_max_age_s": num("policy_max_age_s", 86400),
        "heartbeat_interval_s": num("heartbeat_interval_s", 30),
        "policy_poll_interval_s": num("policy_poll_interval_s", 60),
        "enroll_url": enroll_url,
        "pin": pin,
    }
    if not _SRC_ID.fullmatch(e["source_id"]):
        raise FleetError("enroll_bad_source_id")
    if not _GROUP.fullmatch(e["group"]):
        raise FleetError("enroll_bad_group")
    if not _SVC.fullmatch(e["service_name"]):
        raise FleetError("enroll_bad_service_name")
    if not pem_blocks(e["client_cert"], "CERTIFICATE"):
        raise FleetError("enroll_bad_cert")
    if not any(pin_of(d) == pin for d in pem_blocks(e["ca_chain"], "CERTIFICATE")):
        raise FleetError("enroll_chain_without_pinned_root")
    if not keys:
        raise FleetError("enroll_no_signing_keys")
    if not _https_url(e["intake_url"]) or not _https_url(e["fleet_url"]):
        raise FleetError("enroll_bad_urls")
    return e


def enroll(enroll_url: str, token: str, source: Dict[str, Any], timeout: float = 15.0,
           ca_file: Optional[str] = None) -> Tuple[Dict[str, Any], str]:
    """Enrolls with a token. Returns ``(enrollment record, private key PEM)``."""
    tok = ctxmod.internal.set(True)  # this request is never captured, whoever calls it
    try:
        return _enroll(enroll_url, token, source, timeout, ca_file)
    finally:
        ctxmod.internal.reset(tok)


def _enroll(enroll_url: str, token: str, source: Dict[str, Any], timeout: float,
            ca_file: Optional[str]) -> Tuple[Dict[str, Any], str]:
    pin = token_pin(token)
    if not pin:
        raise FleetError("enroll_token_malformed")
    u = urllib.parse.urlsplit(enroll_url)
    if u.scheme != "https" or not u.hostname:
        raise FleetError("enroll_url_not_https")
    root_pem = fetch_pinned_root(enroll_url, pin, timeout, ca_file)
    client = HttpsClient(enroll_url, client_context(root_pem), timeout)
    body = json.dumps({"token": token, "source": source}).encode("utf-8")
    try:
        res = client.request("POST", "/fleet/v1/enroll", {"Content-Type": "application/json"}, body)
    except (OSError, http.client.HTTPException):
        raise FleetError("enroll_network") from None
    finally:
        client.close()
    if res.status not in (200, 201):
        raise FleetError("enroll_http_%d" % res.status, res.status)
    j = res.json()
    if not isinstance(j, dict):
        raise FleetError("enroll_bad_response")
    key_pem = j.get("client_key")
    if not isinstance(key_pem, str) or "PRIVATE KEY" not in key_pem:
        raise FleetError("enroll_no_key")
    return parse_enrollment(j, pin, enroll_url), key_pem


class FleetClient:
    """mTLS calls: heartbeat, policy, renewal."""

    def __init__(self, fleet_url: str, ctx: ssl.SSLContext) -> None:
        self.http = HttpsClient(fleet_url, ctx, 15.0)

    def close(self) -> None:
        self.http.close()

    def shutdown(self) -> None:
        self.http.shutdown()

    def heartbeat(self, body: Dict[str, Any]) -> Tuple[int, Optional[Dict[str, Any]]]:
        r = self.http.request("POST", "/fleet/v1/heartbeat", {"Content-Type": "application/json"},
                              json.dumps(body, separators=(",", ":")).encode("utf-8"))
        j = r.json() if r.status == 200 else None
        return r.status, j if isinstance(j, dict) else None

    def get_policy(self, etag: Optional[str]) -> HttpResult:
        h = {"If-None-Match": etag} if etag else {}
        return self.http.request("GET", "/fleet/v1/policy", h, None, max_response=8 << 20)

    def renew(self) -> Optional[Dict[str, Any]]:
        r = self.http.request("POST", "/fleet/v1/renew", {"Content-Type": "application/json"}, b"{}")
        if r.status != 200:
            return None
        j = r.json()
        if not isinstance(j, dict) or not isinstance(j.get("client_cert"), str) or not isinstance(j.get("client_key"), str):
            return None
        return j
