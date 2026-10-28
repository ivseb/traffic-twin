"""Outbound capture: one recorder (``OutboundCall``) and the client hooks that feed it.

Extension points first, no global patching:

* ``requests``: ``TrafficTwinAdapter`` (a transport adapter, ``session.mount``);
* ``httpx``: ``TrafficTwinTransport`` / ``AsyncTrafficTwinTransport`` (client ``transport=``);
* ``urllib``: ``TrafficTwinHandler`` (``urllib.request.build_opener``).

Where an application builds clients it does not control, a patch is unavoidable. Patches
are **opt-in** (``TT_OUTBOUND`` / ``start(outbound=...)``) and **reversible** (every
``install_*`` returns the function that restores the originals): ``requests`` (new
``Session`` objects get the adapter), ``httpx`` (the default transports), ``urllib`` (the
default opener, an official API) and ``http.client`` (the lowest level, which also covers
``urllib3``). When two layers see the same call (for instance the requests adapter and the
``http.client`` patch) only the outer one records it: it sets the ``suppress`` context
variable.

None of these hooks changes a byte, a header or a timing of the call, except the optional
``tt.s`` baggage member towards the hosts of ``sampling.propagate_to`` (sanitizer.md 12).
"""

from __future__ import annotations

import http.client
import re
import sys
import time
import weakref
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from .. import context as ctxmod
from .._log import debug
from ..sanitizer import Decision, Exchange
from .common import BodyTap, RawExchange, latin1, net_error_of, split_target, with_tt_s

_NO_BODY_STATUS = frozenset([204, 304])


class OutboundCall:
    """One outbound exchange being recorded. ``finish`` is idempotent."""

    __slots__ = (
        "host", "san", "decision", "method", "url_base", "raw_path", "raw_query", "req_headers", "req_tap", "res_tap",
        "req_unknown", "status", "resp_headers", "ts_ms", "t0", "trace_id", "trace_known", "span_id", "parent_span",
        "done", "overhead_ns", "chunked", "dechunk", "__weakref__",
    )

    def __init__(self, host: Any, san: Any, decision: Decision, method: str, url_base: str, raw_path: bytes,
                 raw_query: Optional[bytes], trace_id: str, trace_known: bool, parent_span: Optional[str]) -> None:
        limit = san.policy.capture_limit  # max(max_body_bytes, bodies.max_large_body_bytes) + 1 (9.0, 22.5)
        self.host = host
        self.san = san
        self.decision = decision
        self.method = method
        self.url_base = url_base
        self.raw_path = raw_path
        self.raw_query = raw_query
        self.req_headers: List[Tuple[str, bytes]] = []
        self.req_tap = BodyTap(limit)
        self.res_tap = BodyTap(limit)
        self.req_unknown = False
        self.status: Optional[int] = None
        self.resp_headers: List[Tuple[str, bytes]] = []
        self.ts_ms = int(time.time() * 1000)
        self.t0 = time.perf_counter()
        self.trace_id = trace_id
        self.trace_known = trace_known
        self.span_id = ctxmod.new_span_id()
        self.parent_span = parent_span
        self.done = False
        self.overhead_ns = 0
        self.chunked = False
        self.dechunk: Optional["_ChunkDecoder"] = None

    # --- request side --------------------------------------------------------------

    def add_header(self, name: Any, value: Any) -> None:
        self.req_headers.append((name.decode("latin-1") if isinstance(name, (bytes, bytearray)) else str(name), latin1(value)))

    def set_request_body(self, body: Any) -> None:
        """``bytes``/``str`` bodies are copied; anything else (a stream) is not read: its
        length is unknown (``trunc:size``), the traffic is never touched."""
        if body is None:
            self.req_tap.ended = True
        elif isinstance(body, (bytes, bytearray, memoryview, str)):
            self.req_tap.add(body)
            self.req_tap.ended = True
        else:
            self.req_unknown = True

    # --- finishing -----------------------------------------------------------------

    def finish(self, net_error: Optional[str] = None, consumed: bool = True) -> None:
        if self.done:
            return
        self.done = True
        t_out = time.perf_counter_ns()
        try:
            self._submit(net_error, consumed)
        except Exception:
            self.host.note_error("capture_outbound_finish")
        self.host.note_overhead(self.overhead_ns + (time.perf_counter_ns() - t_out))

    def finish_abandoned(self) -> None:
        """Called by a finalizer when the caller dropped the exchange without finishing it."""
        if not self.done:
            if self.status is None:
                self.finish(net_error="other")
            else:
                self.finish(consumed=False)

    def _submit(self, net_error: Optional[str], consumed: bool) -> None:
        status = self.status
        if net_error is None and status is None:
            net_error = "other"
        if net_error is not None:
            status = None
        latency_ms = max(0, int((time.perf_counter() - self.t0) * 1000))
        method = self.method
        no_body = method == "HEAD" or (status is not None and (status in _NO_BODY_STATUS or 100 <= status < 200))
        req_tap, res_tap = self.req_tap, self.res_tap
        req_body = req_tap.bytes()
        req_total: Any = "unknown" if self.req_unknown or not req_tap.ended and req_tap.total > 0 else req_tap.total
        res_body = b"" if no_body else res_tap.bytes()
        res_total: Any = 0 if no_body else res_tap.total
        if not no_body and not consumed:
            res_total = "unknown"
        d = self
        url_base, raw_path, raw_query = self.url_base, self.raw_path, self.raw_query
        req_headers, resp_headers = self.req_headers, self.resp_headers
        trace_id = self.trace_id if self.trace_known else None

        def build() -> Exchange:
            ex = Exchange("outbound", method, raw_path)
            ex.url_base = url_base
            ex.raw_query = raw_query
            ex.trace_id = trace_id
            ex.req_headers = req_headers
            ex.req_body, ex.req_body_total = req_body, req_total
            if net_error is not None:
                ex.net_error = net_error
            else:
                ex.status = status
                ex.resp_headers = resp_headers
                ex.resp_body, ex.resp_body_total = res_body, res_total
            return ex

        self.host.submit(RawExchange(
            self.san, self.decision, build, "outbound", self.ts_ms, latency_ms, self.trace_id, self.span_id,
            self.parent_span, status, net_error, len(req_body) + len(res_body)))


def begin_call(host: Any, method: str, url_base: str, target: Any) -> Optional[OutboundCall]:
    """Starts recording an outbound call, or returns None (not captured / not sampled).
    ``target`` is the request target (path and query, as sent), ``str`` or ``bytes``."""
    if host is None or ctxmod.internal.get() or ctxmod.suppress.get():
        return None
    san = host.active()
    if san is None:
        return None
    t_in = time.perf_counter_ns()
    host.note_seen()
    ctx = ctxmod.current.get()
    if ctx is not None:
        if not ctx.sampled:
            return None
        decision = Decision(True, "inherited")
        if not ctx.trace_known:
            o = ctxmod.otel_active()
            if o is not None:
                ctx.trace_id, ctx.trace_known = o[0], True
        trace_id, known, parent = ctx.trace_id, ctx.trace_known, ctx.span_id
    else:
        o = ctxmod.otel_active()
        decision = san.decide_parts("outbound", None, None, o[0] if o else None, None)
        if not decision.sampled:
            return None
        if o is not None:
            trace_id, known, parent = o[0], True, (o[1] or None)
        else:
            trace_id, known, parent = ctxmod.new_trace_id(), False, None
    host.note_sampled()
    path, query = split_target(target if isinstance(target, str) else target.decode("latin-1"))
    call = OutboundCall(host, san, decision, method, url_base, path, query, trace_id, known, parent)
    call.overhead_ns = time.perf_counter_ns() - t_in
    return call


def baggage_to_add(host: Any, url_base: str) -> Optional[str]:
    """The ``tt.s=0|1`` member to add to the baggage of a call to ``url_base``, if the
    policy allows it (``sampling.propagate_to``, never towards an external base)."""
    try:
        ctx = ctxmod.current.get()
        if host is None or ctx is None or host.active() is None or not host.may_propagate(url_base):
            return None
        return "tt.s=1" if ctx.sampled else "tt.s=0"
    except Exception:
        return None


def url_base_of(scheme: str, host: str, port: Optional[int]) -> str:
    """``scheme://host[:port]`` with the host as the client sees it (spec v1.5, point 9): case and
    a trailing dot untouched, no IDN conversion, an IPv6 literal in brackets."""
    if ":" in host and not host.startswith("["):
        host = "[" + host + "]"
    return "%s://%s%s" % (scheme, host, (":%d" % port) if port else "")


def host_of(u: Any) -> str:
    """Host of a ``urlsplit`` result as written in the URL: not lowercased (``SplitResult.hostname``
    applies ``str.lower``, which maps some non-ASCII characters to ASCII), IPv6 keeps its brackets."""
    h = u.netloc.rpartition("@")[2]
    if h.startswith("["):
        end = h.find("]")
        return h[:end + 1] if end >= 0 else h
    c = h.rfind(":")
    return h[:c] if c >= 0 else h


# ---------------------------------------------------------------------------------
# Taps on http.client.HTTPResponse (instance level: no class is patched)

_TAPPED = ("read", "read1", "readinto", "readinto1", "readline")


def tap_http_response(resp: http.client.HTTPResponse, call: OutboundCall) -> None:
    """Records the body of ``resp`` as the application reads it. The wrapped methods only
    add a copy of what they return; ``busy`` stops the double counting of methods that
    call each other. The exchange ends at the natural end of the body, at ``close()``
    (body not consumed unless it had ended) or when the response is garbage collected."""
    call.status = resp.status
    call.resp_headers = [(n, latin1(v)) for n, v in resp.getheaders()]
    status = resp.status
    if call.method == "HEAD" or status in _NO_BODY_STATUS or 100 <= status < 200:
        call.finish()
        return
    fin = weakref.finalize(resp, call.finish_abandoned)
    fin.atexit = False
    tap = call.res_tap
    st = {"busy": False, "closing": False}

    def wrap(name: str) -> None:
        orig = getattr(resp, name)

        def w(*a: Any, **k: Any) -> Any:
            if st["busy"]:
                return orig(*a, **k)
            st["busy"] = True
            try:
                r = orig(*a, **k)
            finally:
                st["busy"] = False
            try:
                if name in ("readinto", "readinto1"):
                    if isinstance(r, int) and r > 0:
                        tap.add(bytes(memoryview(a[0])[:r]))
                elif r:
                    tap.add(r)
                if resp.fp is None and not st["closing"] and not call.done:
                    tap.ended = True
                    call.finish()
            except Exception:
                pass
            return r

        setattr(resp, name, w)

    for n in _TAPPED:
        if hasattr(resp, n):
            wrap(n)
    orig_close = resp.close

    def close() -> Any:
        st["closing"] = True
        try:
            return orig_close()
        finally:
            call.finish(consumed=tap.ended)

    resp.close = close  # type: ignore[method-assign]


class _ChunkDecoder:
    """Incremental decoder of a chunked body (the request framing seen on ``send``)."""

    def __init__(self) -> None:
        self.buf = b""
        self.remaining = 0
        self.state = "size"  # size | data | crlf | trailer | done

    def feed(self, data: bytes) -> bytes:
        out = []
        self.buf += data
        while self.buf and self.state != "done":
            if self.state == "size":
                i = self.buf.find(b"\r\n")
                if i < 0:
                    if len(self.buf) > 64:
                        self.state = "done"
                    break
                try:
                    n = int(self.buf[:i].split(b";")[0].strip() or b"x", 16)
                except ValueError:
                    self.state = "done"
                    break
                self.buf = self.buf[i + 2:]
                if n == 0:
                    self.state = "trailer"
                else:
                    self.remaining, self.state = n, "data"
            elif self.state == "data":
                take = self.buf[:self.remaining]
                out.append(take)
                self.buf = self.buf[len(take):]
                self.remaining -= len(take)
                if self.remaining == 0:
                    self.state = "crlf"
            elif self.state == "crlf":
                if len(self.buf) < 2:
                    break
                self.buf = self.buf[2:]
                self.state = "size"
            elif self.state == "trailer":
                self.state = "done"
        return b"".join(out)

    @property
    def done(self) -> bool:
        return self.state in ("trailer", "done")


# ---------------------------------------------------------------------------------
# http.client (opt-in patch; there is no extension point at this level)

def _hdr_value(values: Tuple[Any, ...]) -> bytes:
    parts = []
    for v in values:
        parts.append(bytes(v) if isinstance(v, (bytes, bytearray)) else str(v).encode("latin-1", "replace"))
    return b"\r\n\t".join(parts)


def install_http_client(host: Any) -> Callable[[], None]:
    """Patches ``http.client.HTTPConnection`` (putrequest, putheader, endheaders, send,
    getresponse). Returns the function that restores the originals."""
    hc = http.client
    C = hc.HTTPConnection
    o_putrequest, o_putheader, o_endheaders, o_send, o_getresponse = (
        C.putrequest, C.putheader, C.endheaders, C.send, C.getresponse)

    def hd(self: Any) -> Dict[str, Any]:
        return self.__dict__

    def putrequest(self: Any, method: str, url: str, *a: Any, **k: Any) -> Any:
        call = None
        try:
            if isinstance(url, str) and url[:4].lower() in ("http",) and "://" in url[:9]:
                u = urlsplit(url)
                base = url_base_of(u.scheme.lower(), host_of(u), u.port)
            else:
                scheme = "https" if isinstance(self, hc.HTTPSConnection) else "http"
                base = url_base_of(scheme, getattr(self, "_tunnel_host", None) or self.host,
                                   getattr(self, "_tunnel_port", None) or self.port)
            call = begin_call(host, method, base, url)
        except Exception:
            call = None
        hd(self)["_tt_call"] = call
        hd(self)["_tt_phase"] = "headers"
        try:
            return o_putrequest(self, method, url, *a, **k)
        except BaseException:
            hd(self)["_tt_call"] = None
            raise

    def putheader(self: Any, header: Any, *values: Any) -> Any:
        r = o_putheader(self, header, *values)
        call = self.__dict__.get("_tt_call")
        if call is not None and self.__dict__.get("_tt_phase") == "headers":
            try:
                val = _hdr_value(values)
                call.req_headers.append((header.decode("latin-1") if isinstance(header, bytes) else str(header), val))
                if str(header).lower() == "transfer-encoding" and b"chunked" in val.lower():
                    call.chunked = True
            except Exception:
                pass
        return r

    def endheaders(self: Any, *a: Any, **k: Any) -> Any:
        call = self.__dict__.get("_tt_call")
        if call is None:
            return o_endheaders(self, *a, **k)
        self.__dict__["_tt_phase"] = "header_block"
        if call.chunked:
            call.dechunk = _ChunkDecoder()
        try:
            return o_endheaders(self, *a, **k)
        except BaseException as e:
            self.__dict__["_tt_call"] = None
            call.finish(net_error=net_error_of(e))
            raise

    def send(self: Any, data: Any) -> Any:
        call = self.__dict__.get("_tt_call")
        if call is None:
            return o_send(self, data)
        phase = self.__dict__.get("_tt_phase")
        if phase == "header_block":
            self.__dict__["_tt_phase"] = "body"
        elif phase == "body":
            try:
                if isinstance(data, (bytes, bytearray, memoryview)):
                    chunk = bytes(data) if call.dechunk is not None else data
                    if call.dechunk is not None:
                        chunk = call.dechunk.feed(chunk)
                        if call.dechunk.done:
                            call.req_tap.ended = True
                    call.req_tap.add(chunk)
                else:
                    call.req_unknown = True
            except Exception:
                call.req_unknown = True
        try:
            return o_send(self, data)
        except BaseException as e:
            self.__dict__["_tt_call"] = None
            call.finish(net_error=net_error_of(e))
            raise

    def getresponse(self: Any) -> Any:
        call = self.__dict__.get("_tt_call")
        if call is None:
            return o_getresponse(self)
        self.__dict__["_tt_call"] = None
        if not call.req_tap.ended and not call.req_unknown and call.dechunk is None and call.req_tap.total >= 0:
            call.req_tap.ended = True  # Content-Length framed or empty body: all of it was sent
        try:
            resp = o_getresponse(self)
        except BaseException as e:
            call.finish(net_error=net_error_of(e))
            raise
        try:
            tap_http_response(resp, call)
        except Exception:
            host.note_error("capture_outbound_tap")
        return resp

    C.putrequest, C.putheader, C.endheaders, C.send, C.getresponse = putrequest, putheader, endheaders, send, getresponse

    def restore() -> None:
        C.putrequest, C.putheader, C.endheaders, C.send, C.getresponse = (
            o_putrequest, o_putheader, o_endheaders, o_send, o_getresponse)

    return restore


# ---------------------------------------------------------------------------------
# urllib (extension point: handler)

def make_urllib_handler(host: Any = None):
    """``TrafficTwinHandler`` class bound to ``host`` (default: the running agent)."""
    import urllib.request

    class TrafficTwinHandler(urllib.request.BaseHandler):
        """``opener = urllib.request.build_opener(TrafficTwinHandler())``"""

        handler_order = 900  # after the HTTP handlers' request processing, before HTTPErrorProcessor (1000)

        def _host(self) -> Any:
            if host is not None:
                return host
            from ..runtime import get_agent

            return get_agent()

        def _request(self, req: Any) -> Any:
            h = self._host()
            try:
                if h is None or h.active() is None:
                    return req
                scheme = req.type.lower()
                u = urlsplit(req.full_url)
                base = url_base_of(scheme, host_of(u), u.port)
                call = begin_call(h, req.get_method(), base, req.selector)
                if call is None:
                    return req
                for n, v in list(req.header_items()) + list(req.unredirected_hdrs.items()):
                    call.add_header(n, v)
                call.set_request_body(req.data)
                req._tt_call = call
                fin = weakref.finalize(req, call.finish_abandoned)  # a request that never gets a response
                fin.atexit = False
                req._tt_fin = fin
                add = baggage_to_add(h, base)
                if add:
                    cur = req.get_header("Baggage")
                    req.add_unredirected_header("Baggage", with_tt_s(cur, add.endswith("1")))
            except Exception:
                debug("urllib_request_hook_failed")
            return req

        def _response(self, req: Any, resp: Any) -> Any:
            call = getattr(req, "_tt_call", None)
            if call is not None and not call.done:
                try:
                    fin = getattr(req, "_tt_fin", None)
                    if fin is not None:
                        fin.detach()  # the response (below) owns the end of the exchange now
                    call.req_tap.ended = True
                    if isinstance(resp, http.client.HTTPResponse):
                        tap_http_response(resp, call)
                    else:
                        call.status = getattr(resp, "status", None) or getattr(resp, "code", None) or 0
                        call.finish(consumed=False)
                except Exception:
                    debug("urllib_response_hook_failed")
            return resp

        http_request = https_request = _request
        http_response = https_response = _response

    return TrafficTwinHandler


# ---------------------------------------------------------------------------------
# requests (extension point: transport adapter)

def make_requests_adapter(host: Any = None):
    """``TrafficTwinAdapter`` class (needs ``requests``). ``session.mount('https://',
    TrafficTwinAdapter())``."""
    from requests.adapters import HTTPAdapter  # type: ignore

    class TrafficTwinAdapter(HTTPAdapter):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)

        def _host(self) -> Any:
            if host is not None:
                return host
            from ..runtime import get_agent

            return get_agent()

        def send(self, request: Any, *args: Any, **kwargs: Any) -> Any:
            h = self._host()
            call = None
            try:
                if h is not None and h.active() is not None and not ctxmod.suppress.get():
                    u = urlsplit(request.url)
                    base = url_base_of((u.scheme or "http").lower(), host_of(u), u.port)
                    call = begin_call(h, request.method or "GET", base, request.path_url)
                    if call is not None:
                        for n, v in request.headers.items():
                            call.add_header(n, v)
                        call.set_request_body(request.body)
                    add = baggage_to_add(h, base)
                    if add:
                        request.headers["baggage"] = with_tt_s(request.headers.get("baggage"), add.endswith("1"))
            except Exception:
                call = None
            if call is None:
                return super().send(request, *args, **kwargs)
            token = ctxmod.suppress.set(True)
            try:
                response = super().send(request, *args, **kwargs)
            except BaseException as e:
                call.finish(net_error=net_error_of(e))
                raise
            finally:
                ctxmod.suppress.reset(token)
            try:
                fp = getattr(getattr(response, "raw", None), "_fp", None)
                if isinstance(fp, http.client.HTTPResponse):
                    tap_http_response(fp, call)
                else:
                    call.status = response.status_code
                    call.resp_headers = [(k, latin1(v)) for k, v in response.headers.items()]
                    call.finish(consumed=False)
            except Exception:
                h.note_error("capture_outbound_tap")
            return response

    return TrafficTwinAdapter


# ---------------------------------------------------------------------------------
# httpx (extension point: transport wrapper)

def make_httpx_transports(host: Any = None):
    """``(TrafficTwinTransport, AsyncTrafficTwinTransport)`` (need ``httpx``). Wrap the
    transport of a client: ``httpx.Client(transport=TrafficTwinTransport(httpx.HTTPTransport()))``."""
    import httpx  # type: ignore

    def get_host() -> Any:
        if host is not None:
            return host
        from ..runtime import get_agent

        return get_agent()

    def begin(request: Any) -> Optional[OutboundCall]:
        h = get_host()
        if h is None or h.active() is None or ctxmod.suppress.get():
            return None
        try:
            u = request.url
            base = url_base_of(u.scheme.lower(), u.raw_host.decode("ascii", "replace").lower(), u.port)
            call = begin_call(h, request.method, base, u.raw_path)
            add = baggage_to_add(h, base)
            if add:
                request.headers["baggage"] = with_tt_s(request.headers.get("baggage"), add.endswith("1"))
            if call is None:
                return None
            for n, v in request.headers.raw:
                call.add_header(n, v)
            content = getattr(request, "_content", None)
            if isinstance(content, (bytes, bytearray)):
                call.set_request_body(bytes(content))
            else:
                call.req_unknown = True
            return call
        except Exception:
            return None

    def attach(call: OutboundCall, response: Any) -> None:
        call.status = response.status_code
        call.resp_headers = [(n.decode("latin-1"), bytes(v)) for n, v in response.headers.raw]
        call.req_tap.ended = True

    class _TeeStream(httpx.SyncByteStream):
        def __init__(self, inner: Any, call: OutboundCall) -> None:
            self._inner, self._call, self._complete = inner, call, False

        def __iter__(self):
            for chunk in self._inner:
                self._call.res_tap.add(chunk)
                yield chunk
            self._complete = True
            self._call.res_tap.ended = True
            self._call.finish()

        def close(self) -> None:
            try:
                if hasattr(self._inner, "close"):
                    self._inner.close()
            finally:
                self._call.finish(consumed=self._complete)

    class _AsyncTeeStream(httpx.AsyncByteStream):
        def __init__(self, inner: Any, call: OutboundCall) -> None:
            self._inner, self._call, self._complete = inner, call, False

        async def __aiter__(self):
            async for chunk in self._inner:
                self._call.res_tap.add(chunk)
                yield chunk
            self._complete = True
            self._call.res_tap.ended = True
            self._call.finish()

        async def aclose(self) -> None:
            try:
                if hasattr(self._inner, "aclose"):
                    await self._inner.aclose()
            finally:
                self._call.finish(consumed=self._complete)

    def wrap_response(call: OutboundCall, response: Any, is_async: bool) -> None:
        attach(call, response)
        m = call.method
        if m == "HEAD" or response.status_code in _NO_BODY_STATUS or 100 <= response.status_code < 200:
            call.finish()
            return
        response.stream = (_AsyncTeeStream if is_async else _TeeStream)(response.stream, call)

    class TrafficTwinTransport(httpx.BaseTransport):
        def __init__(self, transport: Optional[Any] = None) -> None:
            self._t = transport if transport is not None else httpx.HTTPTransport()

        def handle_request(self, request: Any) -> Any:
            call = begin(request)
            if call is None:
                return self._t.handle_request(request)
            token = ctxmod.suppress.set(True)
            try:
                response = self._t.handle_request(request)
            except BaseException as e:
                call.finish(net_error=net_error_of(e))
                raise
            finally:
                ctxmod.suppress.reset(token)
            try:
                wrap_response(call, response, False)
            except Exception:
                get_host().note_error("capture_outbound_tap")
            return response

        def close(self) -> None:
            self._t.close()

        def __enter__(self) -> "TrafficTwinTransport":
            self._t.__enter__()
            return self

        def __exit__(self, *a: Any) -> None:
            self._t.__exit__(*a)

    class AsyncTrafficTwinTransport(httpx.AsyncBaseTransport):
        def __init__(self, transport: Optional[Any] = None) -> None:
            self._t = transport if transport is not None else httpx.AsyncHTTPTransport()

        async def handle_async_request(self, request: Any) -> Any:
            call = begin(request)
            if call is None:
                return await self._t.handle_async_request(request)
            token = ctxmod.suppress.set(True)
            try:
                response = await self._t.handle_async_request(request)
            except BaseException as e:
                call.finish(net_error=net_error_of(e))
                raise
            finally:
                ctxmod.suppress.reset(token)
            try:
                wrap_response(call, response, True)
            except Exception:
                get_host().note_error("capture_outbound_tap")
            return response

        async def aclose(self) -> None:
            await self._t.aclose()

        async def __aenter__(self) -> "AsyncTrafficTwinTransport":
            await self._t.__aenter__()
            return self

        async def __aexit__(self, *a: Any) -> None:
            await self._t.__aexit__(*a)

    return TrafficTwinTransport, AsyncTrafficTwinTransport


# ---------------------------------------------------------------------------------
# Opt-in global installation (reversible)

def install_requests(host: Any) -> Callable[[], None]:
    """New ``requests.Session`` objects get the adapter on ``http://`` and ``https://``."""
    import requests  # type: ignore

    Adapter = make_requests_adapter(host)
    orig_init = requests.Session.__init__

    def init(self: Any, *a: Any, **k: Any) -> None:
        orig_init(self, *a, **k)
        for prefix in ("https://", "http://"):
            if not isinstance(self.adapters.get(prefix), Adapter):
                self.mount(prefix, Adapter())

    requests.Session.__init__ = init  # type: ignore[method-assign]

    def restore() -> None:
        requests.Session.__init__ = orig_init  # type: ignore[method-assign]

    return restore


def install_httpx(host: Any) -> Callable[[], None]:
    """Wraps ``handle_request`` / ``handle_async_request`` of the default httpx transports."""
    import httpx  # type: ignore

    T, AT = make_httpx_transports(host)
    o_sync = httpx.HTTPTransport.handle_request
    o_async = httpx.AsyncHTTPTransport.handle_async_request

    def handle_request(self: Any, request: Any) -> Any:
        return _delegate_sync(T, self, o_sync, request)

    async def handle_async_request(self: Any, request: Any) -> Any:
        return await _delegate_async(AT, self, o_async, request)

    httpx.HTTPTransport.handle_request = handle_request  # type: ignore[method-assign]
    httpx.AsyncHTTPTransport.handle_async_request = handle_async_request  # type: ignore[method-assign]

    def restore() -> None:
        httpx.HTTPTransport.handle_request = o_sync  # type: ignore[method-assign]
        httpx.AsyncHTTPTransport.handle_async_request = o_async  # type: ignore[method-assign]

    return restore


class _Bound:
    """Adapts an unbound original method to the ``handle_request`` interface of a transport."""

    def __init__(self, owner: Any, fn: Callable) -> None:
        self._o, self._f = owner, fn

    def handle_request(self, request: Any) -> Any:
        return self._f(self._o, request)

    async def handle_async_request(self, request: Any) -> Any:
        return await self._f(self._o, request)


def _delegate_sync(T: Any, owner: Any, orig: Callable, request: Any) -> Any:
    return T(_Bound(owner, orig)).handle_request(request)


async def _delegate_async(AT: Any, owner: Any, orig: Callable, request: Any) -> Any:
    return await AT(_Bound(owner, orig)).handle_async_request(request)


def install_urllib(host: Any) -> Callable[[], None]:
    """Installs an opener with the handler as the default opener (``install_opener``)."""
    import urllib.request

    previous = getattr(urllib.request, "_opener", None)
    urllib.request.install_opener(urllib.request.build_opener(make_urllib_handler(host)()))

    def restore() -> None:
        urllib.request.install_opener(previous)  # type: ignore[arg-type]

    return restore


_INSTALLERS = {
    "http.client": install_http_client, "httpclient": install_http_client,
    "requests": install_requests, "httpx": install_httpx, "urllib": install_urllib,
}
_MODULES = {"requests": "requests", "httpx": "httpx"}


class _CurrentAgent:
    """Stands for the process-wide agent, looked up at call time. The hooks of the zero-code
    start use it instead of an agent object: after ``fork`` (gunicorn) the child has a new
    agent and the patches inherited from the parent must follow it. Without an agent every
    method does nothing (``active()`` is ``None``: nothing is captured)."""

    def __getattr__(self, name: str) -> Any:
        from ..runtime import get_agent

        a = get_agent()
        if a is None:
            return lambda *args, **kw: None
        return getattr(a, name)


CURRENT = _CurrentAgent()


def install_from_option(host: Any, option: Optional[str]) -> List[Callable[[], None]]:
    """``option`` is a comma-separated list of ``requests``, ``httpx``, ``urllib``,
    ``http.client``; ``auto`` means requests/httpx if already imported, plus urllib."""
    if not option or option.strip().lower() in ("", "0", "none", "off", "false"):
        return []
    names = [n.strip().lower() for n in option.split(",") if n.strip()]
    if "auto" in names:
        names = [n for n in ("requests", "httpx") if n in sys.modules] + ["urllib"]
    undo: List[Callable[[], None]] = []
    for n in names:
        inst = _INSTALLERS.get(n)
        if inst is None:
            host.note_error("outbound_unknown_" + re.sub(r"[^a-z0-9._-]", "", n)[:20])
            continue
        try:
            undo.append(inst(host))
        except ImportError:
            host.note_error("outbound_missing_" + n)
    return undo
