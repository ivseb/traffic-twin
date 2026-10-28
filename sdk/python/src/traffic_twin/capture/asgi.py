"""Inbound capture for ASGI apps (FastAPI, Starlette, Django ASGI, any ASGI 3 app).

A pure ASGI middleware: it wraps ``receive`` and ``send`` of sampled exchanges to tee the
body bytes; it never changes a message, never delays one and never swallows an error.
Everything expensive (header normalization, sanitizing, serializing, sending) happens
later in the sanitizer thread.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from .. import context as ctxmod
from ..sanitizer import Decision, Exchange
from . import routes as routes_mod
from .common import BodyTap, RawExchange, latin1, split_target
from urllib.parse import quote_from_bytes

_perf = time.perf_counter_ns


def _raw_path(scope: Dict[str, Any]) -> bytes:
    rp = scope.get("raw_path")
    if isinstance(rp, (bytes, bytearray)) and rp:
        # Servers differ on whether raw_path includes the query; the spec wants it without.
        q = rp.find(b"?")
        return bytes(rp[:q] if q >= 0 else rp)
    root = scope.get("root_path") or ""
    path = scope.get("path") or "/"
    full = path if (not root or path.startswith(root)) else root + path
    return quote_from_bytes(full.encode("utf-8"), safe="/!$&'()*+,;=:@~").encode("ascii")


class _State:
    __slots__ = ("san", "decision", "ctx", "parent_span", "ts_ms", "t0", "req_tap", "res_tap", "status",
                 "resp_headers", "resp_unknown", "error", "overhead_ns", "snapshot", "req_headers", "raw_path",
                 "query", "method", "end_ns")


class ASGIMiddleware:
    """``app = ASGIMiddleware(app)``. With ``framework`` (``'fastapi'`` for Starlette and
    FastAPI, ``'django'``) and the framework app, the route template is resolved for the
    policy (§3.4)."""

    def __init__(self, app: Callable, host: Any = None, framework: Optional[str] = None, framework_app: Any = None) -> None:
        self.app = app
        self._host = host
        self.framework = framework
        self.framework_app = framework_app
        from ..autocapture import note_wrapped

        note_wrapped()
        from ..autocapture import note_wrapped

        note_wrapped()

    def _get_host(self) -> Any:
        if self._host is not None:
            return self._host
        from ..runtime import get_agent

        return get_agent()

    async def __call__(self, scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        host = self._get_host()
        san = host.active() if host is not None else None
        if san is None:
            await self.app(scope, receive, send)
            return
        t_in = _perf()
        try:
            ctx, st = self._begin(host, san, scope, t_in)
        except Exception:  # whatever goes wrong here, the request goes on untouched
            host.note_error("capture_inbound_start")
            await self.app(scope, receive, send)
            return
        token = ctxmod.current.set(ctx)
        try:
            if st is None:
                host.note_overhead(_perf() - t_in)
                await self.app(scope, receive, send)
                return
            req_tap, res_tap = st.req_tap, st.res_tap

            async def tapped_receive() -> Any:
                msg = await receive()
                try:
                    if msg.get("type") == "http.request":
                        req_tap.add(msg.get("body"))
                        if not msg.get("more_body"):
                            req_tap.ended = True
                except Exception:
                    pass
                return msg

            async def tapped_send(message: Any) -> None:
                try:
                    t = message.get("type")
                    if t == "http.response.start":
                        st.status = message.get("status")
                        st.resp_headers = message.get("headers")
                        if not ctx.trace_known:  # adopt the app's OpenTelemetry trace when the request carried none
                            o = ctxmod.otel_active()
                            if o is not None:
                                ctx.trace_id, ctx.trace_known = o[0], True
                    elif t == "http.response.body":
                        res_tap.add(message.get("body"))
                        if not message.get("more_body"):
                            res_tap.ended = True
                    elif t in ("http.response.zerocopysend", "http.response.pathsend"):
                        st.resp_unknown = True
                except Exception:
                    pass
                await send(message)

            st.overhead_ns = _perf() - t_in
            try:
                await self.app(scope, tapped_receive, tapped_send)
            except BaseException as e:
                st.error = e
                raise
            finally:
                t_out = _perf()
                try:
                    self._finish(host, st)
                except Exception:
                    host.note_error("capture_inbound_finish")
                host.note_overhead(st.overhead_ns + (_perf() - t_out))
        finally:
            ctxmod.current.reset(token)

    def _begin(self, host: Any, san: Any, scope: Dict[str, Any], t_in: int) -> Tuple[Any, Optional[_State]]:
        """Counts the exchange, takes the sampling decision and, if sampled, prepares the taps."""
        host.note_seen()
        raw_headers = scope.get("headers") or []
        need = host.decision_headers_bytes()
        pairs: List[Tuple[str, bytes]] = []
        tp: Optional[Tuple[str, str]] = None
        for k, v in raw_headers:
            if k in need:
                pairs.append((k.decode("latin-1"), v))
                if k == b"traceparent":
                    tp = ctxmod.parse_traceparent(v.decode("latin-1"))
        decision = san.decide_parts("inbound", host.service_name(), pairs, tp[0] if tp else None, None)
        ctx = ctxmod.ExchangeCtx(decision.sampled, tp[0] if tp else ctxmod.new_trace_id(), tp is not None, ctxmod.new_span_id())
        if not decision.sampled:
            return ctx, None
        host.note_sampled()
        limit = san.policy.capture_limit  # max(max_body_bytes, bodies.max_large_body_bytes) + 1 (9.0, 22.5)
        st = _State()
        st.san, st.decision, st.ctx = san, decision, ctx
        st.parent_span = tp[1] if tp else None
        st.ts_ms = int(time.time() * 1000)
        st.t0 = time.perf_counter()
        st.req_tap, st.res_tap = BodyTap(limit), BodyTap(limit)
        st.status = None
        st.resp_headers = None
        st.resp_unknown = False
        st.error = None
        st.req_headers = raw_headers
        st.raw_path = _raw_path(scope)
        st.query = scope.get("query_string")
        st.method = scope.get("method") or ""
        st.snapshot = dict(scope) if self.framework else None
        st.end_ns = 0
        return ctx, st

    def _finish(self, host: Any, st: _State) -> None:
        status = st.status
        if status is None:
            if st.error is None:
                return  # connection dropped before any response: nothing to report
            status = 500
        latency_ms = max(0, int((time.perf_counter() - st.t0) * 1000))
        method = st.method
        no_body = method == "HEAD" or status in (204, 304) or 100 <= status < 200
        req_tap, res_tap = st.req_tap, st.res_tap
        # 9.0: a body the app did not read to the end is "not consumed"; an empty, undeclared body is complete.
        declared = False
        for k, v in st.req_headers:
            if k == b"content-length":
                try:
                    declared = int(v) > 0
                except ValueError:
                    declared = True
            elif k == b"transfer-encoding":
                declared = True
        req_consumed = req_tap.ended or (req_tap.total == 0 and not declared)
        req_body = req_tap.bytes() if req_consumed else b""
        res_body = b"" if no_body else res_tap.bytes()
        res_total: Any = 0 if no_body else res_tap.total
        if not no_body and (st.resp_unknown or not res_tap.ended):
            res_total = "unknown"
        raw_headers, resp_headers = st.req_headers, st.resp_headers or []
        service = host.service_name()
        trace_known, trace_id = st.ctx.trace_known, st.ctx.trace_id
        snapshot, framework, fapp = st.snapshot, self.framework, self.framework_app
        raw_path, query, req_total = st.raw_path, st.query, req_tap.total

        def build() -> Exchange:
            ex = Exchange("inbound", method, raw_path)
            ex.service_name = service
            ex.raw_query = bytes(query) if query else None
            if framework and snapshot is not None:
                r = self._route(framework, fapp, snapshot)
                if r is not None:
                    ex.framework, ex.framework_route = r
            ex.trace_id = trace_id if trace_known else None
            ex.req_headers = [(k.decode("latin-1"), v) for k, v in raw_headers]
            ex.req_body, ex.req_body_total, ex.req_body_consumed = req_body, req_total, req_consumed
            ex.status = status
            ex.resp_headers = [(k.decode("latin-1"), v) for k, v in resp_headers]
            ex.resp_body, ex.resp_body_total = res_body, res_total
            return ex

        host.submit(RawExchange(
            st.san, st.decision, build, "inbound", st.ts_ms, latency_ms, st.ctx.trace_id, st.ctx.span_id,
            st.parent_span, status, None, len(req_body) + len(res_body)))

    @staticmethod
    def _route(framework: str, fapp: Any, scope: Dict[str, Any]) -> Optional[Tuple[str, str]]:
        if framework == "fastapi":
            return routes_mod.resolve_starlette(fapp, scope)
        if framework == "django":
            root = scope.get("root_path") or ""
            path = scope.get("path") or "/"
            rel = path[len(root):] if root and path.startswith(root) else path
            return routes_mod.resolve_django(rel, root)
        return None
