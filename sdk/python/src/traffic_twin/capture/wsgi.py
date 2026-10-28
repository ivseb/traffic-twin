"""Inbound capture for WSGI apps (Flask, Django WSGI, any WSGI app).

The middleware gives the app a tee around ``wsgi.input`` and around ``start_response`` /
the response iterable of sampled exchanges. Reads and writes pass through unchanged, with
the same arguments, results and exceptions. Sanitizing and sending happen later in the
sanitizer thread.

Limits of WSGI (documented in the README): ``PATH_INFO`` and the header names are already
decoded by the server. The raw path is taken from ``RAW_URI`` / ``REQUEST_URI`` when the
server provides it (gunicorn, uWSGI, mod_wsgi), otherwise the decoded path is percent-
encoded again (an original ``%2F`` is then indistinguishable from ``/``). Header names are
rebuilt from ``HTTP_*`` variables (``-`` for ``_``): a client header that really contains
an underscore is seen with a dash.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote_from_bytes

from .. import context as ctxmod
from ..sanitizer import Exchange
from . import routes as routes_mod
from .common import BodyTap, RawExchange, split_target

_perf = time.perf_counter_ns
_ENV_KEYS = ("SCRIPT_NAME", "PATH_INFO", "QUERY_STRING", "REQUEST_METHOD", "HTTP_HOST", "SERVER_NAME", "SERVER_PORT",
             "wsgi.url_scheme", "REMOTE_ADDR")


def environ_headers(environ: Dict[str, Any]) -> List[Tuple[str, bytes]]:
    out: List[Tuple[str, bytes]] = []
    for k, v in environ.items():
        if k.startswith("HTTP_"):
            name = k[5:].lower().replace("_", "-")
        elif k == "CONTENT_TYPE" and v:
            name = "content-type"
        elif k == "CONTENT_LENGTH" and v:
            name = "content-length"
        else:
            continue
        if isinstance(v, str):
            out.append((name, v.encode("latin-1", "replace")))
    return out


def environ_raw_target(environ: Dict[str, Any]) -> Tuple[bytes, Optional[bytes]]:
    raw = environ.get("RAW_URI") or environ.get("REQUEST_URI")
    if isinstance(raw, str) and raw.startswith(("/", "http://", "https://")):
        path, query = split_target(raw)
        # A mounted app sees SCRIPT_NAME/PATH_INFO of its own, but the spec wants the full path.
        return path, query
    path_b = ((environ.get("SCRIPT_NAME") or "") + (environ.get("PATH_INFO") or "")).encode("latin-1", "replace")
    qs = environ.get("QUERY_STRING") or ""
    return quote_from_bytes(path_b, safe="/!$&'()*+,;=:@~").encode("ascii"), (qs.encode("latin-1", "replace") if qs else None)


class _TeeInput:
    """Wraps ``wsgi.input``; forwards every call and records the bytes read."""

    def __init__(self, inner: Any, tap: BodyTap, content_length: Optional[int]) -> None:
        self._inner = inner
        self._tap = tap
        self._cl = content_length

    def _seen(self, data: Any, requested: Optional[int] = None) -> Any:
        tap = self._tap
        if data:
            tap.add(data)
        elif requested is None or requested != 0:
            tap.ended = True
        if self._cl is not None and tap.total >= self._cl:
            tap.ended = True
        return data

    def read(self, *args: Any) -> Any:
        data = self._inner.read(*args)
        self._seen(data, args[0] if args and args[0] is not None and args[0] >= 0 else None)
        if not args or args[0] is None or args[0] < 0:
            self._tap.ended = True  # read() to the end
        return data

    def readline(self, *args: Any) -> Any:
        return self._seen(self._inner.readline(*args), 1)

    def readlines(self, *args: Any) -> Any:
        lines = self._inner.readlines(*args)
        for ln in lines:
            self._tap.add(ln)
        if not args or args[0] is None or args[0] <= 0:
            self._tap.ended = True
        if self._cl is not None and self._tap.total >= self._cl:
            self._tap.ended = True
        return lines

    def __iter__(self) -> "_TeeInput":
        return self

    def __next__(self) -> Any:
        line = self._inner.readline()
        if not line:
            self._tap.ended = True
            raise StopIteration
        self._seen(line, 1)
        return line

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class _State:
    __slots__ = ("san", "decision", "ctx", "parent_span", "ts_ms", "t0", "req_tap", "res_tap", "status",
                 "resp_headers", "resp_unknown", "error", "overhead_ns", "snapshot", "req_headers", "raw_path",
                 "query", "method", "done", "declared")


class WSGIMiddleware:
    """``app = WSGIMiddleware(app)``. With ``framework='flask'`` and the Flask app, or
    ``framework='django'``, the route template is resolved for the policy (§3.4)."""

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

    def __call__(self, environ: Dict[str, Any], start_response: Callable) -> Iterable[bytes]:
        host = self._get_host()
        san = host.active() if host is not None else None
        if san is None:
            return self.app(environ, start_response)
        t_in = _perf()
        try:
            ctx, st = self._begin(host, san, environ, t_in)
        except Exception:  # whatever goes wrong here, the request goes on untouched
            host.note_error("capture_inbound_start")
            return self.app(environ, start_response)
        if st is None:
            token = ctxmod.current.set(ctx)
            try:
                host.note_overhead(_perf() - t_in)
                result = self.app(environ, start_response)
            finally:
                ctxmod.current.reset(token)
            if isinstance(result, (list, tuple)) or hasattr(result, "filelike"):
                return result
            return _CtxIter(result, ctx)
        res_tap = st.res_tap

        def tapped_start_response(status: str, headers: List[Tuple[str, str]], exc_info: Any = None) -> Callable:
            try:
                st.status = int(status[:3])
                st.resp_headers = list(headers)
                if not ctx.trace_known:
                    o = ctxmod.otel_active()
                    if o is not None:
                        ctx.trace_id, ctx.trace_known = o[0], True
            except Exception:
                pass
            write = start_response(status, headers) if exc_info is None else start_response(status, headers, exc_info)

            def tapped_write(data: Any) -> Any:
                res_tap.add(data)
                return write(data)

            return tapped_write

        st.overhead_ns = _perf() - t_in
        token = ctxmod.current.set(ctx)
        try:
            result = self.app(environ, tapped_start_response)
        except BaseException as e:
            st.error = e
            self._finish(host, st, environ, ended=True)
            raise
        finally:
            ctxmod.current.reset(token)
        if hasattr(result, "filelike"):  # wsgi.file_wrapper: bytes go out by sendfile, not visible
            st.resp_unknown = True
            self._finish(host, st, environ, ended=True)
            return result
        if isinstance(result, (list, tuple)):
            for chunk in result:
                res_tap.add(chunk)
            res_tap.ended = True
            self._finish(host, st, environ, ended=True)
            return result
        cls = _TeeIterLen if hasattr(result, "__len__") else _TeeIter
        return cls(result, st, ctx, lambda ended: self._finish(host, st, environ, ended))

    def _begin(self, host: Any, san: Any, environ: Dict[str, Any], t_in: int) -> Tuple[Any, Optional[_State]]:
        """Counts the exchange, takes the sampling decision and, if sampled, prepares the taps."""
        host.note_seen()
        pairs: List[Tuple[str, bytes]] = []
        tp = None
        for name in host.decision_headers():
            v = environ.get("HTTP_" + name.upper().replace("-", "_"))
            if isinstance(v, str):
                pairs.append((name, v.encode("latin-1", "replace")))
                if name == "traceparent":
                    tp = ctxmod.parse_traceparent(v)
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
        st.status, st.resp_headers, st.resp_unknown, st.error, st.done = None, None, False, None, False
        st.req_headers = environ_headers(environ)
        st.raw_path, st.query = environ_raw_target(environ)
        st.method = environ.get("REQUEST_METHOD") or ""
        st.snapshot = {k: environ[k] for k in _ENV_KEYS if k in environ} if self.framework else None
        try:
            cl = environ.get("CONTENT_LENGTH")
            clen = int(cl) if cl not in (None, "") else None
        except ValueError:
            clen = None
        st.declared = (clen is not None and clen > 0) or bool(environ.get("HTTP_TRANSFER_ENCODING"))
        if clen == 0:
            st.req_tap.ended = True
        inner_input = environ.get("wsgi.input")
        if inner_input is not None:
            environ["wsgi.input"] = _TeeInput(inner_input, st.req_tap, clen)
        return ctx, st

    # --- finishing ---------------------------------------------------------------------

    def _finish(self, host: Any, st: _State, environ: Dict[str, Any], ended: bool) -> None:
        if st.done:
            return
        st.done = True
        t_out = _perf()
        try:
            self._submit(host, st, ended)
        except Exception:
            host.note_error("capture_inbound_finish")
        host.note_overhead(st.overhead_ns + (_perf() - t_out))

    def _submit(self, host: Any, st: _State, ended: bool) -> None:
        status = st.status
        if status is None:
            if st.error is None:
                return
            status = 500
        latency_ms = max(0, int((time.perf_counter() - st.t0) * 1000))
        method = st.method
        no_body = method == "HEAD" or status in (204, 304) or 100 <= status < 200
        req_tap, res_tap = st.req_tap, st.res_tap
        req_consumed = req_tap.ended or (req_tap.total == 0 and not st.declared)
        req_body = req_tap.bytes() if req_consumed else b""
        res_body = b"" if no_body else res_tap.bytes()
        res_total: Any = 0 if no_body else res_tap.total
        if not no_body and (st.resp_unknown or not (res_tap.ended or ended and st.error is None)):
            res_total = "unknown"
        req_headers = st.req_headers
        resp_headers = [(n, v.encode("latin-1", "replace")) for n, v in (st.resp_headers or [])]
        service = host.service_name()
        trace_known, trace_id = st.ctx.trace_known, st.ctx.trace_id
        snapshot, framework, fapp = st.snapshot, self.framework, self.framework_app
        raw_path, query, req_total = st.raw_path, st.query, req_tap.total

        def build() -> Exchange:
            ex = Exchange("inbound", method, raw_path)
            ex.service_name = service
            ex.raw_query = query
            if framework and snapshot is not None:
                r = self._route(framework, fapp, snapshot)
                if r is not None:
                    ex.framework, ex.framework_route = r
            ex.trace_id = trace_id if trace_known else None
            ex.req_headers = req_headers
            ex.req_body, ex.req_body_total, ex.req_body_consumed = req_body, req_total, req_consumed
            ex.status = status
            ex.resp_headers = resp_headers
            ex.resp_body, ex.resp_body_total = res_body, res_total
            return ex

        host.submit(RawExchange(
            st.san, st.decision, build, "inbound", st.ts_ms, latency_ms, st.ctx.trace_id, st.ctx.span_id,
            st.parent_span, status, None, len(req_body) + len(res_body)))

    @staticmethod
    def _route(framework: str, fapp: Any, env: Dict[str, Any]) -> Optional[Tuple[str, str]]:
        if framework == "flask":
            return routes_mod.resolve_flask(fapp, env)
        if framework == "django":
            path = (env.get("PATH_INFO") or "").encode("latin-1", "replace").decode("utf-8", "replace")
            return routes_mod.resolve_django(path, env.get("SCRIPT_NAME") or "")
        return None


class _CtxIter:
    """Not sampled: keeps the context bound while a lazy iterable runs (so that outbound
    calls made there inherit "not sampled"). Adds nothing else."""

    def __init__(self, result: Any, ctx: ctxmod.ExchangeCtx) -> None:
        self._result = result
        self._it = iter(result)
        self._ctx = ctx

    def __iter__(self) -> "_CtxIter":
        return self

    def __next__(self) -> Any:
        token = ctxmod.current.set(self._ctx)
        try:
            return next(self._it)
        finally:
            ctxmod.current.reset(token)

    def close(self) -> None:
        c = getattr(self._result, "close", None)
        if c is not None:
            c()


class _TeeIter:
    def __init__(self, result: Any, st: _State, ctx: ctxmod.ExchangeCtx, finish: Callable[[bool], None]) -> None:
        self._result = result
        self._it = iter(result)
        self._st = st
        self._ctx = ctx
        self._finish = finish

    def __iter__(self) -> "_TeeIter":
        return self

    def __next__(self) -> Any:
        token = ctxmod.current.set(self._ctx)
        try:
            chunk = next(self._it)
        except StopIteration:
            self._st.res_tap.ended = True
            self._finish(True)
            raise
        except BaseException as e:
            self._st.error = e
            self._finish(True)
            raise
        finally:
            ctxmod.current.reset(token)
        self._st.res_tap.add(chunk)
        return chunk

    def close(self) -> None:
        try:
            c = getattr(self._result, "close", None)
            if c is not None:
                c()
        finally:
            self._finish(self._st.res_tap.ended)


class _TeeIterLen(_TeeIter):
    def __len__(self) -> int:
        return len(self._result)
