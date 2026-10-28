"""Automatic capture for the zero-code start (``python -m traffic_twin run -- <command>``,
``import traffic_twin.auto``).

The application is not touched; instead, the first time a known framework or server module
is imported, a small patch makes the objects it creates capture the inbound traffic:

* **FastAPI / Starlette**: ``Starlette.build_middleware_stack`` returns the stack wrapped in the
  ASGI middleware (outermost, once per app, never for an app that already has it);
* **Flask**: ``Flask.__init__`` wraps ``wsgi_app``;
* **Django**: ``get_wsgi_application()`` / ``get_asgi_application()`` return the wrapped object;
* **uvicorn** (``uvicorn app:app``, ``uvicorn.run(app)``) and **gunicorn** (WSGI, or the uvicorn
  worker): the application object they load is wrapped when it is a plain WSGI/ASGI callable
  that no framework patch has covered (a ``--factory`` is left alone).

``requests`` and ``httpx`` get the outbound hook when they are imported (``TT_OUTBOUND=auto``).

Nothing here can break the application: every patch is guarded, runs once and falls back to the
original object. If, after a grace period, no web app has been wrapped (an unknown server, a
custom framework), a single warning says so on stderr and the source reports the problem
``inbound_not_captured`` to tt-core (the console shows it), so that "only outgoing calls are
seen" is never silent. The remedy is one line: ``app = traffic_twin.install(app)``.
"""

from __future__ import annotations

import importlib.abc
import importlib.util
import inspect
import os
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from ._log import debug, notice

GRACE_S = 20.0           # time to wait for a web app to be wrapped before warning
RENOTICE_S = 300.0       # the problem is reported again this often (the console shows the last 15 minutes)

WARNING = ("inbound not captured: no web application was wrapped, so only outgoing calls are seen. "
           "Add `app = traffic_twin.install(app)` where the application object is created "
           "(Flask, FastAPI/Starlette, Django, any WSGI/ASGI app).")

_lock = threading.RLock()
_pending: Dict[str, List[Callable[[Any], None]]] = {}
_finder: Optional["_Finder"] = None
_enabled = False
_wrapped = False
_warned = False
_monitor: Optional[threading.Thread] = None
_monitor_stop = threading.Event()


# ---------------------------------------------------------------------------------------------
# post-import hooks


class _Loader(importlib.abc.Loader):
    """Runs the callbacks right after the module body has been executed."""

    def __init__(self, inner: Any, name: str) -> None:
        self._inner, self._name = inner, name

    def create_module(self, spec: Any) -> Any:
        return self._inner.create_module(spec) if hasattr(self._inner, "create_module") else None

    def exec_module(self, module: Any) -> None:
        self._inner.exec_module(module)
        _run_callbacks(self._name, module)

    def __getattr__(self, item: str) -> Any:  # get_code, get_source, get_resource_reader, ...
        return getattr(self._inner, item)


class _Finder(importlib.abc.MetaPathFinder):
    def __init__(self) -> None:
        self._busy: set = set()

    def find_spec(self, name: str, path: Any = None, target: Any = None) -> Any:
        if name not in _pending or name in self._busy:
            return None
        self._busy.add(name)
        try:
            spec = importlib.util.find_spec(name)
        except Exception:
            return None
        finally:
            self._busy.discard(name)
        if spec is None or spec.loader is None or not hasattr(spec.loader, "exec_module"):
            return None
        spec.loader = _Loader(spec.loader, name)
        return spec


def _run_callbacks(name: str, module: Any) -> None:
    with _lock:
        cbs = _pending.pop(name, [])
    for cb in cbs:
        try:
            cb(module)
        except Exception as e:  # a patch that does not fit this version: the app runs unchanged
            debug("autocapture patch failed", name, type(e).__name__)


def on_import(name: str, cb: Callable[[Any], None]) -> None:
    """Calls ``cb(module)`` once ``name`` is imported (now, when it already is)."""
    global _finder
    with _lock:
        mod = sys.modules.get(name)
        if mod is None:
            _pending.setdefault(name, []).append(cb)
            if _finder is None:
                _finder = _Finder()
                sys.meta_path.insert(0, _finder)
            return
    try:
        cb(mod)
    except Exception as e:
        debug("autocapture patch failed", name, type(e).__name__)


# ---------------------------------------------------------------------------------------------
# what has been wrapped


def note_wrapped() -> None:
    """Called when any inbound middleware is created (by a patch or by the application)."""
    global _wrapped
    _wrapped = True


def inbound_wrapped() -> bool:
    return _wrapped


def _is_ours(app: Any) -> bool:
    from .capture.asgi import ASGIMiddleware
    from .capture.wsgi import WSGIMiddleware

    return isinstance(app, (ASGIMiddleware, WSGIMiddleware)) or getattr(app, "_tt_installed", False) is True


def _nested() -> bool:
    from . import context as ctxmod

    return ctxmod.current.get() is not None


def _auto_asgi(app: Any, framework: Optional[str] = None, framework_app: Any = None) -> Any:
    from .capture.asgi import ASGIMiddleware

    class AutoASGI(ASGIMiddleware):
        # A mounted sub-application inside an application that is already captured must not
        # capture the same request a second time.
        async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
            if scope.get("type") == "http" and _nested():
                await self.app(scope, receive, send)
                return
            await ASGIMiddleware.__call__(self, scope, receive, send)

    return AutoASGI(app, framework=framework, framework_app=framework_app)


def _auto_wsgi(app: Any, framework: Optional[str] = None, framework_app: Any = None) -> Any:
    from .capture.wsgi import WSGIMiddleware

    class AutoWSGI(WSGIMiddleware):
        def __call__(self, environ: Any, start_response: Any) -> Any:
            if _nested():
                return self.app(environ, start_response)
            return WSGIMiddleware.__call__(self, environ, start_response)

    return AutoWSGI(app, framework=framework, framework_app=framework_app)


def _is_asgi_callable(app: Any) -> bool:
    from .runtime import _is_asgi

    return _is_asgi(app)


def _is_wsgi_callable(app: Any) -> bool:
    if not callable(app) or inspect.isclass(app):
        return False
    call = app if inspect.isfunction(app) or inspect.ismethod(app) else getattr(app, "__call__", None)
    try:
        n = len([p for p in inspect.signature(call).parameters.values()
                 if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD) and p.default is p.empty])
    except (TypeError, ValueError):
        return False
    return n == 2


def wrap_loaded_app(app: Any, interface: str = "auto") -> Any:
    """Wraps an application object a server has just loaded, when that is safe: a plain WSGI or
    ASGI callable that is not already captured and not a framework object the patches cover.
    Anything else (a factory, a class, an unknown shape) is returned as it is."""
    try:
        if app is None or _is_ours(app):
            return app
        if hasattr(app, "wsgi_app") and hasattr(app, "url_map"):  # Flask: wrapped by its patch
            return app
        if hasattr(app, "add_middleware") and hasattr(app, "router"):  # Starlette/FastAPI: by its patch
            return app
        if interface == "wsgi" or (interface == "auto" and not _is_asgi_callable(app) and _is_wsgi_callable(app)):
            return _auto_wsgi(app)
        if interface in ("asgi3", "auto") and _is_asgi_callable(app):
            return _auto_asgi(app)
    except Exception as e:
        debug("wrap_loaded_app failed", type(e).__name__)
    return app


# ---------------------------------------------------------------------------------------------
# patches


def _patch_stack_class(cls: Any) -> None:
    """Wraps the ``build_middleware_stack`` the class defines itself (FastAPI builds its own)."""
    if cls is None or "build_middleware_stack" not in cls.__dict__ or cls.__dict__.get("_tt_patched", False):
        return
    orig = cls.build_middleware_stack

    def build_middleware_stack(self: Any) -> Any:
        stack = orig(self)
        try:
            from .capture.asgi import ASGIMiddleware

            if getattr(self, "_tt_installed", False) or any(getattr(m, "cls", None) is ASGIMiddleware
                                                             for m in getattr(self, "user_middleware", [])):
                return stack
            out = _auto_asgi(stack, framework="fastapi", framework_app=self)
            self._tt_installed = True
            return out
        except Exception as e:
            debug("starlette patch failed", type(e).__name__)
            return stack

    cls.build_middleware_stack = build_middleware_stack
    cls._tt_patched = True


def _patch_starlette(mod: Any) -> None:
    _patch_stack_class(getattr(mod, "Starlette", None))


def _patch_fastapi(mod: Any) -> None:
    _patch_stack_class(getattr(mod, "FastAPI", None))


def _patch_flask(mod: Any) -> None:
    cls = getattr(mod, "Flask", None)
    if cls is None or getattr(cls, "_tt_patched", False):
        return
    orig = cls.__init__

    def __init__(self: Any, *a: Any, **k: Any) -> None:
        orig(self, *a, **k)
        try:
            from .capture.wsgi import WSGIMiddleware

            if not isinstance(self.wsgi_app, WSGIMiddleware) and not getattr(self, "_tt_installed", False):
                self.wsgi_app = _auto_wsgi(self.wsgi_app, framework="flask", framework_app=self)
                self._tt_installed = True
        except Exception as e:
            debug("flask patch failed", type(e).__name__)

    cls.__init__ = __init__
    cls._tt_patched = True


def _patch_django_wsgi(mod: Any) -> None:
    orig = getattr(mod, "get_wsgi_application", None)
    if orig is None or getattr(orig, "_tt_patched", False):
        return

    def get_wsgi_application() -> Any:
        app = orig()
        try:
            return app if _is_ours(app) else _auto_wsgi(app, framework="django")
        except Exception:
            return app

    get_wsgi_application._tt_patched = True  # type: ignore[attr-defined]
    mod.get_wsgi_application = get_wsgi_application


def _patch_django_asgi(mod: Any) -> None:
    orig = getattr(mod, "get_asgi_application", None)
    if orig is None or getattr(orig, "_tt_patched", False):
        return

    def get_asgi_application() -> Any:
        app = orig()
        try:
            return app if _is_ours(app) else _auto_asgi(app, framework="django")
        except Exception:
            return app

    get_asgi_application._tt_patched = True  # type: ignore[attr-defined]
    mod.get_asgi_application = get_asgi_application


def _patch_uvicorn(mod: Any) -> None:
    cfg = getattr(mod, "Config", None)
    if cfg is not None and hasattr(cfg, "load_app") and not getattr(cfg, "_tt_patched", False):
        orig = cfg.load_app

        def load_app(self: Any) -> Any:
            app = orig(self)
            if getattr(self, "factory", False):  # the factory is called afterwards: leave it alone
                return app
            return wrap_loaded_app(app, getattr(self, "interface", "auto") or "auto")

        cfg.load_app = load_app
        cfg._tt_patched = True
        return
    imp = getattr(mod, "import_from_string", None)  # older uvicorn: no load_app()
    if imp is not None and not getattr(imp, "_tt_patched", False):
        def import_from_string(import_str: Any) -> Any:
            app = imp(import_str)
            return wrap_loaded_app(app) if isinstance(import_str, str) and ":" in import_str and not _is_class_or_module(app) else app

        import_from_string._tt_patched = True  # type: ignore[attr-defined]
        mod.import_from_string = import_from_string


def _is_class_or_module(x: Any) -> bool:
    return inspect.isclass(x) or inspect.ismodule(x)


def _patch_gunicorn(mod: Any) -> None:
    orig = getattr(mod, "import_app", None)
    if orig is None or getattr(orig, "_tt_patched", False):
        return

    def import_app(module: str) -> Any:
        return wrap_loaded_app(orig(module))

    import_app._tt_patched = True  # type: ignore[attr-defined]
    mod.import_app = import_app


def _patch_outbound(name: str) -> Callable[[Any], None]:
    def patch(_mod: Any) -> None:
        from .runtime import get_agent

        a = get_agent()
        if a is not None:
            a.install_outbound_hook(name)

    return patch


def enable(outbound_auto: bool = True) -> None:
    """Registers the patches (idempotent). Called by the zero-code start."""
    global _enabled
    with _lock:
        if _enabled:
            return
        _enabled = True
    on_import("starlette.applications", _patch_starlette)
    on_import("fastapi.applications", _patch_fastapi)
    on_import("flask.app", _patch_flask)
    on_import("django.core.wsgi", _patch_django_wsgi)
    on_import("django.core.asgi", _patch_django_asgi)
    on_import("uvicorn.config", _patch_uvicorn)
    on_import("gunicorn.util", _patch_gunicorn)
    if outbound_auto:
        on_import("requests", _patch_outbound("requests"))
        on_import("httpx", _patch_outbound("httpx"))


def enabled() -> bool:
    return _enabled


# ---------------------------------------------------------------------------------------------
# "inbound not captured"


def _grace() -> float:
    v = os.environ.get("TT_INBOUND_GRACE_MS", "")
    return max(0.05, int(v) / 1000.0) if v.isdigit() else GRACE_S


def _report() -> bool:
    """One tick: True when the problem exists (and was reported)."""
    global _warned
    if _wrapped:
        return False
    if not _warned:
        _warned = True
        notice(WARNING)
    from .runtime import get_agent

    a = get_agent()
    if a is not None:
        a.note_error("inbound_not_captured")
    return True


def start_monitor() -> None:
    """After the grace period, warns once and reports ``inbound_not_captured`` while no web app
    has been wrapped. The thread ends as soon as one is."""
    global _monitor
    with _lock:
        if _monitor is not None and _monitor.is_alive():
            return
        _monitor_stop.clear()

        def run() -> None:
            from .context import mark_internal_thread

            mark_internal_thread()
            if _monitor_stop.wait(_grace()):
                return
            while not _monitor_stop.is_set():
                if not _report():
                    return
                if _monitor_stop.wait(RENOTICE_S):
                    return

        _monitor = threading.Thread(target=run, name="traffic-twin-inbound-check", daemon=True)
        _monitor.start()


def stop_monitor() -> None:
    _monitor_stop.set()


def after_fork_in_child() -> None:
    """Threads do not survive ``fork``: the check restarts in the child when it is still needed."""
    global _monitor
    _monitor = None
    if _enabled and not _wrapped:
        start_monitor()


def _reset_for_tests() -> None:  # pragma: no cover
    global _enabled, _wrapped, _warned
    _monitor_stop.set()
    _enabled = _wrapped = _warned = False
    _pending.clear()
    time.sleep(0)
