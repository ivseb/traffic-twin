"""Process-wide agent: ``start``, ``stop``, ``current``, and the framework helpers
(``install``). One agent per process; ``start`` is idempotent and never raises.

Forking servers (gunicorn with ``--preload``, uWSGI, multiprocessing): threads do not
survive ``fork``, so a child process builds a fresh agent from the same options. They
share the state directory (enrollment, key, cache); enrollment is serialized with a file
lock, so a one-time token is consumed once.
"""

from __future__ import annotations

import os
import threading
from typing import Any, Callable, Dict, Optional

from ._log import debug
from .agent import Agent, AgentOptions, options_from_env

_lock = threading.Lock()
_agent: Optional[Agent] = None
_options: Optional[AgentOptions] = None


def get_agent() -> Optional[Agent]:
    return _agent


def start(*, wait: float = 0.0, env: Optional[Dict[str, str]] = None, **overrides: Any) -> Agent:
    """Starts the agent from the environment (``TT_*``) and keyword overrides
    (``enroll_url``, ``enroll_token``, ``hmac_key``, ``hmac_key_file``, ``service_name``,
    ``state_dir``, ``outbound``, ...). Idempotent: a second call returns the running agent."""
    global _agent, _options
    with _lock:
        if _agent is not None:
            return _agent
        try:
            opts = options_from_env(env)
            for k, v in overrides.items():
                if hasattr(opts, k) and v is not None:
                    setattr(opts, k, v)
        except Exception:
            opts = AgentOptions()
        _options = opts
        _agent = Agent(opts)
        a = _agent
    a.start(wait=wait)
    return a


def stop() -> None:
    global _agent
    with _lock:
        a, _agent = _agent, None
    if a is not None:
        a.stop()


def status() -> Optional[Dict[str, Any]]:
    a = _agent
    return a.status() if a is not None else None


def _after_fork_in_child() -> None:
    global _agent
    old = _agent
    if old is None or _options is None:
        return
    # Locks and threads of the parent are not valid here; sockets are shared with the
    # parent and must not be closed (that would send a TLS close_notify): just drop them.
    try:
        globals()["_lock"] = threading.Lock()
        _agent = Agent(_options)
        # The outbound patches of the parent live on in the child and follow the process-wide agent.
        _agent._uninstall, _agent._hooks_inherited = old._uninstall, True
        _agent.start()
        debug("agent restarted after fork, pid", os.getpid())
        from . import autocapture

        autocapture.after_fork_in_child()
    except Exception:
        _agent = None


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)


def ensure_started() -> Optional[Agent]:
    """Starts the agent from the environment if it is not running (used by ``install``)."""
    return _agent if _agent is not None else start()


# ---------------------------------------------------------------------------------
# install(app): framework helpers


def _is_asgi(app: Any) -> bool:
    import inspect

    call = app if inspect.isfunction(app) or inspect.ismethod(app) else getattr(app, "__call__", app)
    if inspect.iscoroutinefunction(call):
        return True
    try:
        n = len([p for p in inspect.signature(call).parameters.values()
                 if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD) and p.default is p.empty])
    except (TypeError, ValueError):
        return False
    return n == 3


def install(app: Any, *, kind: Optional[str] = None, start_agent: bool = True, **start_overrides: Any) -> Any:
    """Adds the inbound capture to a web app and returns it.

    * **Flask** (and Quart-less Werkzeug apps with ``wsgi_app``): ``app.wsgi_app`` is wrapped in place.
    * **FastAPI / Starlette**: the ASGI middleware is added with ``add_middleware`` (outermost).
    * **Django**: pass the ``get_wsgi_application()`` / ``get_asgi_application()`` object; the
      wrapped application is **returned** (assign it back to ``application``).
    * **Any other WSGI or ASGI callable**: the wrapped callable is returned.

    ``kind`` (``'wsgi'`` or ``'asgi'``) overrides the detection. The agent starts from the
    environment unless ``start_agent=False``.
    """
    from .capture.asgi import ASGIMiddleware
    from .capture.wsgi import WSGIMiddleware

    if start_agent:
        try:
            start(**start_overrides)
        except Exception:
            debug("start failed")
    mod = type(app).__module__ or ""
    top = mod.split(".")[0]
    try:
        if isinstance(app, (ASGIMiddleware, WSGIMiddleware)) or getattr(app, "_tt_installed", False) is True:
            return app  # already captured (by an earlier install() or by the zero-code start)
        if kind is None:
            if hasattr(app, "wsgi_app") and hasattr(app, "url_map"):  # Flask
                if isinstance(app.wsgi_app, WSGIMiddleware):
                    return app
                app.wsgi_app = WSGIMiddleware(app.wsgi_app, framework="flask", framework_app=app)
                app._tt_installed = True
                return app
            if hasattr(app, "add_middleware") and hasattr(app, "router"):  # Starlette / FastAPI
                app.add_middleware(ASGIMiddleware, framework="fastapi", framework_app=app)
                app._tt_installed = True
                return app
            if top == "django":
                if _is_asgi(app) or "asgi" in mod:
                    return ASGIMiddleware(app, framework="django")
                return WSGIMiddleware(app, framework="django")
        if kind == "asgi" or (kind is None and _is_asgi(app)):
            return ASGIMiddleware(app)
        return WSGIMiddleware(app)
    except Exception as e:
        import warnings

        warnings.warn("traffic_twin.install: not installed (%s); the app is unchanged" % type(e).__name__, RuntimeWarning, stacklevel=2)
        return app
