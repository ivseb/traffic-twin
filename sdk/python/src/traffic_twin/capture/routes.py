"""``framework_route`` extraction (sanitizer.md 3.3, 3.4).

The route must be complete with the mount prefixes, or absent. The resolvers run in the
sanitizer thread, after the response, on a snapshot of the request taken at its start;
they ask the framework's own router which route matches and never run application code.
Any failure means "no route": the sanitizer then falls back to the policy templates.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple


def resolve_flask(flask_app: Any, environ: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """``('flask', '/api/orders/<int:id>')`` from the Flask URL map."""
    try:
        subdomain = (flask_app.url_map.default_subdomain or None) if not getattr(flask_app, "subdomain_matching", False) else None
        adapter = flask_app.url_map.bind_to_environ(environ, server_name=flask_app.config.get("SERVER_NAME"), subdomain=subdomain)
        rule, _args = adapter.match(return_rule=True)
        prefix = (environ.get("SCRIPT_NAME") or "").rstrip("/")
        return "flask", prefix + rule.rule
    except Exception:
        return None


def _starlette_match(routes: List[Any], scope: Dict[str, Any], prefix: str, depth: int = 0) -> Optional[str]:
    from starlette.routing import Match  # type: ignore

    if depth > 8:
        return None
    for route in routes:
        try:
            match, child = route.matches(scope)
        except Exception:
            continue
        if match != Match.FULL:
            continue
        sub = getattr(route, "routes", None)
        path = getattr(route, "path", None)
        if sub:  # Mount / Host: descend with the child scope
            child_scope = dict(scope)
            child_scope.update(child)
            mount = path if isinstance(path, str) else ""
            return _starlette_match(list(sub), child_scope, prefix + mount, depth + 1)
        if isinstance(path, str):
            return prefix + path
        return None
    return None


def resolve_starlette(app: Any, scope: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """``('fastapi', '/orders/{order_id:int}')`` for Starlette and FastAPI apps."""
    try:
        router = getattr(app, "router", app)
        routes = list(getattr(router, "routes", []) or [])
        r = _starlette_match(routes, scope, "")
        if r is None:
            return None
        root = (scope.get("app_root_path") or "").rstrip("/")
        return "fastapi", root + r
    except Exception:
        return None


def resolve_django(path_info: str, script_name: str = "") -> Optional[Tuple[str, str]]:
    """``('django', '/orders/<int:pk>/')`` from the URL resolver. ``re_path`` routes keep
    their regular expression, which the sanitizer refuses to normalize (3.4)."""
    try:
        from django.urls import resolve  # type: ignore

        m = resolve(path_info)
        route = getattr(m, "route", None)
        if not isinstance(route, str):
            return None
        return "django", (script_name.rstrip("/") + "/" + route.lstrip("/"))
    except Exception:
        return None


Resolver = Callable[[], Optional[Tuple[str, str]]]
