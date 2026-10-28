"""traffic-twin capture SDK for Python.

Zero runtime dependencies: only the standard library. Quick start::

    import traffic_twin
    app = traffic_twin.install(app)      # Flask, FastAPI/Starlette, Django, any WSGI/ASGI app

with ``TT_ENROLL_URL``, ``TT_ENROLL_TOKEN``, ``TT_HMAC_KEY`` (or ``TT_HMAC_KEY_FILE``) and
``TT_SERVICE_NAME`` in the environment. See the README.
"""

from ._version import SDK_VERSION as __version__  # noqa: F401
from .runtime import get_agent, install, start, status, stop  # noqa: F401

__all__ = ["install", "start", "stop", "status", "get_agent", "__version__"]
