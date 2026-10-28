"""Overhead micro-benchmark (threat model M12, guarantee G10).

Measures what the capture hooks add to a request, in microseconds, on a WSGI app that
reads a JSON body and writes a JSON response (about 1 KiB each way):

* ``off``      the bare app;
* ``idle``     middleware installed, capture not allowed (no policy / killed): the cost of
               every request while tt is installed but not capturing;
* ``dropped``  capture on, the exchange is not sampled (rate 0): the decision only;
* ``sampled``  capture on, 100 % sampled: tee, context, hand-off to the sanitizer thread.

The work of the sanitizer thread is not on the request path; ``sampled+bg`` runs
requests back to back and includes it (the GIL is shared), so it is the pessimistic
end-to-end figure. Run it with ``PYTHONPATH=src:. python bench/overhead.py``; it needs
nothing but the standard library (a fake tt-core from ``tests/`` is the intake).
"""

from __future__ import annotations

import io
import json
import statistics
import sys
import tempfile
import time

from tests.fakecore import HMAC_KEY
from tests.harness import Env, shop_policy
from traffic_twin.capture.wsgi import WSGIMiddleware

BODY = json.dumps({"items": [{"sku": "TSHIRT-RED-M-%03d" % i, "qty": i % 5 + 1} for i in range(12)], "email": "giulia.neri@example.com",
                   "note": "leave at the door", "total": 73.4}).encode()
OUT = json.dumps({"id": "ORD-2026-000184", "status": "CREATED", "total": 73.40,
                  "lines": [{"sku": "S-%03d" % i, "price": 9.9 + i} for i in range(20)]}).encode()


def app(environ, start_response):
    data = environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH") or 0))
    json.loads(data)
    start_response("201 Created", [("Content-Type", "application/json"), ("Content-Length", str(len(OUT)))])
    return [OUT]


def environ():
    return {"REQUEST_METHOD": "POST", "PATH_INFO": "/orders", "QUERY_STRING": "promo=AUTUMN10", "SERVER_NAME": "x", "SERVER_PORT": "80",
            "wsgi.url_scheme": "http", "wsgi.input": io.BytesIO(BODY), "CONTENT_LENGTH": str(len(BODY)),
            "CONTENT_TYPE": "application/json", "HTTP_COOKIE": "sid=9f8e7d6c5b4a", "HTTP_USER_AGENT": "bench/1.0",
            "HTTP_ACCEPT": "application/json", "HTTP_AUTHORIZATION": "Bearer abc.def.ghi"}


def sr(status, headers, exc_info=None):
    return lambda d: None


def one(a) -> None:
    r = a(environ(), sr)
    for _ in r:
        pass
    c = getattr(r, "close", None)
    if c:
        c()


def measure(a, n: int) -> list:
    out = []
    for _ in range(n):
        t = time.perf_counter_ns()
        one(a)
        out.append(time.perf_counter_ns() - t)
    return out


def pct(v: list, p: float) -> float:
    s = sorted(v)
    return s[min(len(s) - 1, int(p * len(s)))] / 1000.0


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
    rows = []
    base = measure(app, n)
    rows.append(("off", base))
    from traffic_twin.agent import Agent, AgentOptions

    idle_agent = Agent(AgentOptions())  # never started: active() is None, as with no policy or a kill switch
    rows.append(("idle", measure(WSGIMiddleware(app, host=idle_agent), n)))
    pol = shop_policy()
    pol["sampling"]["rate_bp"] = 0
    with Env(pol) as env:
        mw = WSGIMiddleware(app, host=env.agent)
        rows.append(("dropped", measure(mw, n)))
    pol5 = shop_policy()
    pol5["sampling"]["rate_bp"] = 500
    with Env(pol5) as env:
        mw = WSGIMiddleware(app, host=env.agent)
        measure(mw, 2000)
        env.agent.flush()
        t0 = time.perf_counter()
        for _ in range(n):
            one(mw)
        wall5 = time.perf_counter() - t0
        env.agent.flush(60)
    with Env(shop_policy()) as env:
        mw = WSGIMiddleware(app, host=env.agent)
        warm = measure(mw, 2000)
        env.agent.flush()
        rows.append(("sampled", measure(mw, n)))
        t0 = time.perf_counter()
        for _ in range(n):
            one(mw)
        wall = time.perf_counter() - t0
        t1 = time.perf_counter()
        env.agent.flush(60)
        drain = time.perf_counter() - t1
        st = env.agent.status()["counters"]
        # cost of sanitizing one such exchange in the sanitizer thread
        from traffic_twin.sanitizer import Exchange
        san = env.agent.active()
        ex = Exchange("inbound", "POST", b"/orders")
        ex.service_name = "shop-api"
        ex.raw_query = b"promo=AUTUMN10"
        ex.req_headers = [("Content-Type", b"application/json"), ("Cookie", b"sid=9f8e7d6c5b4a"), ("User-Agent", b"bench/1.0")]
        ex.req_body, ex.status = BODY, 201
        ex.resp_headers, ex.resp_body = [("Content-Type", b"application/json")], OUT
        t = time.perf_counter()
        for _ in range(2000):
            san.run(ex, time.time())
        san_us = (time.perf_counter() - t) / 2000 * 1e6
    print("python %s, %d requests per row" % (sys.version.split()[0], n))
    print("%-9s %9s %9s %9s %9s" % ("", "p50 us", "p99 us", "mean us", "added p50"))
    b50 = pct(base, 0.5)
    for name, v in rows:
        print("%-9s %9.1f %9.1f %9.1f %+9.1f" % (name, pct(v, 0.5), pct(v, 0.99), statistics.fmean(v) / 1000.0, pct(v, 0.5) - b50))
    print("rate 5%% with background work: %.1f us/request wall (%+.1f vs the bare app)" % (wall5 / n * 1e6, wall5 / n * 1e6 - statistics.fmean(base) / 1000.0))
    print("sanitizing one exchange (sanitizer thread, off the request path): %.0f us" % san_us)
    print("sampled+bg: %.1f us/request wall (%.1f us added to the bare app); sanitizer backlog drained in %.2f s; counters: %s"
          % (wall / n * 1e6, wall / n * 1e6 - statistics.fmean(base) / 1000.0, drain,
             {k: st[k] for k in ("exchanges_sampled", "events_sent", "events_dropped_queue", "sanitizer_errors")}))


if __name__ == "__main__":
    main()
