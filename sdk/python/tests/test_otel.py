"""Coexistence with OpenTelemetry (ARCHITECTURE 3.2): the app's spans are unchanged with the
SDK loaded, the SDK sets no provider or propagator, and its events reuse the app's trace."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

from .fakecore import HMAC_KEY, FakeCore
from .harness import shop_policy

try:
    import opentelemetry.sdk.trace  # noqa: F401
    HAVE_OTEL = True
except ImportError:
    HAVE_OTEL = False

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(os.path.dirname(HERE), "src")
APP = os.path.join(HERE, "fixtures", "otel_app.py")


def run_app(env_extra):
    env = dict(os.environ, PYTHONPATH=SRC + os.pathsep + os.path.dirname(HERE))
    env.update(env_extra)
    p = subprocess.run([sys.executable, APP], env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)
    if p.returncode != 0:
        raise AssertionError(p.stderr)
    return json.loads(p.stdout)


def shape(spans):
    by_id = {s["span_id"]: s for s in spans}
    out = []
    for s in spans:
        parent = by_id.get(s["parent"])
        out.append((s["name"], s["kind"], s["status"], tuple(s["attributes"]), parent["name"] if parent else None))
    return sorted(out, key=repr)


@unittest.skipUnless(HAVE_OTEL, "opentelemetry-sdk not installed")
class OtelCoexistenceTest(unittest.TestCase):
    def test_spans_unchanged_and_events_join_the_trace(self):
        without = run_app({})
        core = FakeCore(shop_policy())
        state = tempfile.mkdtemp()
        try:
            with_tt = run_app({"TT_ENROLL_URL": core.url, "TT_ENROLL_TOKEN": core.token, "TT_HMAC_KEY": HMAC_KEY,
                               "TT_SERVICE_NAME": "shop-api", "TT_STATE_DIR": state, "TT_EXPORT_FLUSH_MS": "200"})
            core.wait_for(lambda c: len(c.events) >= 6, 15)
        finally:
            events = [e["event"] for e in core.events]
            core.close()
        self.assertTrue(without["provider_is_same"] and with_tt["provider_is_same"], "the app keeps its tracer provider")
        self.assertEqual(with_tt["provider"], without["provider"])
        self.assertTrue(with_tt["propagator_same"], "the global propagator is untouched")
        self.assertEqual(len(without["spans"]), 6)
        self.assertEqual(len(with_tt["spans"]), len(without["spans"]), "same number of spans")
        self.assertEqual(shape(with_tt["spans"]), shape(without["spans"]), "same names, kinds, attributes, structure")
        traces = {s["trace_id"] for s in with_tt["spans"]}
        inbound = [e for e in events if e["dir"] == "inbound"]
        outbound = [e for e in events if e["dir"] == "outbound"]
        self.assertEqual(len(inbound), 3)
        self.assertEqual(len(outbound), 3)
        for e in inbound + outbound:
            self.assertIn(e["trace_id"], traces, "events reuse the trace of the app's spans")
        client_spans = {s["span_id"] for s in with_tt["spans"] if s["kind"] == "CLIENT"}
        # no traceparent added and no span created: the number of finished spans is the same as without tt


if __name__ == "__main__":
    unittest.main()
