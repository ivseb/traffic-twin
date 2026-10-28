"""Overhead guard: the request path stays cheap (generous bounds, not a benchmark; the real
figures come from ``make bench``). Idle and unsampled requests cost a few microseconds,
a sampled one tens, and the work of the sanitizer thread is not on the request path."""

import unittest

from bench.overhead import app, measure, pct
from traffic_twin.agent import Agent, AgentOptions
from traffic_twin.capture.wsgi import WSGIMiddleware

from .harness import Env, shop_policy


class OverheadTest(unittest.TestCase):
    N = 3000

    def test_request_path_overhead(self):
        base = pct(measure(app, self.N), 0.5)
        idle = pct(measure(WSGIMiddleware(app, host=Agent(AgentOptions())), self.N), 0.5)
        pol = shop_policy()
        pol["sampling"]["rate_bp"] = 0
        with Env(pol) as env:
            dropped = pct(measure(WSGIMiddleware(app, host=env.agent), self.N), 0.5)
        with Env(shop_policy()) as env:
            sampled = pct(measure(WSGIMiddleware(app, host=env.agent), self.N), 0.5)
        print("\n  overhead p50 (us): bare %.1f, idle %+.1f, not sampled %+.1f, sampled %+.1f" % (base, idle - base, dropped - base, sampled - base))
        self.assertLess(idle - base, 20)
        self.assertLess(dropped - base, 60)
        self.assertLess(sampled - base, 300)


if __name__ == "__main__":
    unittest.main()
