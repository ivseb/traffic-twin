"""Forking servers: threads do not survive fork(); the child rebuilds the agent from the
same options and the shared state directory (no second enrollment)."""

import os
import subprocess
import sys
import tempfile
import unittest

from .fakecore import HMAC_KEY, FakeCore
from .harness import shop_policy

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(os.path.dirname(HERE), "src")

SCRIPT = r"""
import os, sys, time, traffic_twin
a = traffic_twin.start(wait=30)
end = time.time() + 20
while time.time() < end and a.state != 'capturing': time.sleep(0.05)
assert a.state == 'capturing', a.state
pid = os.fork()
if pid == 0:
    b = traffic_twin.get_agent()
    assert b is not a, 'child must have a fresh agent'
    end = time.time() + 20
    while time.time() < end and b.state != 'capturing': time.sleep(0.05)
    sys.stdout.write('child:' + b.state + '\n'); sys.stdout.flush()
    os._exit(0 if b.state == 'capturing' else 3)
_, status = os.waitpid(pid, 0)
sys.stdout.write('parent:%d\n' % os.WEXITSTATUS(status))
traffic_twin.stop()
"""


@unittest.skipUnless(hasattr(os, "fork"), "POSIX only")
class ForkTest(unittest.TestCase):
    def test_child_gets_its_own_agent(self):
        core = FakeCore(shop_policy())
        state = tempfile.mkdtemp()
        env = dict(os.environ, PYTHONPATH=SRC, TT_ENROLL_URL=core.url, TT_ENROLL_TOKEN=core.token, TT_HMAC_KEY=HMAC_KEY,
                   TT_SERVICE_NAME="shop-api", TT_STATE_DIR=state, TT_HEARTBEAT_INTERVAL_MS="500")
        if core.ca_file_if_needed():
            env["TT_ENROLL_CA_FILE"] = core.ca_file_if_needed()
        try:
            p = subprocess.run([sys.executable, "-c", SCRIPT], env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("child:capturing", p.stdout)
            self.assertIn("parent:0", p.stdout)
            self.assertEqual(len(core.enrollments), 1, "the child reuses the enrollment of the shared state dir")
        finally:
            core.close()


if __name__ == "__main__":
    unittest.main()
