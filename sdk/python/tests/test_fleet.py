"""Fleet client and agent lifecycle against the fake tt-core: enrollment with CA pin,
state files, heartbeat before capture, kill switch, min_issued_seq, signing keys, sampling
override, exporter retry. Every refusal must leave the agent in a non-capturing state."""

import json
import os
import stat
import tempfile
import time
import unittest

from traffic_twin import ed25519
from traffic_twin.agent import Agent, AgentOptions
from traffic_twin.policy import b64url_nopad
from traffic_twin.fleet import FleetError, enroll, fetch_pinned_root, token_pin

from .fakecore import HMAC_KEY, SIGNING_KID, FakeCore, base_policy, iso
from .harness import Env, shop_policy


def read_json(p):
    with open(p) as f:
        return json.load(f)


def wait_state(env, state, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        if env.agent.state == state:
            return True
        time.sleep(0.02)
    return False


class EnrollmentTest(unittest.TestCase):
    def test_enroll_pin_and_state_files(self):
        with Env() as env:
            sd = env.state_dir
            self.assertEqual(len(env.core.enrollments), 1)
            req = env.core.enrollments[0]
            self.assertNotIn("csr", req)  # the stdlib cannot build one: the no-CSR path
            self.assertEqual(req["source"]["kind"], "sdk-python")
            self.assertEqual(req["source"]["service_name"], "shop-api")
            self.assertEqual(req["source"]["hmac_kids"], ["k1"])
            self.assertEqual(stat.S_IMODE(os.stat(sd).st_mode), 0o700)
            for f in ("client.key", "enrollment.json", "client.crt", "state.json", "policy.envelope.json"):
                self.assertEqual(stat.S_IMODE(os.stat(os.path.join(sd, f)).st_mode), 0o600, f)
            # the HMAC key never leaves the process and is not in the state dir
            for f in os.listdir(sd):
                p = os.path.join(sd, f)
                if os.path.isfile(p):
                    with open(p, "rb") as fh:
                        self.assertNotIn(b"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", fh.read())
            self.assertNotIn("AAECAwQFBgc", json.dumps(env.core.heartbeats))

    def test_restart_reuses_enrollment_and_waits_for_heartbeat(self):
        with Env() as env:
            env.agent.stop()
            env.core.heartbeat_status = 500  # tt-core unreachable for heartbeats
            a2 = env.make_agent().start(wait=20)
            try:
                self.assertEqual(len(env.core.enrollments), 1)  # no second enrollment
                time.sleep(0.8)
                self.assertIsNone(a2.active(), "no capture before the first successful heartbeat")
                self.assertEqual(a2.state, "starting")
                env.core.heartbeat_status = 200
                time.sleep(1.2)
                end = time.time() + 10
                while time.time() < end and a2.state != "capturing":
                    time.sleep(0.05)
                self.assertEqual(a2.state, "capturing")
            finally:
                a2.stop()

    def test_wrong_pin_is_refused_before_the_token_is_sent(self):
        core = FakeCore()
        try:
            bad = "tte_" + "a" * 40 + "." + "A" * 43
            with self.assertRaises(FleetError) as cm:
                enroll(core.url, bad, {"kind": "sdk-python", "version": "0.1.0", "service_name": "x"}, ca_file=core.ca_file_if_needed())
            self.assertEqual(cm.exception.code, "enroll_pin_mismatch")
            self.assertEqual(core.enrollments, [])
            with self.assertRaises(FleetError) as cm:
                enroll(core.url, "nope", {})
            self.assertEqual(cm.exception.code, "enroll_token_malformed")
            with self.assertRaises(FleetError) as cm:
                enroll("http://127.0.0.1:1", core.token, {})
            self.assertEqual(cm.exception.code, "enroll_url_not_https")
            self.assertEqual(token_pin(core.token), core.pki.pin)
            self.assertIn("BEGIN CERTIFICATE", fetch_pinned_root(core.url, core.pki.pin, ca_file=core.ca_file_if_needed()))
        finally:
            core.close()

    def test_unknown_token_is_not_retried_forever(self):
        core = FakeCore()
        try:
            st = tempfile.mkdtemp()
            tok = "tte_" + "b" * 40 + "." + core.pki.pin
            a = Agent(AgentOptions(enroll_url=core.url, enroll_token=tok, hmac_key=HMAC_KEY, service_name="shop-api", state_dir=st, ca_file=core.ca_file_if_needed())).start(wait=15)
            self.assertIsNone(a.active())
            self.assertEqual(a.state, "no_policy")
            self.assertTrue(any(e["code"] == "enroll_http_401" for e in a._last_errors))
            a.stop()
        finally:
            core.close()


class PolicyAcceptanceTest(unittest.TestCase):
    def test_no_policy_404(self):
        with Env(wait_capturing=False) as env:
            pass
        core = FakeCore(policy=None)
        core.policy_body = None
        core.envelope = None
        env = Env.__new__(Env)
        env.core, env.state_dir, env.agent_kw, env.wait_capturing, env.agent = core, tempfile.mkdtemp(), {}, False, None
        with env:
            self.assertTrue(wait_state(env, "no_policy"))
            self.assertIsNone(env.agent.active())

    def test_replay_group_expiry_signature(self):
        with Env() as env:
            core = env.core
            ag = env.agent
            core.set_policy(shop_policy(), bump=False)  # same seq: no change
            core.set_policy(dict(shop_policy(), issued_seq=3, version=3), bump=False)
            end = time.time() + 10
            while time.time() < end and ag._policy.issued_seq != 3:
                time.sleep(0.05)
            self.assertEqual(ag._policy.issued_seq, 3)
            # replay of an older (validly signed) policy: kept on seq 3
            core.set_policy(dict(shop_policy(), issued_seq=2, version=2), bump=False)
            time.sleep(1.5)
            self.assertEqual(ag._policy.issued_seq, 3)
            self.assertEqual(ag.state, "capturing")
            self.assertTrue(any(e["code"] == "policy_rejected" for e in ag._last_errors))
            # wrong group
            bad = dict(shop_policy(), issued_seq=4, version=4)
            bad["targets"] = {"groups": ["other-group"]}
            core.set_policy(bad, bump=False)
            time.sleep(1.5)
            self.assertEqual(ag._policy.issued_seq, 3)
            # signed with an unknown key
            other = os.urandom(32)
            core.policy_body = dict(shop_policy(), issued_seq=5, version=5)
            core.envelope = core.make_envelope(core.policy_body, seed=other)
            time.sleep(1.5)
            self.assertEqual(ag._policy.issued_seq, 3)
            # tampered body
            env_ = core.make_envelope(dict(shop_policy(), issued_seq=6, version=6))
            env_["body_b64"] = env_["body_b64"][:-4] + "AAAA"
            core.envelope = env_
            time.sleep(1.5)
            self.assertEqual(ag._policy.issued_seq, 3)
            self.assertEqual(ag.state, "capturing", "a rejected policy never replaces the valid one")

    def test_expired_policy_stops_capture(self):
        with Env() as env:
            pol = dict(shop_policy(), issued_seq=2, version=2)
            pol["created_at"] = iso(time.time() - 7200)
            pol["not_after"] = iso(time.time() - 3600)
            env.core.set_policy(pol, bump=False)
            time.sleep(1.5)
            self.assertEqual(env.agent.state, "capturing")  # the expired one was rejected, the valid one is kept
            # a source that restarts with only an expired policy does not capture
            env.agent.stop()
            os.unlink(os.path.join(env.state_dir, "policy.envelope.json"))  # no valid cache left
            env.core.set_policy(None)
            env.core.envelope = env.core.make_envelope(pol)
            a2 = env.make_agent().start(wait=15)
            try:
                time.sleep(1.0)
                self.assertIsNone(a2.active())
                self.assertIn(a2.state, ("expired_policy", "policy_rejected"))
            finally:
                a2.stop()

    def test_min_issued_seq_from_heartbeat(self):
        with Env() as env:
            env.core.min_issued_seq = 5
            self.assertTrue(wait_state(env, "policy_rejected"))
            self.assertIsNone(env.agent.active())
            env.core.set_policy(shop_policy())  # bumped above the current seq, still < 5
            env.core.set_policy(dict(shop_policy(), issued_seq=6, version=6), bump=False)
            self.assertTrue(wait_state(env, "capturing"))
            self.assertEqual(env.agent.status()["state"], "capturing")

    def test_normal_policy_change_reports_no_error(self):
        # Usability test 4: tt-core moves min_issued_seq to the new policy in the same heartbeat
        # that announces it; the source switches without an error or a policy_rejected state.
        with Env() as env:
            start = len(env.core.heartbeats)
            for _ in range(3):
                env.core.set_policy(shop_policy())
                seq = env.core.policy_body["issued_seq"]
                env.core.min_issued_seq = seq
                self.assertTrue(env.core.wait_for(lambda c: bool(c.heartbeats) and c.heartbeats[-1].get("state") == "capturing"
                                                  and (c.heartbeats[-1].get("policy") or {}).get("issued_seq") == seq))
            hbs = env.core.heartbeats[start:]
            self.assertNotIn("policy_rejected", [h.get("state") for h in hbs])
            codes = [e["code"] for e in env.agent._last_errors]
            self.assertNotIn("policy_below_min_issued_seq", codes)
            self.assertNotIn("policy_rejected", codes)

    def test_hmac_key_states(self):
        with Env(hmac_key="k2:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", wait_capturing=False) as env:
            self.assertTrue(wait_state(env, "key_mismatch"))
            self.assertIsNone(env.agent.active())
        with Env(hmac_key="k1:c2hvcnQ", wait_capturing=False) as env:  # shorter than 32 bytes
            self.assertTrue(wait_state(env, "key_missing"))
            self.assertIsNone(env.agent.active())
        with Env(hmac_key=None, wait_capturing=False) as env:
            self.assertTrue(wait_state(env, "key_missing"))
        with tempfile.NamedTemporaryFile("w", suffix=".key", delete=False) as f:
            f.write(HMAC_KEY + "\r\n\r\n")
        try:
            with Env(hmac_key=None, hmac_key_file=f.name) as env:
                self.assertEqual(env.agent.state, "capturing")
        finally:
            os.unlink(f.name)


class HeartbeatCommandsTest(unittest.TestCase):
    def test_kill_switch_persists_across_restart(self):
        with Env() as env:
            env.core.kill = True
            self.assertTrue(wait_state(env, "killed"))
            self.assertIsNone(env.agent.active())
            st = read_json(os.path.join(env.state_dir, "state.json"))
            self.assertTrue(st["kill"])
            env.agent.stop()
            env.core.heartbeat_status = 500  # tt-core unreachable: the switch must still hold
            a2 = env.make_agent().start(wait=20)
            try:
                time.sleep(0.8)
                self.assertEqual(a2.state, "killed")
                self.assertIsNone(a2.active())
                env.core.heartbeat_status = 200
                env.core.kill = False
                end = time.time() + 10
                while time.time() < end and a2.state != "capturing":
                    time.sleep(0.05)
                self.assertEqual(a2.state, "capturing")
            finally:
                a2.stop()

    def test_revoked_source_stops_and_stays_stopped(self):
        with Env() as env:
            env.core.heartbeat_status = 403
            self.assertTrue(wait_state(env, "killed"))
            self.assertTrue(read_json(os.path.join(env.state_dir, "state.json"))["revoked"])

    def test_sampling_override_only_lowers(self):
        with Env() as env:
            ag = env.agent
            self.assertEqual(ag.active().rate_bp(), 10000)
            env.core.sampling_override_bp = 0
            end = time.time() + 10
            while time.time() < end and ag.active() is not None and ag.active().rate_bp() != 0:
                time.sleep(0.05)
            self.assertEqual(ag.active().rate_bp(), 0)
            env.core.sampling_override_bp = None
            end = time.time() + 10
            while time.time() < end and ag.active().rate_bp() != 10000:
                time.sleep(0.05)
            self.assertEqual(ag.active().rate_bp(), 10000)
        pol = shop_policy()
        pol["sampling"]["rate_bp"] = 100
        with Env(pol) as env:
            env.core.sampling_override_bp = 10000
            time.sleep(1.2)
            self.assertEqual(env.agent.active().rate_bp(), 100, "an override can never raise the rate")

    def test_signing_key_rotation_and_revocation(self):
        with Env() as env:
            core, ag = env.core, env.agent
            new_seed = os.urandom(32)
            new_pub = ed25519.public_key(new_seed)
            kid = "policy-test-2"
            msg = b"tt-fleet-key/v1\x00" + kid.encode() + b"\x00" + new_pub
            good = {"kid": kid, "alg": "Ed25519", "public_key": b64url_nopad(new_pub), "endorsed_by": SIGNING_KID,
                    "endorsement": b64url_nopad(ed25519.sign(core.signer_seed, msg))}
            forged = dict(good, kid="policy-test-3", endorsement=b64url_nopad(ed25519.sign(os.urandom(32), b"x")))
            core.extra_heartbeat = {"add_signing_keys": [good, forged]}
            end = time.time() + 10
            while time.time() < end and "policy-test-2" not in ag._signing_keys():
                time.sleep(0.05)
            keys = ag._signing_keys()
            self.assertIn("policy-test-2", keys)
            self.assertNotIn("policy-test-3", keys)
            # a policy signed by the new key is accepted
            pol = dict(shop_policy(), issued_seq=9, version=9)
            core.policy_body = pol
            core.envelope = core.make_envelope(pol, kid="policy-test-2", seed=new_seed)
            end = time.time() + 10
            while time.time() < end and ag._policy.issued_seq != 9:
                time.sleep(0.05)
            self.assertEqual(ag._policy.issued_seq, 9)
            # revoke the key that signed the running policy: capture stops
            core.extra_heartbeat = {"revoke_signing_keys": ["policy-test-2"]}
            self.assertTrue(wait_state(env, "policy_rejected"))
            self.assertIsNone(ag.active())
            self.assertNotIn("policy-test-2", ag._signing_keys())



def endorsed_key(endorser_seed, endorsed_by, kid, new_seed):
    """The add_signing_keys entry for ``new_seed`` endorsed by ``endorser_seed`` (pinned as ``endorsed_by``)."""
    pub = ed25519.public_key(new_seed)
    msg = b"tt-fleet-key/v1\x00" + kid.encode() + b"\x00" + pub
    return {"kid": kid, "alg": "Ed25519", "public_key": b64url_nopad(pub), "endorsed_by": endorsed_by,
            "endorsement": b64url_nopad(ed25519.sign(endorser_seed, msg))}


def wait_heartbeats(core, n, timeout=15.0):
    k = len(core.heartbeats)
    return core.wait_for(lambda c: len(c.heartbeats) >= k + n, timeout)


def key_errors(hb):
    return [e["code"] for e in hb.get("last_errors") or [] if e["code"].startswith("signing_key")]


def publish(core, issued_seq, kid=SIGNING_KID, seed=None):
    pol = dict(shop_policy(), issued_seq=issued_seq, version=issued_seq)
    core.policy_body = pol
    core.envelope = core.make_envelope(pol, kid=kid, seed=seed)


class SigningKeyRotationTest(unittest.TestCase):
    def test_key_endorsed_by_kid_revoked_in_same_heartbeat_is_not_pinned(self):
        with Env() as env:
            core, ag = env.core, env.agent
            self.assertEqual(core.heartbeats[-1]["signing_kids"], [SIGNING_KID])
            evil = os.urandom(32)
            core.extra_heartbeat = {"revoke_signing_keys": [SIGNING_KID],
                                    "add_signing_keys": [endorsed_key(core.signer_seed, SIGNING_KID, "policy-evil-1", evil)]}
            self.assertTrue(wait_heartbeats(core, 2))
            self.assertEqual(ag._signing_keys(), {})
            publish(core, 9, kid="policy-evil-1", seed=evil)
            self.assertTrue(wait_heartbeats(core, 3))
            hb = core.heartbeats[-1]
            self.assertEqual(hb["signing_kids"], [])
            self.assertNotEqual((hb.get("policy") or {}).get("issued_seq"), 9)
            self.assertIsNone(ag.active())
            self.assertNotEqual(ag.state, "capturing")
            saved = read_json(os.path.join(env.state_dir, "state.json"))
            self.assertEqual(saved["revoked_kids"], [SIGNING_KID])
            self.assertNotIn("policy-evil-1", [k["kid"] for k in saved.get("added_keys") or []])

    def test_endorsed_rotation_then_revocation_survives_restart(self):
        with Env() as env:
            core, ag = env.core, env.agent
            k2, k3 = os.urandom(32), os.urandom(32)
            # policy-test-3 is endorsed by policy-test-2, pinned earlier in the same list.
            adds = [endorsed_key(core.signer_seed, SIGNING_KID, "policy-test-2", k2),
                    endorsed_key(k2, "policy-test-2", "policy-test-3", k3)]
            core.extra_heartbeat = {"add_signing_keys": adds}
            self.assertTrue(core.wait_for(lambda c: len(c.heartbeats[-1].get("signing_kids") or []) == 3))
            self.assertEqual(core.heartbeats[-1]["signing_kids"], [SIGNING_KID, "policy-test-2", "policy-test-3"])
            publish(core, 5, kid="policy-test-2", seed=k2)
            self.assertTrue(core.wait_for(lambda c: (c.heartbeats[-1].get("policy") or {}).get("issued_seq") == 5))
            self.assertTrue(wait_heartbeats(core, 1))  # acceptance (and its state write) is complete

            # The same keys at every heartbeat: no error, no rewrite of state.json.
            sp = os.path.join(env.state_dir, "state.json")
            m0 = os.stat(sp).st_mtime_ns
            self.assertTrue(wait_heartbeats(core, 3))
            self.assertEqual(key_errors(core.heartbeats[-1]), [])
            self.assertEqual(os.stat(sp).st_mtime_ns, m0, "state.json rewritten for keys already pinned")

            core.extra_heartbeat = {"add_signing_keys": adds, "revoke_signing_keys": [SIGNING_KID]}
            self.assertTrue(core.wait_for(lambda c: len(c.heartbeats[-1].get("signing_kids") or [SIGNING_KID]) == 2))
            self.assertTrue(wait_heartbeats(core, 2))
            hb = core.heartbeats[-1]
            self.assertEqual(hb["signing_kids"], ["policy-test-2", "policy-test-3"])
            self.assertEqual(hb["state"], "capturing")
            self.assertEqual(ag.state, "capturing")
            self.assertEqual(key_errors(hb), [])

            # A kid already pinned with another key is refused.
            core.extra_heartbeat = {"add_signing_keys": adds + [endorsed_key(k2, "policy-test-2", "policy-test-3", os.urandom(32))],
                                    "revoke_signing_keys": [SIGNING_KID]}
            self.assertTrue(core.wait_for(lambda c: "signing_key_conflict" in key_errors(c.heartbeats[-1])))
            self.assertEqual(ed25519.public_key(k3), ag._signing_keys()["policy-test-3"])

            env.agent.stop()
            core.extra_heartbeat = {}
            n = len(core.heartbeats)
            a2 = env.make_agent().start(wait=20)
            try:
                self.assertTrue(core.wait_for(lambda c: len(c.heartbeats) > n and a2.state == "capturing"))
                self.assertEqual(core.heartbeats[-1]["signing_kids"], ["policy-test-2", "policy-test-3"])
                self.assertEqual(a2._policy.issued_seq, 5)
                publish(core, 6)  # signed by the revoked enrollment key
                self.assertTrue(wait_heartbeats(core, 3))
                self.assertEqual(a2._policy.issued_seq, 5, "policy signed by a revoked key accepted after restart")
                publish(core, 7, kid="policy-test-3", seed=k3)
                self.assertTrue(core.wait_for(lambda c: a2._policy is not None and a2._policy.issued_seq == 7),
                                "rotated key lost after restart")
            finally:
                a2.stop()

class ExporterTest(unittest.TestCase):
    def test_retry_with_retry_after_then_delivery(self):
        with Env() as env:
            env.core.fail_logs = 2
            env.agent.exporter_for_test = env.agent._exporter
            env.agent._exporter.base_backoff_s = 0.05
            from tests.test_wsgi import tiny_app
            from traffic_twin.capture.wsgi import WSGIMiddleware
            from .harness import WsgiRunner, call
            with WsgiRunner(WSGIMiddleware(tiny_app, host=env.agent)) as srv:
                call(srv.port, "GET", "/orders/ORD-1")
            evs = env.events(n=1, timeout=20)
            self.assertEqual(len(evs), 1)
            self.assertGreaterEqual(env.agent.counters.get("send_errors"), 2)
            self.assertEqual(env.agent.counters.get("events_sent"), 1)

    def test_400_drops_without_retry_and_counts_rejected(self):
        with Env() as env:
            env.core.fail_logs, env.core.fail_logs_status = 1, 400
            from tests.test_wsgi import tiny_app
            from traffic_twin.capture.wsgi import WSGIMiddleware
            from .harness import WsgiRunner, call
            with WsgiRunner(WSGIMiddleware(tiny_app, host=env.agent)) as srv:
                call(srv.port, "GET", "/orders/ORD-1")
            env.agent.flush()
            self.assertEqual(env.agent.counters.get("events_rejected"), 1)
            self.assertEqual(env.core.events, [])

    def test_queue_drops_oldest_and_counts(self):
        from traffic_twin.event import QueuedEvent
        from traffic_twin.exporter import Counters, Exporter
        import ssl
        c = Counters()
        ex = Exporter("https://127.0.0.1:1/v1/logs", ssl.create_default_context(), "svc", "src-1", c, lambda code: None, max_events=3)
        for i in range(5):
            ex.enqueue(QueuedEvent('{"n":%d}' % i, 0, None, None, "sha256:x"))
        self.assertEqual(ex.size["events"], 3)
        self.assertEqual(c.get("events_dropped_queue"), 2)
        self.assertEqual([e.json for e in ex._q], ['{"n":2}', '{"n":3}', '{"n":4}'])


if __name__ == "__main__":
    unittest.main()
