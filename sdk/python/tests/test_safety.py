"""v1.3 source-side safety subset (docs/spec/hardening.md 2.1): H1, H2, H3."""

import calendar
import json
import time
import unittest

from traffic_twin.jsonlex import parse_plain
from traffic_twin.policy import Refused, UNSAFE_DETAIL, validate_body_schema

from tests.fakecore import base_policy

SVC = {"name": "shop-api", "match": {"inbound": True, "internal": False}, "ops": []}
WEEK = 7 * 86400


def outcome(body):
    plain = parse_plain(json.dumps(body).encode("utf-8"), True)
    try:
        validate_body_schema(plain)
    except Refused as e:
        return "unsafe" if e.detail.startswith(UNSAFE_DETAIL) else e.code
    return "accepted"


def at(body, seconds):
    t = calendar.timegm(time.strptime(body["created_at"], "%Y-%m-%dT%H:%M:%SZ")) + seconds
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


class SafetySubsetTest(unittest.TestCase):
    def test_h1_credential_headers(self):
        for h in ("authorization", "cookie", "set-cookie", "proxy-authorization"):
            for action in ({"action": "keep"}, {"action": "hmac", "domain": "tok"}):
                rule = {"headers": {h: action}}
                what = "%s %s" % (h, action["action"])
                places = {
                    "global request": base_policy(**{"global": {"request": rule}}),
                    "global response": base_policy(**{"global": {"response": rule}}),
                    "global errors": base_policy(**{"global": {"errors": rule}}),
                    "service errors": base_policy(services=[dict(SVC, errors=rule)]),
                    "op request": base_policy(services=[dict(SVC, ops=[{"op": "GET /a", "request": rule}])]),
                    "op response": base_policy(services=[dict(SVC, ops=[{"op": "GET /a", "response": rule}])]),
                }
                for place, body in places.items():
                    self.assertEqual(outcome(body), "unsafe", place + " " + what)
        drop = base_policy(**{"global": {"request": {"headers": {"authorization": {"action": "drop"}}}}})
        self.assertEqual(outcome(drop), "accepted")

    def test_h2_global_star(self):
        def g(action, path="$.a.*"):
            return base_policy(**{"global": {"response": {"body": [{"path": path, "action": action}]}}})
        self.assertEqual(outcome(g({"action": "keep"})), "unsafe")
        self.assertEqual(outcome(g({"action": "hmac", "domain": "tok"}, "$.items[*].*")), "unsafe")
        self.assertEqual(outcome(g({"action": "drop"})), "accepted")
        rule = [{"path": "$.*", "action": {"action": "keep"}}]
        self.assertEqual(outcome(base_policy(services=[dict(SVC, request={"body": rule})])), "accepted")
        self.assertEqual(outcome(base_policy(services=[dict(SVC, ops=[{"op": "GET /a", "response": {"body": rule}}])])),
                         "accepted")

    def test_h3_windows(self):
        def win(field, seconds):
            body = base_policy()
            when = at(body, seconds)  # relative to the body's own created_at
            if field == "discovery":
                body["discovery"] = {"enabled": True, "expires_at": when}
            else:
                body["segments"] = {"auto_words": True, "auto_words_expires_at": when, "allow": [], "hosts_allow": []}
            return body
        for field in ("discovery", "auto_words"):
            self.assertEqual(outcome(win(field, WEEK)), "accepted", field + " at exactly 7 days")
            self.assertEqual(outcome(win(field, WEEK + 1)), "unsafe", field + " at 7 days + 1 s")
        off = base_policy()
        off["discovery"] = {"enabled": False, "expires_at": at(off, 30 * 86400)}
        self.assertEqual(outcome(off), "accepted")


if __name__ == "__main__":
    unittest.main()
