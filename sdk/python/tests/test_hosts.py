"""Spec v1.5 host autodiscovery: IPv6 parser, host patterns, IP classes, service selection,
the ``hosts`` policy object, and G1 with host labels (sanitizer.md 3.1, 3.5, 3.6, 13)."""

import os
import random
import re
import unittest

from traffic_twin.conformance import find_conformance_dir
from traffic_twin.hostpat import host_label_safe, host_pattern, parse_ipv6
from traffic_twin.jsonlex import parse_plain
from traffic_twin.policy import Policy, Refused, parse_key_ring, select_key, validate_body_schema
from traffic_twin.sanitizer import Exchange, Sanitizer, normalize_url_base

KEY = "k1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"


def empty_body():
    with open(os.path.join(find_conformance_dir(), "policies", "empty.json"), "rb") as f:
        return parse_plain(f.read(), True)


def sanitizer(**extra):
    body = empty_body()
    body.update(extra)
    policy = Policy(validate_body_schema(body))
    kid, key = select_key(parse_key_ring(KEY), policy)
    return Sanitizer(policy, kid, key)


def service(san, url_base):
    ex = Exchange("outbound", "GET", b"/x")
    ex.url_base = url_base
    ex.status = 200
    res = san.run(ex, 1.7e9)
    assert res.outcome == "event"
    m = re.search(r'"service":"([^"]*)"', res.canonical)
    return m.group(1)


def pattern_of(u):
    b = normalize_url_base(u)
    if b.invalid:
        return "invalid"
    p = host_pattern(b.host, b.port, b.ip6)
    return "invalid" if p is None else p


class Ipv6ParserTest(unittest.TestCase):
    def test_accepted_and_refused_forms(self):
        ok = ["::", "::1", "1::", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7::", "::2:3:4:5:6:7:8", "1::8", "::ffff:1.2.3.4",
              "64:ff9b::10.0.0.1", "1:2:3:4:5:6:1.2.3.4", "abcd::ef", "0:0:0:0:0:0:0:0"]
        for a in ok:
            self.assertIsNotNone(parse_ipv6(a), a)
        bad = ["", ":", ":::", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7:8::", "::1:2:3:4:5:6:7:8", "1::2::3",
               "12345::", "g::", "::1.2.3", "::1.2.3.04", "::1.2.3.256", "1.2.3.4::", "::1.2.3.4:1", "1.2.3.4",
               "fe80::1%eth0", ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:", " ::1", "::1 ", "::ffff:1.2.3.4.5", "::١"]
        for a in bad:
            self.assertIsNone(parse_ipv6(a), repr(a))
        self.assertEqual(parse_ipv6("::ffff:1.2.3.4"), bytes([0] * 10 + [0xFF, 0xFF, 1, 2, 3, 4]))

    def test_url_base_with_brackets(self):
        b = normalize_url_base("https://[2001:DB8::1]:8443")
        self.assertFalse(b.invalid)
        self.assertEqual((b.hostport, b.port), ("[2001:db8::1]:8443", "8443"))
        self.assertIsNone(normalize_url_base("https://[::1]").port)
        self.assertIsNone(normalize_url_base("http://[::1]:80").port)
        for bad in ["https://[::1", "https://[::1]x", "https://[::1]:", "https://[::1]:0", "https://[::1%eth0]",
                    "https://[]", "https://[::1]/x", "https://::1"]:
            self.assertTrue(normalize_url_base(bad).invalid, bad)


class PatternTest(unittest.TestCase):
    def test_patterns_and_classes(self):
        cases = {
            "https://api.carrier.example": "api.carrier.example",
            "HTTPS://API.Carrier.example:443": "api.carrier.example",
            "https://api.carrier.example.:8443": "api.carrier.example:8443",
            "https://t-3912345678.tenant.example": "{*}.tenant.example",
            "https://cdn-9f8e7d6c5b4a.assets.example": "{*}.assets.example",
            "https://deadbeefcafe.example": "{*}.example",
            "https://1password.example": "{*}.example",
            "https://xn--bcher-kva.example": "xn--bcher-kva.example",
            "https://ab12cd34ef56.0012345678.cdn.example": "{*}.{*}.cdn.example",
            "https://a_b.example": "invalid",
            "http://10.0.0.5:8080": "ip:private:8080",
            "https://8.8.8.8": "ip:public",
            "https://8.8.8.8.": "ip:public",
            "https://010.0.0.1": "{*}.{*}.{*}.{*}",
            "https://127.1": "{*}.{*}",
            "https://172.15.255.255": "ip:public",
            "https://172.16.0.1": "ip:private",
            "https://169.254.169.254": "ip:private",
            "https://100.64.0.1": "ip:private",
            "https://[2606:4700::1111]": "ip:public",
            "https://[::1]:8080": "ip:private:8080",
            "https://[::ffff:10.0.0.1]": "ip:private",
            "https://[::ffff:8.8.8.8]": "ip:public",
            "https://[64:ff9b::808:808]": "ip:public",
            "https://[64:ff9b::a00:1]": "ip:private",
            "https://[64:ff9b:1::1]": "ip:private",
            "https://[2001:db8::1]": "ip:private",
            "https://[2001:200::1]": "ip:public",
            "https://[fd12::1]": "ip:private",
            "https://[fe80::1]": "ip:private",
            "https://[ff02::1]": "ip:private",
            "https://[::2:0:0]": "ip:public",
            "https://api..carrier.example": "invalid",
            "https://.example": "invalid",
            "https://.": "invalid",
            "https://example..": "invalid",
            "https://localhost": "localhost",
        }
        for u, want in cases.items():
            self.assertEqual(pattern_of(u), want, u)
        self.assertTrue(host_label_safe("g" * 63))
        self.assertFalse(host_label_safe("g" * 64))
        self.assertTrue(host_label_safe("a-1"))
        self.assertFalse(host_label_safe("-a"))
        self.assertFalse(host_label_safe("ü"))


class ServiceSelectionTest(unittest.TestCase):
    def test_order_base_allow_pattern_unlisted(self):
        auto, off = sanitizer(), sanitizer(hosts={"discovery": "off"})
        self.assertEqual(service(auto, "https://t-3912345678.tenant.example"), "host:{*}.tenant.example")
        self.assertEqual(service(off, "https://t-3912345678.tenant.example"), "host:unlisted")
        self.assertEqual(service(off, "https://[::1]"), "host:unlisted")
        self.assertEqual(service(off, "https://api..x.example"), "host:unlisted")
        self.assertEqual(service(auto, "https://[::1"), "host:invalid")
        self.assertEqual(service(auto, "https://api..x.example"), "host:invalid")
        for mode in ("off", "auto"):
            allow = sanitizer(hosts={"discovery": mode},
                              segments={"auto_words": False, "allow": [], "hosts_allow": ["t-3912345678.tenant.example"]})
            self.assertEqual(service(allow, "https://T-3912345678.tenant.example"), "host:t-3912345678.tenant.example")
        allow = sanitizer(segments={"auto_words": False, "allow": [], "hosts_allow": ["t-3912345678.tenant.example"]})
        self.assertEqual(service(allow, "https://other.tenant.example"), "host:other.tenant.example")

    def test_hosts_object_is_validated(self):
        def check(hosts):
            b = empty_body()
            if hosts is not None:
                b["hosts"] = hosts
            return Policy(validate_body_schema(b))
        self.assertTrue(check(None).hosts_auto)
        self.assertTrue(check({"discovery": "auto"}).hosts_auto)
        self.assertFalse(check({"discovery": "off"}).hosts_auto)
        for bad in [{"discovery": "on"}, {}, {"discovery": "off", "extra": 1}, {"discovery": None}, {"discovery": "AUTO"},
                    "off", [], {"discovery": ["off"]}]:
            with self.assertRaises(Refused, msg=repr(bad)) as cm:
                check(bad)
            self.assertEqual(cm.exception.code, "policy_rejected")


def _safe(label):
    """Independent statement of the safe-label rule (3.5 a-c)."""
    return (re.fullmatch(r"[a-z][a-z0-9-]{0,62}", label) is not None and not re.search(r"[0-9]{6}", label)
            and not re.search(r"[0-9a-f]{12}", label))


class HostLeakTest(unittest.TestCase):
    """G1 with host labels: only safe labels, {*} or an IP class leave; strict mode gives host:unlisted."""

    def test_only_safe_labels_leave(self):
        r = random.Random(20261024)
        atoms = ["giulia", "mario-rossi", "t-3912345678", "cdn-9f8e7d6c5b4a", "9f8e7d6c5b4a3f2e",
                 "550e8400-e29b-41d4-a716-446655440000", "user_42", "x", "Q7", "ORD-2026-000184", "tok_abc", "api",
                 "xn--bcher-kva", "xn--9f8e7d6c5b4a", "", "123", "g" * 63, "g" * 64, "ünï", "K"]
        auto, off = sanitizer(), sanitizer(hosts={"discovery": "off"})
        for _ in range(600):
            labels = [r.choice(atoms) for _ in range(r.randint(1, 5))]
            k = r.random()
            if k < 0.1:
                host = "[" + r.choice(["::1", "2606:4700::1111", "fe80::1", "::ffff:10.0.0.1", "zz::1"]) + "]"
            elif k < 0.2:
                host = ".".join(str(r.randint(0, 300)) for _ in range(4))
            else:
                host = ".".join(labels) + ("." if r.random() < 0.2 else "")
            ub = r.choice(["http", "https"]) + "://" + host + (":%d" % r.randint(1, 70000) if r.random() < 0.3 else "")
            svc = service(auto, ub)
            self.assertTrue(svc.startswith("host:"))
            self.assertLessEqual(len(svc.encode("utf-8")), 518, svc)
            if svc != "host:invalid":
                m = re.fullmatch(r"host:(.*?)(?::([0-9]{1,5}))?", svc)
                pat = m.group(1)
                if pat not in ("ip:private", "ip:public"):
                    for lab in pat.split("."):
                        self.assertTrue(lab == "{*}" or _safe(lab), "unsafe label %r in %s from %s" % (lab, svc, ub))
            self.assertIn(service(off, ub), ("host:unlisted", "host:invalid"))


class OutboundBaseTest(unittest.TestCase):
    """Integrations pass the host as the client sees it (spec v1.5, point 9)."""

    def test_url_base_of_and_host_of(self):
        from urllib.parse import urlsplit
        from traffic_twin.capture.outbound import host_of, url_base_of
        self.assertEqual(url_base_of("http", "::1", 8080), "http://[::1]:8080")
        self.assertEqual(url_base_of("http", "[::1]", None), "http://[::1]")
        self.assertEqual(url_base_of("https", "api.example.", 443), "https://api.example.:443")
        for url, want in [("http://[2001:db8::1]:8080/x", "[2001:db8::1]"), ("http://u:p@API.Example.:81/x", "API.Example."),
                          ("https://xn--bcher-kva.example/", "xn--bcher-kva.example"), ("http://K.example/", "K.example")]:
            self.assertEqual(host_of(urlsplit(url)), want, url)
        # a non-ASCII host stays invalid (no IDN conversion, no Unicode lowercasing)
        self.assertTrue(normalize_url_base(url_base_of("http", host_of(urlsplit("http://K.example/")), None)).invalid)


if __name__ == "__main__":
    unittest.main()
