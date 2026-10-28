"""Unit tests: Ed25519 (RFC 8032), the JSON tokenizer, canonical numbers, the conformance
vectors, and the G1 property (an empty policy lets no input value out)."""

import os
import random
import string
import unittest

from traffic_twin import ed25519, gqlshape
from traffic_twin.conformance import find_conformance_dir, run_all
from traffic_twin.jsonlex import JsonError, JObj, Num, canonical_number, parse_json, write_canonical
from traffic_twin.policy import Policy, parse_key_ring, select_key, validate_body_schema
from traffic_twin.jsonlex import parse_plain
from traffic_twin.sanitizer import Exchange, Sanitizer

# RFC 8032 section 7.1 test vectors (secret key, public key, message, signature).
RFC8032 = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


class Ed25519Test(unittest.TestCase):
    def test_rfc8032_vectors(self):
        for sk, pk, msg, sig in RFC8032:
            sk, pk, msg, sig = (bytes.fromhex(x) for x in (sk, pk, msg, sig))
            self.assertEqual(ed25519.public_key(sk), pk)
            self.assertEqual(ed25519.sign(sk, msg), sig)
            self.assertTrue(ed25519.verify(pk, msg, sig))

    def test_rejections(self):
        sk, pk, msg, sig = (bytes.fromhex(x) for x in RFC8032[1])
        self.assertFalse(ed25519.verify(pk, msg + b"x", sig))
        bad = bytearray(sig)
        bad[0] ^= 1
        self.assertFalse(ed25519.verify(pk, msg, bytes(bad)))
        # S >= L is malleable and must be rejected
        s = int.from_bytes(sig[32:], "little") + ed25519.L
        self.assertFalse(ed25519.verify(pk, msg, sig[:32] + (s % (1 << 256)).to_bytes(32, "little")))
        self.assertFalse(ed25519.verify(pk, msg, sig[:63]))
        self.assertFalse(ed25519.verify(pk[:31], msg, sig))
        self.assertFalse(ed25519.verify(b"\xff" * 32, msg, sig))  # not a curve point

    def test_cross_check_with_cryptography_if_present(self):
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ImportError:
            self.skipTest("cryptography not installed")
        rnd = random.Random(7)
        for _ in range(10):
            k = Ed25519PrivateKey.from_private_bytes(bytes(rnd.getrandbits(8) for _ in range(32)))
            m = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 200)))
            self.assertTrue(ed25519.verify(k.public_key().public_bytes_raw(), m, k.sign(m)))


class JsonTest(unittest.TestCase):
    def test_valid(self):
        v = parse_json(b' {"a":[1,2.50,{"b":null}],"a":"x\\ud83d\\ude00","n":-0.0e+10} ')
        self.assertIsInstance(v, JObj)
        self.assertEqual([k for k, _b, _v in v.m], ["a", "a", "n"])
        self.assertEqual(v.m[0][2][1].lex, "2.50")  # lexeme preserved
        self.assertEqual(v.m[1][2], "x\U0001F600")
        self.assertEqual(v.m[2][2].lex, "-0.0e+10")

    def test_invalid(self):
        for doc in [b"", b"01", b"[1,]", b"{\"a\":1} x", b"[", b"\"\xff\"", b"-", b"1.", b"tru", b"NaN", b"[1 2]",
                    b"{'a':1}", b"\xef\xbb\xbf{}", b"\"a\x01\"", b"{\"a\" 1}", b"[\"\\x\"]", b"[\"\\ud8\"]", b"// c\n{}"]:
            with self.assertRaises(JsonError, msg=repr(doc)):
                parse_json(doc)

    def test_deep_documents_are_validated_without_recursion(self):
        parse_json(b"[" * 200000 + b"]" * 200000)
        with self.assertRaises(JsonError):
            parse_json(b"[" * 200000 + b"]" * 199999)

    def test_canonical_numbers(self):
        cases = {"1.50": "1.5", "15e-1": "1.5", "-0.0": "0", "1E3": "1000", "0.0015": "0.0015", "184.0": "184",
                 "123456789012345678901234567890": "1.2345678901234567890123456789e+29", "1e21": "1e+21",
                 "1e20": "100000000000000000000", "0.0000001": "1e-7", "0.000001": "0.000001", "-1.5E-7": "-1.5e-7"}
        for lex, want in cases.items():
            self.assertEqual(canonical_number(lex), want, lex)

    def test_writer(self):
        self.assertEqual(write_canonical({"b": "é\U0001F600/\"\x7f", "a": [None, True]}),
                         '{"a":[null,true],"b":"\\u00e9\\ud83d\\ude00/\\"\\u007f"}')


class VectorsTest(unittest.TestCase):
    def test_all_conformance_vectors(self):
        root = find_conformance_dir()
        self.assertIsNotNone(root, "conformance/ not found")
        import io
        out = io.StringIO()
        r = run_all(root, None, out)
        self.assertEqual(r["failed"], [], out.getvalue())
        self.assertGreaterEqual(r["passed"], 756)


KEY = "k1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"


class LeakTest(unittest.TestCase):
    """G1: with the empty policy no input value appears in the output."""

    def setUp(self):
        root = find_conformance_dir()
        with open(os.path.join(root, "policies", "empty.json"), "rb") as f:
            body = validate_body_schema(parse_plain(f.read(), True))
        self.policy = Policy(body)
        kid, key = select_key(parse_key_ring(KEY), self.policy)
        self.san = Sanitizer(self.policy, kid, key)

    def rnd(self, r):
        return "".join(r.choice(string.ascii_letters + string.digits) for _ in range(r.randint(10, 24)))

    def test_no_value_leaks(self):
        r = random.Random(11)
        for _ in range(60):
            secrets = [self.rnd(r) + "Zq" for _ in range(8)]
            ex = Exchange("inbound", "GET", ("/orders/%s/items/%s" % (secrets[0], secrets[1])).encode())
            ex.service_name = "shop-api"
            ex.raw_query = ("a=%s&%s&b=%s" % (secrets[2], secrets[3], secrets[4])).encode()
            ex.req_headers = [("X-Token", secrets[5].encode()), ("Cookie", ("sid=%s" % secrets[6]).encode()),
                              ("Content-Type", b"application/json")]
            ex.req_body = ('{"name":"%s","list":["%s",1,true,null],"n":%d}' % (secrets[7], secrets[0], r.randint(0, 10 ** 9))).encode()
            ex.status = 200
            ex.resp_headers = [("Content-Type", b"application/json"), ("Set-Cookie", ("t=%s" % secrets[1]).encode())]
            ex.resp_body = ('{"echo":"%s"}' % secrets[2]).encode()
            res = self.san.run(ex, 1.7e9)
            self.assertEqual(res.outcome, "event")
            for s in secrets:
                self.assertNotIn(s, res.canonical)
                self.assertNotIn(s.lower(), res.canonical.lower())


class BaggagePrependTest(unittest.TestCase):
    """tt.s goes in FRONT of the outbound baggage: the reader takes the first valid member, so a
    tt.s forged by a client and forwarded by the application can never win (like the Go SDK)."""

    def test_member_is_prepended_and_others_untouched(self):
        from traffic_twin.capture.common import with_tt_s
        self.assertEqual(with_tt_s(None, True), "tt.s=1")
        self.assertEqual(with_tt_s("  ", False), "tt.s=0")
        self.assertEqual(with_tt_s("userId=alice,tt.s=1", False), "tt.s=0,userId=alice,tt.s=1")
        self.assertEqual(with_tt_s("a=b", True), "tt.s=1,a=b")

    def test_forged_forwarded_member_does_not_win(self):
        from traffic_twin.capture.common import with_tt_s
        root = find_conformance_dir()
        with open(os.path.join(root, "policies", "empty.json"), "rb") as f:
            raw = parse_plain(f.read(), True)
        raw["sampling"]["trust_baggage"] = True
        # an internal inbound service is needed for the baggage to be honoured
        raw["services"] = [{"name": "shop-api", "match": {"inbound": True, "internal": True}, "ops": []}]
        policy = Policy(validate_body_schema(raw))
        self.assertTrue(policy.inbound["shop-api"].internal)
        kid, key = select_key(parse_key_ring(KEY), policy)
        san = Sanitizer(policy, kid, key)
        for ours, forged in ((True, "tt.s=0"), (False, "tt.s=1")):
            bag = with_tt_s("x=y," + forged, ours)
            d = san.decide_parts("inbound", "shop-api", [("baggage", bag.encode())], None, None)
            self.assertEqual((d.sampled, d.by), (ours, "baggage"), bag)


class GraphQLShapeTest(unittest.TestCase):
    """sanitizer.md 5.7.1 examples and edge cases (vectors 2000-2033 cover the sanitizer side)."""

    def test_shapes(self):
        cases = [
            ("query GetOrder($id: ID!) { order(id: $id) { id status items { sku } } }",
             ("query GetOrder($id:ID!){order(id:$id){id status items{sku}}}", False)),
            ('{ order(id: "ORD-123", n: 5, r: 1.5, ok: true, st: SHIPPED, x: null) { id } }',
             ("{order(id:?s n:?i r:?f ok:?b st:?e x:?n){id}}", False)),
            ('mutation M($in: [OrderIn!]! = [{note: "urgente"}]) { a: create(in: $in) { ...F } } '
             'fragment F on Order { id }',
             ("mutation M($in:[OrderIn!]!=[{note:?s}]){a:create(in:$in){...F}}fragment F on Order{id}", False)),
            ("{ o4821553: order(id: 1) { id } }", ("{*:order(id:?i){id}}", False)),
            ("﻿# c\n{ __schema { types { name } } __typename }", ("{__schema{types{name}}__typename}", True)),
            ("{ x: __schema { a } }", ("{x:__schema{a}}", False)),
            ('{ a(x: """a \\""" b""", y: -0.5e+3) }', ("{a(x:?s y:?f)}", False)),
            ("{a" * 64 + "}" * 64, ("{a" * 64 + "}" * 64, False)),
        ]
        for src, want in cases:
            self.assertEqual(gqlshape.shape(src), want, src)

    def test_errors(self):
        for src in ("ciao", "type Query { a: Int }", "{ a(x: 01) }", "{ a(x: 1.) }", "{ a(x: 1abc) }", "{ }",
                    "{ a ", "{ a } }", '{ a(x: "\\q") }', '{ a(x: "\n") }', "fragment on on T { a }",
                    "{ a(x: ?) }", "{ caffè }", "", "{a" * 65 + "}" * 65):
            self.assertIsNone(gqlshape.shape(src), src)

    def test_names(self):
        self.assertTrue(gqlshape.name_safe("g" * 64) and gqlshape.name_safe("T12345"))
        for bad in ("g" * 65, "T123456", "deadbeefdeadbeef", "", "1a", "a.b"):
            self.assertFalse(gqlshape.name_safe(bad), bad)


if __name__ == "__main__":
    unittest.main()
