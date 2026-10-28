"""Spec v1.19 bodies (sanitizer.md 22): the strict XML reader against hostile documents,
multipart edge cases, base64 documents, the policy fields and the capture prefix."""

import base64
import json
import unittest

from traffic_twin import bodies as B
from traffic_twin.capture.wsgi import WSGIMiddleware
from traffic_twin.jsonlex import Num
from traffic_twin.policy import Policy, Refused, parse_tt_path, validate_body_schema

from .fakecore import base_policy
from .harness import Env, WsgiRunner, call


def _np(obj):
    """Plain policy dict (ints) -> the parsed form validate_body_schema expects (Num)."""
    if isinstance(obj, dict):
        return {k: _np(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_np(v) for v in obj]
    if isinstance(obj, bool) or obj is None or isinstance(obj, str):
        return obj
    return Num(str(obj))


BODIES = {"xml": True, "multipart": True, "docs": True, "max_large_body_bytes": 4096, "large_array": 50,
          "large_nested_array": 5}


class XmlHostileTest(unittest.TestCase):
    def bad(self, doc, why=None):
        with self.assertRaises(B.InvalidXML, msg=doc[:80]):
            B.parse_xml(doc if isinstance(doc, bytes) else doc.encode("utf-8"))

    def test_doctype_and_entities_are_refused(self):
        self.bad('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>')
        laughs = '<!DOCTYPE l [<!ENTITY a "lol"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><l>&b;</l>'
        self.bad(laughs)
        self.bad("<r>&custom;</r>")
        self.bad("<r>a & b</r>")
        self.bad("<r>&amp</r>")
        self.bad("<r><!ENTITY x 'y'></r>")
        self.bad("<r>&#0;</r>")
        self.bad("<r>&#x110000;</r>")
        self.bad("<r>&#" + "9" * 100000 + ";</r>")  # no big-integer work
        self.bad("<r>&#X41;</r>")

    def test_references_that_are_allowed(self):
        root = B.parse_xml(b"<r a='x&#9;y\tz'>&lt;&#x41;&#66;&amp;</r>")
        self.assertEqual("".join(root.text), "<AB&")
        self.assertEqual(root.attrs, [("a", "x\ty z")])

    def test_nesting_cap_without_recursion(self):
        ok = "<a>" * 256 + "</a>" * 256
        tree, _, _ = B.xml_tree(B.parse_xml(ok.encode()), lambda k: True, 32)
        self.assertEqual(tree.m[0][0], "a")
        self.bad("<a>" * 257 + "</a>" * 257)
        # far deeper than any recursion limit: refused early, no RecursionError
        self.bad("<a>" * 200000 + "</a>" * 200000)
        self.bad("<a>" * 200000)

    def test_structure_errors(self):
        for doc in ("", "   ", "text<r/>", "<r/>text", "<r/><r/>", "<r>", "<r></s>", "<r a='1'a='2'/>",
                    "<r a='1' a='2'/>", "<r a='<'/>", "<1r/>", "<a:b:c/>", "<p:r/>", "<r p:a='1'/>",
                    "<r xmlns:='u'/>", "<r><![CDATA[x</r>", "<r>\x01</r>", "<r><!-- x</r>"):
            self.bad(doc)
        self.bad(b"<r>\xff</r>")

    def test_tree_shape(self):
        doc = (b'\xef\xbb\xbf<?xml version="1.0"?><!-- c --><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
               b'<s:Body><Get xmlns="urn:x" id="7"><i>1</i><i>2</i>mixed<j/></Get></s:Body></s:Envelope>')
        tree, entries, fmt = B.xml_tree(B.parse_xml(doc), lambda k: True, 32)
        self.assertEqual(fmt, "soap11")
        self.assertEqual(entries, [("$.Envelope", "ns:http://schemas.xmlsoap.org/soap/envelope/"),
                                   ("$.Envelope.Body.Get", "ns:urn:x")])
        get = tree.m[0][2].m[0][2].m[0][2]
        self.assertEqual([(k, v) for k, _, v in get.m], [("@id", "7"), ("i", ["1", "2"]), ("j", ""), ("#text", "mixed")])

    def test_ns_pattern(self):
        self.assertEqual(B.ns_pattern(""), "ns:{none}")
        self.assertEqual(B.ns_pattern("http://a.example/customers/3912345678/x"), "ns:http://a.example/customers/{*}/x")
        self.assertEqual(B.ns_pattern("mailto:mario.rossi@example.com"), "ns:{*}")
        self.assertEqual(B.ns_pattern("urn:" + "a" * 65), "ns:urn:{*}")


class MultipartTest(unittest.TestCase):
    def parts(self, body, boundary="XyZ"):
        return [(p.name, p.is_file, p.content, p.ct) for p in B.parse_multipart(body, boundary)]

    def test_preamble_epilogue_and_files(self):
        body = (b"preamble\r\n--XyZ\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n"
                b"--XyZ  \r\ncontent-disposition: FORM-DATA; name=\"doc\"; filename=\"a.pdf\"\r\n"
                b"Content-Type: application/octet-stream\r\n\r\n%PDF-1.7 ...\r\n--XyZ--\r\nepilogue")
        self.assertEqual(self.parts(body), [("note", False, b"hello", None),
                                            ("doc", True, b"%PDF-1.7 ...", "application/octet-stream")])
        self.assertEqual(B.file_token(b"%PDF-1.7 ...", None), "drop:file:pdf:l1k")
        self.assertEqual(B.file_token(b"a,b\n", "text/csv"), "drop:file:csv:l1k")
        self.assertEqual(B.file_token(b"\x00", None), "drop:file:bin:l1k")

    def test_quoted_names_and_empty(self):
        body = b'--XyZ\r\nContent-Disposition: form-data; name="a\\"b"; filename*=UTF-8\'\'x\r\n\r\n\r\n--XyZ--'
        self.assertEqual(self.parts(body), [('a"b', True, b"", None)])
        self.assertEqual(self.parts(b"--XyZ--"), [])
        # a part without headers starts with CR LF
        with self.assertRaises(B.InvalidMultipart):
            self.parts(b"--XyZ\r\n\r\nx\r\n--XyZ--")  # no content-disposition

    def test_invalid(self):
        cd = b"Content-Disposition: form-data; name=\"a\"\r\n\r\nv"
        for body, boundary in (
            (b"--XyZ\r\n" + cd + b"\r\n--XyZ--", None),
            (b"--XyZ\r\n" + cd + b"\r\n--XyZ--", "x" * 71),
            (b"--XyZ\r\n" + cd, "XyZ"),                                      # no close delimiter
            (b"no delimiter at all", "XyZ"),
            (b"--XyZ garbage\r\n" + cd + b"\r\n--XyZ--", "XyZ"),
            (b"--XyZ\r\nContent-Disposition: attachment; name=a\r\n\r\nv\r\n--XyZ--", "XyZ"),
            (b"--XyZ\r\nContent-Disposition: form-data; filename=a\r\n\r\nv\r\n--XyZ--", "XyZ"),
            (b"--XyZ\r\nContent-Disposition: form-data; name=\"a\r\n\r\nv\r\n--XyZ--", "XyZ"),
            (b"--XyZ\r\nContent-Disposition: form-data; name=\"a\" x\r\n\r\nv\r\n--XyZ--", "XyZ"),
            (b"--XyZ\r\nBad Header: x\r\n" + cd + b"\r\n--XyZ--", "XyZ"),
            (b"--XyZ\r\n continuation\r\n" + cd + b"\r\n--XyZ--", "XyZ"),
            (b"--XyZ\r\nContent-Disposition: form-data; name=a", "XyZ"),
        ):
            with self.assertRaises(B.InvalidMultipart, msg=repr(body)):
                B.parse_multipart(body, boundary)

    def test_media_params(self):
        v = b'multipart/form-data; Boundary="a b"; boundary=second; x; action="urn:x#Do'
        self.assertEqual(B.media_params(v), {"boundary": "a b"})
        self.assertEqual(B.media_params(b"text/xml; \xff=1"), {})


class DocumentsTest(unittest.TestCase):
    def test_kinds_and_rejections(self):
        pdf = base64.b64encode(b"%PDF-1.4\n" + b"x" * 40).decode()
        self.assertEqual(B.base64_doc(pdf), "drop:doc:pdf:l1k")
        self.assertEqual(B.base64_doc("data:application/pdf;base64," + pdf), "drop:doc:pdf:l1k")
        self.assertIsNone(B.base64_doc("data:application/pdf," + pdf))
        url = base64.urlsafe_b64encode(b"\x89PNG\r\n\x1a\n" + b"\xff\xfe" * 20).decode().rstrip("=")
        self.assertEqual(B.base64_doc(url), "drop:doc:png:l1k")
        docx = base64.b64encode(b"PK\x03\x04" + b"\x00" * 30 + b"word/document.xml").decode()
        self.assertEqual(B.base64_doc(docx), "drop:doc:docx:l1k")
        self.assertIsNone(B.base64_doc(base64.b64encode(b"just some text here").decode()))
        self.assertIsNone(B.base64_doc(pdf[:12]))
        self.assertIsNone(B.base64_doc(pdf + " "))
        self.assertIsNone(B.base64_doc(pdf[:-1] + "==="))


class PolicyFieldsTest(unittest.TestCase):
    def check(self, **over):
        return validate_body_schema(_np(base_policy(**over)))

    def test_bodies_and_capture_limit(self):
        p = Policy(self.check())
        self.assertFalse(p.bodies.xml or p.bodies.multipart or p.bodies.docs)
        self.assertEqual(p.capture_limit, 1048577)
        p = Policy(self.check(bodies=dict(BODIES, max_large_body_bytes=8 * 1048576)))
        self.assertEqual(p.capture_limit, 8 * 1048576 + 1)
        for bad in (dict(BODIES, extra=True), {k: v for k, v in BODIES.items() if k != "docs"},
                    dict(BODIES, max_large_body_bytes=67108865), dict(BODIES, large_array=1025),
                    dict(BODIES, xml=1)):
            with self.assertRaises(Refused):
                self.check(bodies=bad)

    def test_code_alnum_and_new_steps(self):
        def svc(action, path="$.code"):
            return [{"name": "shop-api", "match": {"inbound": True, "internal": False},
                     "ops": [{"op": "GET /x", "response": {"body": [{"path": path, "action": action}]}}]}]
        self.check(services=svc({"action": "code", "shape": "alnum"}))
        self.check(services=svc({"action": "keep"}, "$.order.@id"))
        self.check(services=svc({"action": "keep"}, "$.order.#text"))
        for action, path in (({"action": "code", "shape": "digits"}, "$.code"), ({"action": "keep", "shape": "alnum"}, "$.code"),
                             ({"action": "keep"}, "$.a.#txt"), ({"action": "keep"}, "$.a.@"), ({"action": "keep"}, "$.@1a")):
            with self.assertRaises(Refused):
                self.check(services=svc(action, path))
        # H2: code(alnum) on a global wildcard is refused like code
        g = {"response": {"body": [{"path": "$.*", "action": {"action": "code", "shape": "alnum"}}]}}
        with self.assertRaises(Refused):
            self.check(**{"global": g})
        self.assertEqual([(s.t, s.name) for s in parse_tt_path("$.a.@id[*].#text")],
                         [("name", "a"), ("name", "@id"), ("idx", ""), ("name", "#text")])


def echo_app(environ, start_response):
    body = environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH") or 0))
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"%d" % len(body)]


class LargeBodyCaptureTest(unittest.TestCase):
    """22.5: the tee keeps max(max_body_bytes, max_large_body_bytes) + 1 bytes."""

    def test_large_json_body_is_analysed(self):
        limits = {"max_body_bytes": 64, "max_depth": 32, "max_array": 2, "max_keys": 256, "keep_max_bytes": 64}
        policy = base_policy(limits=limits, bodies=BODIES,
                             services=[{"name": "shop-api", "match": {"inbound": True, "internal": False}, "ops": []}])
        with Env(policy) as env:
            app = WSGIMiddleware(echo_app, host=env.agent)
            with WsgiRunner(app) as srv:
                payload = json.dumps({"items": [{"sku": "SKU-%04d" % i} for i in range(60)]}).encode()
                self.assertGreater(len(payload), 64)
                self.assertLess(len(payload), 4096)
                got = call(srv.port, "POST", "/bulk", payload, {"Content-Type": "application/json"})
                self.assertEqual(got[2], b"%d" % len(payload))
                e = env.events(lambda e: e["req"].get("ct") == "application/json")[0]
                items = e["req"]["body"]["items"]
                self.assertEqual(len(items), 51)  # large_array, then the marker
                self.assertEqual(items[-1], "trunc:n:l128")
                self.assertNotIn("SKU-0001", json.dumps(e))


if __name__ == "__main__":
    unittest.main()
