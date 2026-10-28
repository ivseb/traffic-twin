package io.github.ivseb.traffictwin;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.ivseb.traffictwin.sanitizer.Bodies;
import io.github.ivseb.traffictwin.sanitizer.Json;
import io.github.ivseb.traffictwin.sanitizer.Policy;
import io.github.ivseb.traffictwin.sanitizer.PolicyValidator;
import io.github.ivseb.traffictwin.sanitizer.Refused;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Spec v1.19 (sanitizer.md 22): the strict XML reader, multipart framing, base64 documents, policy switches. Invented data only. */
class BodiesTest {
    static byte[] b(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    static void invalidXml(String doc) {
        assertThrows(Bodies.InvalidXml.class, () -> Bodies.parseXml(b(doc)), doc.length() > 200 ? doc.substring(0, 200) : doc);
    }

    static Json.Obj tree(String doc) throws Exception {
        return Bodies.xmlTree(Bodies.parseXml(b(doc)), 32).tree();
    }

    static Object plain(Json.Node n) {
        return Json.toPlain(n, true);
    }

    // --- XML: hostile documents -------------------------------------------------------

    @Test
    void doctypeAndEntitiesAreNeverRead() {
        invalidXml("<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/hostname\">]><r>&x;</r>");
        invalidXml("<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;\">]><r>&lol2;</r>");
        invalidXml("<r><!DOCTYPE r></r>");
        invalidXml("<r><!ENTITY x \"y\"></r>");
        invalidXml("<r>&x;</r>");
        invalidXml("<r a=\"&ext;\"/>");
        invalidXml("<r>a & b</r>");
        invalidXml("<r>&amp</r>");
        invalidXml("<r>&#0;</r>");
        invalidXml("<r>&#xD800;</r>");
        invalidXml("<r>&#x110000;</r>");
        invalidXml("<r>&#99999999999999999999;</r>");
        invalidXml("<r>&#X41;</r>");
        invalidXml("<r/><!DOCTYPE r>");
    }

    @Test
    void nestingIsBoundedWithoutRecursionProblems() throws Exception {
        assertDoesNotThrow(() -> Bodies.parseXml(b("<a>".repeat(256) + "</a>".repeat(256))));
        invalidXml("<a>".repeat(257) + "</a>".repeat(257));
        // A self-closing element does not open a level: 256 open elements plus one empty one is accepted.
        assertDoesNotThrow(() -> Bodies.parseXml(b("<a>".repeat(256) + "<b/>" + "</a>".repeat(256))));
        // Very deep input fails fast at level 257 (no stack overflow, no quadratic work).
        invalidXml("<a>".repeat(200_000));
        // The tree of a 256-level document stops at max_depth in the walk, not here.
        assertEquals(1, tree("<a>".repeat(256) + "x" + "</a>".repeat(256)).size());
    }

    @Test
    void outsideTheSubsetIsInvalid() {
        for (String bad : List.of("", "   ", "<!-- only a comment -->", "text<r/>", "<r/>text", "<r/><r/>", "<r>", "<r></s>",
            "<r a=\"1\"a=\"2\"/>", "<r a=\"1\" a=\"2\"/>", "<r a=\"<\"/>", "<r a=1/>", "<p:r/>", "<r p:a=\"1\"/>", "<a:b:c/>",
            "<:r/>", "<r: />", "<r xmlns:=\"u\"/>", "<r xmlns:a:b=\"u\"/>", "<1r/>", "<r><![CDATA[x</r>", "<r><!-- x</r>",
            "<r>\u0001</r>", "<r>￾</r>", "<r><?pi</r>", "<r></r >x")) {
            invalidXml(bad);
        }
        assertThrows(Bodies.InvalidXml.class, () -> Bodies.parseXml(new byte[] {'<', 'r', '>', (byte) 0xc3, '<', '/', 'r', '>'}), "not UTF-8");
    }

    @Test
    void treeMappingFollowsPoint7() throws Exception {
        String doc = "﻿<?xml version=\"1.0\"?>\r\n<!-- c --><o:order xmlns:o=\"urn:x\" id=\"A1\" o:k=\"v\" x:k=\"w\" xmlns:x=\"urn:y\">"
            + "<line n=\"1\">a</line><line>b</line><note/>mixed&#x1F600;<![CDATA[<cd>]]><?pi skip?></o:order>\n";
        Map<String, Object> want = new LinkedHashMap<>();
        Map<String, Object> order = new LinkedHashMap<>();
        order.put("@id", "A1");
        order.put("@k", "w");
        order.put("line", List.of(Map.of("@n", "1", "#text", "a"), "b"));
        order.put("note", "");
        order.put("#text", "mixed😀<cd>");
        want.put("order", order);
        assertEquals(want, plain(tree(doc.replace("﻿", ""))));
        // The BOM is removed as bytes.
        byte[] bom = b(doc);
        assertEquals(want, plain(Bodies.xmlTree(Bodies.parseXml(bom), 32).tree()));
    }

    @Test
    void attributeValuesAndLineEndings() throws Exception {
        assertEquals(Map.of("r", Map.of("@a", "x y z&#9;", "#text", "1\n2\n3")),
            plain(tree("<r a=\"x\ty\r\nz&amp;#9;\">1\r\n2\r3</r>")));
        assertEquals(Map.of("r", Map.of("@a", "x\ty")), plain(tree("<r a='x&#9;y'/>")));
        assertEquals(Map.of("r", "  "), plain(tree("<r>  </r>")));
    }

    @Test
    void namespacesFmtAndPatterns() throws Exception {
        Bodies.XmlTree t = Bodies.xmlTree(Bodies.parseXml(b(
            "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><m:Get xmlns:m=\"http://a.example/customers/3912345678/x\">"
                + "<i xmlns=\"\">1</i><i>2</i></m:Get></s:Body></s:Envelope>")), 32);
        assertEquals("soap11", t.fmt());
        List<String> got = t.xmlns().stream().map(e -> e[0] + "=" + e[1]).toList();
        assertEquals(List.of("$.Envelope=ns:http://schemas.xmlsoap.org/soap/envelope/", "$.Envelope.Body.Get=ns:http://a.example/customers/{*}/x",
            "$.Envelope.Body.Get.i[*]=ns:{none}"), got);
        assertEquals("ns:{*}", Bodies.nsPattern("mailto:someone@example.test"));
        assertEquals("ns:{*}", Bodies.nsPattern("urn:a b"));
        assertEquals("ns:{*}", Bodies.nsPattern("urn:" + "a".repeat(600)));
        assertEquals("ns:urn:{*}:v1", Bodies.nsPattern("urn:" + "b".repeat(65) + ":v1"));
        assertEquals("ns:urn:{*}", Bodies.nsPattern("urn:deadbeef0123"));
        assertEquals("soap12", Bodies.xmlTree(Bodies.parseXml(b("<Envelope xmlns=\"http://www.w3.org/2003/05/soap-envelope\"/>")), 32).fmt());
        assertEquals("xml", Bodies.xmlTree(Bodies.parseXml(b("<Envelope/>")), 32).fmt());
        assertEquals("ns:http://www.w3.org/XML/1998/namespace",
            Bodies.xmlTree(Bodies.parseXml(b("<xml:r/>")), 32).xmlns().get(0)[1]);
    }

    @Test
    void soapActionNames() {
        assertEquals("GetOrder", Bodies.soapActionName("\"http://ws.example/orders/v2/GetOrder\""));
        assertEquals("Renew", Bodies.soapActionName(" urn:x#Renew\t"));
        assertNull(Bodies.soapActionName("\"\""));
        assertNull(Bodies.soapActionName("  "));
        assertEquals("{*}", Bodies.soapActionName("http://x.example/"));
        assertEquals("{*}", Bodies.soapActionName("urn:op:12345678"));
        assertEquals("Bare", Bodies.soapActionName("Bare"));
        assertEquals(Map.of("action", "urn:a#B", "charset", "utf-8"),
            Bodies.mediaParams(b("application/soap+xml; CHARSET=utf-8; action=\"urn:a#B\"; action=ignored; junk; q=\"")));
        assertTrue(Bodies.mediaParams(new byte[] {'a', ';', 'x', '=', (byte) 0xff}).isEmpty());
    }

    // --- multipart ------------------------------------------------------------------

    static List<Bodies.MultipartPart> mp(String body, String boundary) throws Bodies.InvalidMultipart {
        return Bodies.parseMultipart(b(body), boundary);
    }

    static void invalidMp(String body, String boundary) {
        assertThrows(Bodies.InvalidMultipart.class, () -> mp(body, boundary), body);
    }

    @Test
    void multipartFraming() throws Exception {
        String body = "preamble\r\n--XyZ \t\r\nContent-Disposition: form-data; name=\"a\\\"q\"\r\nX-Other: 1\r\ncontent-disposition: ignored\r\n\r\nv1\r\n"
            + "--XyZ\r\ncontent-disposition: FORM-DATA ; name=b; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf\r\nContent-Type: Text/CSV; charset=x\r\n\r\n"
            + "a,b\r\n--XyZ--\r\nepilogue --XyZ junk";
        List<Bodies.MultipartPart> parts = mp(body, "XyZ");
        assertEquals(2, parts.size());
        assertEquals("a\"q", parts.get(0).name());
        assertEquals("v1", new String(parts.get(0).content(), StandardCharsets.UTF_8));
        assertTrue(parts.get(1).isFile());
        assertEquals("text/csv", parts.get(1).contentType());
        assertEquals("drop:file:csv:l1k", Bodies.fileToken(parts.get(1).content(), parts.get(1).contentType()));
        assertEquals("drop:file:pdf:l1k", Bodies.fileToken(b("%PDF-1.4 x"), "text/plain"));
        assertEquals("drop:file:bin:l1k", Bodies.fileToken(new byte[0], null));
        assertEquals(0, mp("--b--", "b").size());
        assertEquals(1, mp("--b\r\ncontent-disposition: form-data; name=e\r\n\r\n\r\n--b--", "b").size());
    }

    @Test
    void multipartEdgeCasesAreInvalid() {
        invalidMp("--b\r\ncontent-disposition: form-data; name=a\r\n\r\nv\r\n--b--", null);
        invalidMp("--b \r\n", "b ");                                   // a boundary cannot end with a space
        invalidMp("--b\r\n", "b".repeat(71));                          // more than 70 characters
        invalidMp("no delimiter at all", "b");
        invalidMp("--b\r\ncontent-disposition: form-data; name=a\r\n\r\nv", "b");          // no close delimiter
        invalidMp("--bX\r\n", "b");                                                          // garbage after the delimiter
        invalidMp("--b\r\n\r\nv\r\n--b--", "b");                                             // no headers: no content-disposition
        invalidMp("--b\r\ncontent-disposition: attachment; name=a\r\n\r\nv\r\n--b--", "b"); // not form-data
        invalidMp("--b\r\ncontent-disposition: form-data; filename=a\r\n\r\nv\r\n--b--", "b"); // no name
        invalidMp("--b\r\ncontent-disposition: form-data; name=\"a\r\n\r\nv\r\n--b--", "b");   // unterminated quote
        invalidMp("--b\r\ncontent-disposition: form-data; name=\"a\" x\r\n\r\nv\r\n--b--", "b"); // garbage after quotes
        invalidMp("--b\r\ncontent-disposition: form-data;\r\n name=a\r\n\r\nv\r\n--b--", "b"); // header continuation
        invalidMp("--b\r\nbad header: x\r\ncontent-disposition: form-data; name=a\r\n\r\nv\r\n--b--", "b");
        invalidMp("--b\r\n: x\r\n\r\nv\r\n--b--", "b");
        invalidMp("--b\r\ncontent-disposition: form-data; name=a\r\nv\r\n--b--", "b");      // headers never end
        // content-disposition that is not UTF-8
        assertThrows(Bodies.InvalidMultipart.class, () -> Bodies.parseMultipart(
            concat(b("--b\r\ncontent-disposition: form-data; name="), new byte[] {(byte) 0xff}, b("\r\n\r\nv\r\n--b--")), "b"));
    }

    static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, o, p.length);
            o += p.length;
        }
        return out;
    }

    // --- documents ------------------------------------------------------------------

    @Test
    void base64DocumentsAreLenientOnPaddingBits() {
        byte[] pdf = b("%PDF-1.7 invente");                      // 16 bytes: one byte in the last group
        String std = Base64.getEncoder().encodeToString(pdf);     // ends with "=="
        assertEquals("drop:doc:pdf:l1k", Bodies.base64Doc(std));
        String bare = std.replace("=", "");
        assertEquals("drop:doc:pdf:l1k", Bodies.base64Doc(bare));
        // Non-zero padding bits in the last character are ignored.
        char last = bare.charAt(bare.length() - 1);
        String dirty = bare.substring(0, bare.length() - 1) + (char) (last + 1);
        assertEquals("drop:doc:pdf:l1k", Bodies.base64Doc(dirty));
        assertEquals("drop:doc:pdf:l1k", Bodies.base64Doc("data:application/pdf;base64," + std));
        assertNull(Bodies.base64Doc("data:application/pdf," + std));
        assertNull(Bodies.base64Doc("data: x;base64," + std));
        assertNull(Bodies.base64Doc(bare + "="));                  // '=' with a length not multiple of 4
        assertNull(Bodies.base64Doc(std + "="));                   // three '='
        assertNull(Bodies.base64Doc(bare + "ABB"));                // length mod 4 == 1
        assertNull(Bodies.base64Doc("JVBERi0x"));                  // shorter than 16 characters
        assertNull(Bodies.base64Doc(std.replace('V', ' ')));
        byte[] png = new byte[40];
        System.arraycopy(new byte[] {(byte) 0x89, 'P', 'N', 'G', 13, 10, 26, 10}, 0, png, 0, 8);
        String url = Base64.getUrlEncoder().withoutPadding().encodeToString(png);
        assertEquals("drop:doc:png:l1k", Bodies.base64Doc(url));
        byte[] zip = concat(new byte[] {'P', 'K', 3, 4}, new byte[2000], b("xl/workbook.xml"));
        assertEquals("drop:doc:xlsx:l16k", Bodies.base64Doc(Base64.getEncoder().encodeToString(zip)));
        assertEquals("l128k", Bodies.docClass(131072));
        assertEquals("l1m", Bodies.docClass(131073));
        assertEquals("lmax", Bodies.docClass(8388609));
    }

    // --- policy -----------------------------------------------------------------------

    static Map<String, Object> policyBody(Object bodies, Object action, String path) {
        String json = "{\"format\":\"tt.policy.body/v1\",\"policy_id\":\"p\",\"version\":1,\"issued_seq\":1,"
            + "\"created_at\":\"2026-10-27T00:00:00Z\",\"not_after\":\"2026-11-27T00:00:00Z\",\"targets\":{\"groups\":[\"g\"]},"
            + "\"hmac\":{\"kid\":\"k1\",\"accept_kids\":[],\"epoch\":\"e1\"},\"sampling\":{\"rate_bp\":10000,\"trust_baggage\":false,\"propagate_to\":[]},"
            + "\"segments\":{\"auto_words\":false,\"allow\":[],\"hosts_allow\":[]},"
            + "\"limits\":{\"max_body_bytes\":1024,\"max_depth\":32,\"max_array\":32,\"max_keys\":256,\"keep_max_bytes\":64},"
            + (bodies == null ? "" : "\"bodies\":" + bodies + ",")
            + "\"global\":{\"request\":{\"body\":[{\"path\":\"" + path + "\",\"action\":" + action + "}]}},\"services\":[]}";
        @SuppressWarnings("unchecked")
        Map<String, Object> m = (Map<String, Object>) Json.parsePlain(b(json), true);
        return m;
    }

    static final String ALL = "{\"xml\":true,\"multipart\":true,\"docs\":true,\"max_large_body_bytes\":4096,\"large_array\":5,\"large_nested_array\":2}";

    @Test
    void policyAcceptsBodiesCodeAlnumAndNewSteps() {
        Policy p = new Policy(PolicyValidator.validate(policyBody(ALL, "{\"action\":\"code\",\"shape\":\"alnum\"}", "$.order.@id")));
        assertEquals(new Policy.Bodies(true, true, true, 4096, 5, 2), p.bodies);
        assertEquals(4097, p.captureLimit());
        assertEquals("alnum", p.globalRequest.body.get(0).action.shape);
        assertEquals("@id", p.globalRequest.body.get(0).steps[1].name());
        Policy off = new Policy(PolicyValidator.validate(policyBody(null, "{\"action\":\"drop\"}", "$.a.#text")));
        assertEquals(Policy.Bodies.OFF, off.bodies);
        assertEquals(1025, off.captureLimit());
        assertEquals("#text", off.globalRequest.body.get(0).steps[1].name());
    }

    @Test
    void policyRefusesWhatTheSchemaRefuses() {
        List<Object[]> bad = List.of(
            new Object[] {ALL.replace(",\"large_nested_array\":2", ""), "{\"action\":\"drop\"}", "$.a"},
            new Object[] {ALL.replace("4096", "67108865"), "{\"action\":\"drop\"}", "$.a"},
            new Object[] {ALL.replace("\"large_array\":5", "\"large_array\":1025"), "{\"action\":\"drop\"}", "$.a"},
            new Object[] {ALL.replace("}", ",\"json\":true}"), "{\"action\":\"drop\"}", "$.a"},
            new Object[] {ALL.replace("\"xml\":true", "\"xml\":1"), "{\"action\":\"drop\"}", "$.a"},
            new Object[] {null, "{\"action\":\"code\",\"shape\":\"alpha\"}", "$.a"},
            new Object[] {null, "{\"action\":\"keep\",\"shape\":\"alnum\"}", "$.a"},
            new Object[] {null, "{\"action\":\"drop\"}", "$.a.#texts"},
            new Object[] {null, "{\"action\":\"drop\"}", "$.a.#id"},
            new Object[] {null, "{\"action\":\"drop\"}", "$.a.@"},
            new Object[] {null, "{\"action\":\"drop\"}", "$.a.@1x"},
            // H2: code(alnum) on a wildcard step of a global rule.
            new Object[] {null, "{\"action\":\"code\",\"shape\":\"alnum\"}", "$.a[*].@id"});
        for (Object[] c : bad) {
            Refused r = assertThrows(Refused.class, () -> PolicyValidator.validate(policyBody(c[0], c[1], (String) c[2])), String.valueOf(c[2]) + c[1] + c[0]);
            assertEquals("policy_rejected", r.code());
        }
    }
}
