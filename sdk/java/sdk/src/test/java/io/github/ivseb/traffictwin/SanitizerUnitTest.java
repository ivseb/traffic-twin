package io.github.ivseb.traffictwin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.ivseb.traffictwin.sanitizer.BodyDecoder;
import io.github.ivseb.traffictwin.sanitizer.Exchange;
import io.github.ivseb.traffictwin.sanitizer.Exchange.Header;
import io.github.ivseb.traffictwin.sanitizer.GraphQL;
import io.github.ivseb.traffictwin.sanitizer.HostPattern;
import io.github.ivseb.traffictwin.sanitizer.Json;
import io.github.ivseb.traffictwin.sanitizer.KeyRing;
import io.github.ivseb.traffictwin.sanitizer.Policy;
import io.github.ivseb.traffictwin.sanitizer.PolicyValidator;
import io.github.ivseb.traffictwin.sanitizer.Refused;
import io.github.ivseb.traffictwin.sanitizer.Sanitizer;
import io.github.ivseb.traffictwin.sanitizer.Utf8;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.Test;

/** Unit tests beyond the conformance vectors: tokenizer, canonical numbers, key ring, decoding, and the G1 property. */
class SanitizerUnitTest {
    static byte[] b(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void graphqlShape() {
        // sanitizer.md 5.7.1 (spec v1.14): examples of the spec and edge cases of the lexer.
        String[][] ok = {
            {"query GetOrder($id: ID!) { order(id: $id) { id status items { sku } } }", "query GetOrder($id:ID!){order(id:$id){id status items{sku}}}", "false"},
            {"{ order(id: \"ORD-123\", n: 5, r: 1.5, ok: true, st: SHIPPED, x: null) { id } }", "{order(id:?s n:?i r:?f ok:?b st:?e x:?n){id}}", "false"},
            {"mutation M($in: [OrderIn!]! = [{note: \"urgente\"}]) { a: create(in: $in) { ...F } } fragment F on Order { id }",
                "mutation M($in:[OrderIn!]!=[{note:?s}]){a:create(in:$in){...F}}fragment F on Order{id}", "false"},
            {"{ o4821553: order(id: 1) { id } }", "{*:order(id:?i){id}}", "false"},
            {"\uFEFF# c\n{ __schema { types { name } } __typename }", "{__schema{types{name}}__typename}", "true"},
            {"{ a(s: \"\"\"x \\\"\"\" \u00e8\"\"\", e: -1e5) }", "{a(s:?s e:?f)}", "false"},
        };
        for (String[] c : ok) {
            GraphQL.Result r = GraphQL.shape(c[0]);
            assertEquals(c[1], r == null ? null : r.shape(), c[0]);
            assertEquals(Boolean.parseBoolean(c[2]), r.introspection(), c[0]);
        }
        for (String bad : List.of("ciao", "type Query { a: Int }", "{ a(x: 01) }", "", "{ a }}", "{ a(x: 1abc) }", "{ a(x: 1.5.2) }",
                "{ \u00e8 }", "{ a(x: \"\\q\") }", "{ a", "{ a(x: \"\n\") }", "fragment on on X { a }")) {
            assertNull(GraphQL.shape(bad), bad);
        }
        assertTrue(GraphQL.shape("{a".repeat(64) + "}".repeat(64)) != null, "64 open brackets");
        assertNull(GraphQL.shape("{a".repeat(65) + "}".repeat(65)), "65 open brackets");
        assertFalse(GraphQL.shape("{ __schema { a } x: __type { b } }").introspection(), "alias at the root");
        assertTrue(GraphQL.nameSafe("OrderStatus"));
        assertFalse(GraphQL.nameSafe("p_4821553"));
        assertFalse(GraphQL.nameSafe("deadbeefdeadbeef"));
        assertFalse(GraphQL.nameSafe("a".repeat(65)));
    }

    @Test
    void tokenizerRejectsWhatRfc8259Rejects() {
        for (String bad : List.of("{\"a\":1,}", "[1,2,]", "{'a':1}", "NaN", "01", "1.", ".5", "+1", "[1] [2]", "{\"a\" 1}", "\"\\x\"", "\"\t\"", "// c\n1", "{\"a\":tru}")) {
            assertThrows(Json.JsonError.class, () -> Json.parse(b(bad)), bad);
        }
        assertThrows(Json.JsonError.class, () -> Json.parse(new byte[] {(byte) 0xef, (byte) 0xbb, (byte) 0xbf, '1'}), "BOM");
        assertThrows(Json.JsonError.class, () -> Json.parse(new byte[] {'"', (byte) 0xc0, (byte) 0x80, '"'}), "overlong NUL");
        assertThrows(Json.JsonError.class, () -> Json.parse(new byte[] {'"', (byte) 0xed, (byte) 0xa0, (byte) 0x80, '"'}), "encoded surrogate");
    }

    @Test
    void tokenizerKeepsLexemesAndFlagsLoneSurrogates() {
        Json.Arr a = (Json.Arr) Json.parse(b("[1.50, 1E3, -0.0, \"\\ud800\", \"\\ud83d\\ude00\"]"));
        assertEquals("1.50", ((Json.Num) a.items.get(0)).lex);
        assertEquals("1E3", ((Json.Num) a.items.get(1)).lex);
        assertEquals("-0.0", ((Json.Num) a.items.get(2)).lex);
        assertTrue(((Json.Str) a.items.get(3)).bad);
        assertFalse(((Json.Str) a.items.get(4)).bad);
    }

    @Test
    void deepDocumentsDoNotOverflowTheStack() {
        String deep = "[".repeat(200_000) + "]".repeat(200_000);
        Json.Node n = Json.parse(b(deep));
        assertTrue(n instanceof Json.Arr);
    }

    @Test
    void canonicalNumbersFollowSection10_2() {
        Map<String, String> cases = Map.ofEntries(
            Map.entry("1.50", "1.5"), Map.entry("15e-1", "1.5"), Map.entry("-0.0", "0"), Map.entry("1E3", "1000"),
            Map.entry("123456789012345678901234567890", "1.2345678901234567890123456789e+29"), Map.entry("1e21", "1e+21"),
            Map.entry("1e20", "100000000000000000000"), Map.entry("0.0000015", "0.0000015"), Map.entry("0.00000015", "1.5e-7"),
            Map.entry("0.0015", "0.0015"), Map.entry("73.40", "73.4"), Map.entry("-12e2", "-1200"), Map.entry("0e5", "0"));
        cases.forEach((in, out) -> assertEquals(out, Json.canonicalNumber(in), in));
        assertTrue(Json.lexemeWithinLimits("1e9999"));
        assertFalse(Json.lexemeWithinLimits("1e10000"));
        assertFalse(Json.lexemeWithinLimits("1".repeat(65)));
    }

    @Test
    void keyRingParsingIsStrict() {
        String k = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
        assertEquals(List.of("k1", "k2"), KeyRing.parse("k1:" + k + "\r\n\nk2:" + k + "\n").kids());
        for (String bad : List.of("k1:" + k + "=", "K1:" + k, "k1" + k, "k1:AAAA", "k1:" + k + " ", "k1:" + k.substring(0, 10) + "+" + k.substring(11), "")) {
            Refused r = assertThrows(Refused.class, () -> KeyRing.parse(bad), bad);
            assertEquals("key_missing", r.code());
        }
        assertEquals("key_missing", assertThrows(Refused.class, () -> KeyRing.parse(null)).code());
    }

    @Test
    void gzipDecodingIsStrict() throws Exception {
        byte[] plain = b("{\"a\":[1,2,3]}");
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try (GZIPOutputStream g = new GZIPOutputStream(bo)) {
            g.write(plain);
        }
        byte[] gz = bo.toByteArray();
        assertTrue(java.util.Arrays.equals(plain, BodyDecoder.decode(gz, false, 1000).data));
        assertNull(BodyDecoder.decode(java.util.Arrays.copyOf(gz, gz.length - 3), false, 1000).data, "truncated");
        byte[] trailing = java.util.Arrays.copyOf(gz, gz.length + 1);
        assertNull(BodyDecoder.decode(trailing, false, 1000).data, "bytes after the stream");
        assertTrue(BodyDecoder.decode(gz, false, 5).cap, "output cap");
        byte[] bad = gz.clone();
        bad[bad.length - 6] ^= 0x55;
        assertNull(BodyDecoder.decode(bad, false, 1000).data, "corrupt CRC");
    }

    @Test
    void utf8IsStrict() {
        assertNull(Utf8.decode(new byte[] {(byte) 0xc0, (byte) 0xaf}));
        assertNull(Utf8.decode(new byte[] {(byte) 0xf4, (byte) 0x90, (byte) 0x80, (byte) 0x80}));
        assertEquals("\u00e8", Utf8.decode(new byte[] {(byte) 0xc3, (byte) 0xa8}));
        assertEquals(4, Utf8.length("\ud83d\ude00"));
    }

    // --- G1: with the empty policy no input value reaches the output ----------------------

    static Sanitizer empty() throws Exception {
        Path root = ConformanceTest.dir();
        Object body = Json.parsePlain(Files.readAllBytes(root.resolve("policies/empty.json")), true);
        Policy p = new Policy(PolicyValidator.validate(body));
        return new Sanitizer(p, KeyRing.parse("k1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8").select(p));
    }

    static String secret(Random r, int i) {
        String alphabet = "abcdefghijklmnopqrstuvwxyz";
        StringBuilder sb = new StringBuilder("zq");
        for (int k = 0; k < 10; k++) sb.append(alphabet.charAt(r.nextInt(alphabet.length())));
        return sb + "x" + i;
    }

    @Test
    void withTheEmptyPolicyNoInputValueEverReachesTheOutput() throws Exception {
        Sanitizer s = empty();
        Random r = new Random(20261023);
        for (int i = 0; i < 400; i++) {
            List<String> secrets = new ArrayList<>();
            java.util.function.Supplier<String> sec = () -> {
                String v = secret(r, secrets.size());
                secrets.add(v);
                return v;
            };
            Exchange ex = new Exchange();
            ex.inbound = r.nextBoolean();
            if (ex.inbound) ex.serviceName = "shop-api";
            else {
                // Spec v1.5: a host label is structure only if it passes the label rule (3.5); otherwise it is {*}.
                String label = switch (r.nextInt(4)) {
                    case 0 -> "t-" + (100000 + r.nextInt(900000)) + "-" + sec.get();       // rule b: six digits
                    case 1 -> sec.get() + "-deadbeef" + String.format("%04x", r.nextInt(65536)); // rule c: 12 hex in a row
                    case 2 -> "9" + sec.get();                                        // rule a: starts with a digit
                    default -> "tenant" + r.nextInt(100);                                    // safe: structure, like a name
                };
                ex.urlBase = "https://" + label + ".cdn.example:" + (1 + r.nextInt(65534));
            }
            ex.method = r.nextInt(4) == 0 ? sec.get() : "POST";
            ex.rawPath = b("/" + sec.get() + "/" + sec.get() + "%2F" + sec.get());
            ex.rawQuery = r.nextInt(3) == 0 ? null : b(sec.get() + "&k=" + sec.get() + "&" + sec.get() + "=" + sec.get());
            ex.reqHeaders.add(new Header("X-Custom", b(sec.get())));
            ex.reqHeaders.add(new Header("Cookie", b("a=" + sec.get() + "; b=" + sec.get())));
            ex.reqHeaders.add(new Header("Content-Type", b("application/json")));
            ex.reqHeaders.add(new Header("Authorization", b("Bearer " + sec.get())));
            String k1 = "name";
            ex.reqBody = b("{\"" + k1 + "\":\"" + sec.get() + "\",\"n\":" + (1000 + r.nextInt(9000)) + ",\"arr\":[\"" + sec.get() + "\",{\"deep\":\"" + sec.get()
                + "\"}],\"" + sec.get() + "\":\"" + sec.get() + "\"}");
            ex.status = 200;
            ex.respHeaders.add(new Header("Set-Cookie", b("sid=" + sec.get() + "; Path=/; HttpOnly")));
            ex.respHeaders.add(new Header("Content-Type", b("application/x-www-form-urlencoded")));
            ex.respBody = b("f=" + sec.get() + "&" + sec.get());
            Sanitizer.Result res = s.run(ex, System.currentTimeMillis(), null);
            assertEquals("event", res.outcome);
            if (!ex.inbound) assertServiceLabelsSafe(res.canonical);
            for (String sv : secrets) {
                // A JSON key that looks like a literal name is allowed to appear (structure); nothing else is.
                String key = "\"" + sv + "\":";
                String canon = res.canonical;
                if (canon.contains(sv)) {
                    // The only allowed place is a name, i.e. it must be followed by a colon (object key) and carry no value.
                    assertTrue(canon.contains(key) || canon.contains("\"" + sv + "\":["), "leak of " + sv + " in " + canon);
                    assertFalse(canon.replace(key, "").contains(sv), "value leak of " + sv + " in " + canon);
                }
            }
        }
    }

    /** G1 with host labels (sanitizer.md 3.5): every literal label of the outbound service passes the label rule; at most 518 bytes. */
    static void assertServiceLabelsSafe(String canon) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"service\":\"([^\"]*)\"").matcher(canon);
        assertTrue(m.find(), canon);
        String service = m.group(1);
        assertTrue(service.getBytes(StandardCharsets.UTF_8).length <= 518, service);
        assertTrue(service.startsWith("host:"), service);
        String pat = service.substring(5).replaceFirst(":[0-9]+$", "");
        if (pat.startsWith("ip:") || pat.equals("invalid")) return;
        for (String label : pat.split("\\.", -1)) {
            assertTrue(label.equals("{*}") || HostPattern.labelSafe(label), "unsafe label " + label + " in " + service);
        }
    }
}
