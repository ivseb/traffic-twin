package io.github.ivseb.traffictwin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.ivseb.traffictwin.sanitizer.Exchange;
import io.github.ivseb.traffictwin.sanitizer.HostPattern;
import io.github.ivseb.traffictwin.sanitizer.Json;
import io.github.ivseb.traffictwin.sanitizer.KeyRing;
import io.github.ivseb.traffictwin.sanitizer.Policy;
import io.github.ivseb.traffictwin.sanitizer.PolicyValidator;
import io.github.ivseb.traffictwin.sanitizer.Refused;
import io.github.ivseb.traffictwin.sanitizer.Sanitizer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/** Host autodiscovery (spec v1.5): the examples of sanitizer.md 3.5, the IPv6 parser, the class table and strict mode. */
class HostPatternTest {
    @SuppressWarnings("unchecked")
    static Sanitizer sanitizer(String discovery) throws Exception {
        Object body = Json.parsePlain(Files.readAllBytes(ConformanceTest.dir().resolve("policies/empty.json")), true);
        Map<String, Object> b = new LinkedHashMap<>((Map<String, Object>) body);
        if (discovery != null) b.put("hosts", new LinkedHashMap<>(Map.of("discovery", discovery)));
        Policy p = new Policy(PolicyValidator.validate(b));
        return new Sanitizer(p, KeyRing.parse("k1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8").select(p));
    }

    static String service(Sanitizer s, String urlBase) {
        Exchange ex = new Exchange();
        ex.inbound = false;
        ex.method = "GET";
        ex.rawPath = "/x".getBytes(StandardCharsets.UTF_8);
        ex.urlBase = urlBase;
        ex.status = 200;
        Sanitizer.Result r = s.run(ex, System.currentTimeMillis(), null);
        assertEquals("event", r.outcome);
        Matcher m = Pattern.compile("\"service\":\"([^\"]*)\"").matcher(r.canonical);
        assertTrue(m.find(), r.canonical);
        return m.group(1);
    }

    @Test
    void examplesOfSection35() throws Exception {
        Sanitizer s = sanitizer(null);
        Map<String, String> cases = new LinkedHashMap<>();
        cases.put("https://api.carrier.example", "host:api.carrier.example");
        cases.put("HTTPS://API.Carrier.example:443", "host:api.carrier.example");
        cases.put("https://api.carrier.example.:8443", "host:api.carrier.example:8443");
        cases.put("https://t-3912345678.tenant.example", "host:{*}.tenant.example");
        cases.put("https://cdn-9f8e7d6c5b4a.assets.example", "host:{*}.assets.example");
        cases.put("https://1password.example", "host:{*}.example");
        cases.put("https://xn--bcher-kva.example", "host:xn--bcher-kva.example");
        cases.put("http://10.0.0.5:8080", "host:ip:private:8080");
        cases.put("https://[2606:4700::1111]", "host:ip:public");
        cases.put("https://api..carrier.example", "host:invalid");
        cases.put("https://ab12cd34ef56.0012345678.cdn.example", "host:{*}.{*}.cdn.example");
        cases.put("https://bücher.example", "host:invalid");
        cases.put("https://[fe80::1%25eth0]", "host:invalid");
        cases.put("https://[::1", "host:invalid");
        cases.put("https://[::1]x", "host:invalid");
        cases.put("https://010.0.0.1", "host:{*}.{*}.{*}.{*}");
        cases.put("https://2130706433", "host:{*}");
        for (Map.Entry<String, String> e : cases.entrySet()) assertEquals(e.getValue(), service(s, e.getKey()), e.getKey());
    }

    @Test
    void strictModeKeepsUnlistedAndDiscoveryModeIsStillAPattern() throws Exception {
        Sanitizer strict = sanitizer("off");
        assertEquals("host:unlisted", service(strict, "https://api.carrier.example"));
        assertEquals("host:unlisted", service(strict, "http://10.0.0.5:8080"));
        assertEquals("host:unlisted", service(strict, "https://api..carrier.example"));
        assertEquals("host:invalid", service(strict, "https://[::1"));
        assertEquals("host:unlisted", service(strict, "https://[2606:4700::1111]"));
        assertEquals("host:api.carrier.example", service(sanitizer("auto"), "https://api.carrier.example"));
    }

    @Test
    void policyHostsObjectIsValidated() throws Exception {
        for (Object bad : List.of("on", "", 1, Boolean.TRUE)) {
            assertThrows(Refused.class, () -> bodyWith(new LinkedHashMap<>(Map.of("discovery", bad))));
        }
        assertThrows(Refused.class, () -> bodyWith(new LinkedHashMap<>()));
        assertThrows(Refused.class, () -> bodyWith(new LinkedHashMap<>(Map.of("discovery", "off", "extra", "x"))));
        assertThrows(Refused.class, () -> bodyWith("off"));
    }

    @SuppressWarnings("unchecked")
    static void bodyWith(Object hosts) throws Exception {
        Object body = Json.parsePlain(Files.readAllBytes(ConformanceTest.dir().resolve("policies/empty.json")), true);
        Map<String, Object> b = new LinkedHashMap<>((Map<String, Object>) body);
        b.put("hosts", hosts);
        PolicyValidator.validate(b);
    }

    @Test
    void ipv6ParserFollowsTheSpecTextForm() {
        for (String ok : List.of("::", "::1", "1::", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7::", "::2:3:4:5:6:7:8", "::ffff:1.2.3.4", "64:ff9b::10.0.0.1",
            "1:2:3:4:5:6:1.2.3.4", "2001:db8::", "ABCD::".toLowerCase())) {
            assertNotNull(HostPattern.parseIpv6(ok), ok);
        }
        for (String bad : List.of("", ":", ":::", "1::2::3", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7::8", "12345::", "g::", "::1%eth0",
            "::01.2.3.4", "::1.2.3", "::1.2.3.256", "1.2.3.4::", "::1.2.3.4:1", "1:2:3:4:5:6:7:1.2.3.4", ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:", "::ffff:1.2.3.4.5", "[::1]")) {
            assertNull(HostPattern.parseIpv6(bad), bad);
        }
    }

    @Test
    void classTableIsClosedAndEmbeddedIpv4IsLookedUpFirst() throws Exception {
        Sanitizer s = sanitizer(null);
        Map<String, String> cases = new LinkedHashMap<>();
        cases.put("http://0.1.2.3", "private");
        cases.put("http://100.64.0.1", "private");
        cases.put("http://100.128.0.1", "public");
        cases.put("http://172.15.0.1", "public");
        cases.put("http://172.31.255.255", "private");
        cases.put("http://198.19.255.255", "private");
        cases.put("http://198.20.0.0", "public");
        cases.put("http://169.254.169.254", "private");
        cases.put("http://8.8.8.8", "public");
        cases.put("http://[::ffff:8.8.8.8]", "public");
        cases.put("http://[::ffff:10.0.0.1]", "private");
        cases.put("http://[64:ff9b::808:808]", "public");
        cases.put("http://[64:ff9b::a00:1]", "private");
        cases.put("http://[64:ff9b:1::1]", "private");
        cases.put("http://[::8.8.8.8]", "private");
        cases.put("http://[100::1]", "private");
        cases.put("http://[100:0:0:1::1]", "public");
        cases.put("http://[2001:1::1]", "private");
        cases.put("http://[2001:200::1]", "public");
        cases.put("http://[2001:db8::1]", "private");
        cases.put("http://[fd00::1]", "private");
        cases.put("http://[fbff::1]", "public");
        cases.put("http://[febf::1]", "private");
        cases.put("http://[fec0::1]", "private");
        cases.put("http://[ff02::1]", "private");
        cases.put("http://[2606:4700::1111]", "public");
        for (Map.Entry<String, String> e : cases.entrySet()) assertEquals("host:ip:" + e.getValue(), service(s, e.getKey()), e.getKey());
        assertFalse(service(s, "http://[::1]:8080").contains("::"));
        assertEquals("host:ip:private:8080", service(s, "http://[::1]:8080"));
        assertEquals("host:ip:private", service(s, "http://[::1]:80"));
    }
}
