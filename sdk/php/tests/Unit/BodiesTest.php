<?php

declare(strict_types=1);

namespace TrafficTwin\Tests\Unit;

use PHPUnit\Framework\TestCase;
use TrafficTwin\Sanitizer\Bodies;
use TrafficTwin\Sanitizer\BodyError;
use TrafficTwin\Sanitizer\Exchange;
use TrafficTwin\Sanitizer\Json;
use TrafficTwin\Sanitizer\Policy;
use TrafficTwin\Sanitizer\PolicySchema;
use TrafficTwin\Sanitizer\Refused;
use TrafficTwin\Sanitizer\Sanitizer;
use TrafficTwin\Sanitizer\XmlParser;

/** Spec v1.19 (sanitizer.md 22): hostile XML, multipart edge cases, base64 documents, bodies policy field. */
final class BodiesTest extends TestCase
{
    private const KEY = ['kid' => 'k1', 'key' => "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"];
    private const BODIES = '{"xml":true,"multipart":true,"docs":true,"max_large_body_bytes":0,"large_array":50,"large_nested_array":5}';

    private static function policyJson(string $bodies, string $services = '[]', string $maxBody = '1048576'): string
    {
        return '{"format":"tt.policy.body/v1","policy_id":"p-shop","version":1,"issued_seq":1,'
            . '"created_at":"2026-10-20T08:00:00Z","not_after":"2026-11-19T08:00:00Z",'
            . '"targets":{"groups":["shop"]},"hmac":{"kid":"k1","accept_kids":[],"epoch":"2026-10"},'
            . '"sampling":{"rate_bp":10000,"trust_baggage":false,"propagate_to":[]},'
            . '"segments":{"auto_words":false,"allow":[],"hosts_allow":[]},'
            . '"limits":{"max_body_bytes":' . $maxBody . ',"max_depth":32,"max_array":32,"max_keys":256,"keep_max_bytes":64},'
            . ($bodies === '' ? '' : '"bodies":' . $bodies . ',')
            . '"global":{},"services":' . $services . '}';
    }

    private static function policy(string $json): Policy
    {
        return new Policy(PolicySchema::validate(Json::toPlain(Json::parse($json, 64), true)));
    }

    private static function invalidXml(string $doc): bool
    {
        try {
            XmlParser::parse($doc);
            return false;
        } catch (BodyError) {
            return true;
        }
    }

    /** Request body of an inbound POST through the sanitizer; returns the canonical `req` member. */
    private static function req(Policy $p, string $ct, string $body, array $extraHeaders = []): string
    {
        $ex = new Exchange();
        $ex->method = 'POST';
        $ex->rawPath = '/ws';
        $ex->serviceName = 'shop-api';
        $ex->reqHeaders = array_merge([['Content-Type', $ct]], $extraHeaders);
        $ex->reqBody = $body;
        $ex->status = 200;
        $r = (new Sanitizer($p, self::KEY))->run($ex, null);
        self::assertSame('event', $r->outcome);
        return $r->parts['req'];
    }

    // --- XML (22.2) ---------------------------------------------------------------------

    public function testXmlRefusesDtdAndEntities(): void
    {
        self::assertTrue(self::invalidXml('<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>'));
        self::assertTrue(self::invalidXml('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><a>&lol2;</a>'));
        self::assertTrue(self::invalidXml('<a>&ext;</a>'), 'unknown entity');
        self::assertTrue(self::invalidXml('<a>fish & chips</a>'), 'bare ampersand');
        self::assertTrue(self::invalidXml('<a>&amp</a>'), 'reference without ;');
        self::assertTrue(self::invalidXml('<a>&#0;</a>'), 'forbidden character reference');
        self::assertTrue(self::invalidXml('<a>&#x110000;</a>'), 'reference out of range');
        self::assertTrue(self::invalidXml('<a>&#xD800;</a>'), 'surrogate reference');
        self::assertTrue(self::invalidXml('<a><!ENTITY x "y"></a>'), 'declaration in content');
        self::assertTrue(self::invalidXml('<a b="1" b="2"/>'), 'duplicate attribute');
        self::assertTrue(self::invalidXml('<a b="<"/>'), '< in attribute');
        self::assertTrue(self::invalidXml('<p:a/>'), 'undeclared prefix');
        self::assertTrue(self::invalidXml('<a/><b/>'), 'two roots');
        self::assertTrue(self::invalidXml("<a>\x01</a>"), 'control character');
        self::assertTrue(self::invalidXml("<a>\xEF\xBF\xBE</a>"), 'U+FFFE');
        self::assertTrue(self::invalidXml("<a>\xC3</a>"), 'not UTF-8');
        self::assertTrue(self::invalidXml(''), 'empty');
    }

    public function testXmlNestingLimit(): void
    {
        $ok = str_repeat('<a>', 256) . str_repeat('</a>', 256);
        self::assertFalse(self::invalidXml($ok));
        $deep = str_repeat('<a>', 257) . str_repeat('</a>', 257);
        self::assertTrue(self::invalidXml($deep));
        // A million unclosed tags fail fast on the nesting limit, without recursion.
        self::assertTrue(self::invalidXml(str_repeat('<a>', 1000000)));
    }

    public function testXmlReferencesAndTree(): void
    {
        $root = XmlParser::parse("\xEF\xBB\xBF<?xml version=\"1.0\"?><r xmlns=\"urn:x\" a=\"x&#9;y\tz\"><c>&lt;&#x41;&#66;</c><c><![CDATA[&raw]]></c>t</r>");
        self::assertSame('r', $root->local);
        self::assertSame('urn:x', $root->ns);
        self::assertSame([['a', "x\ty z"]], $root->attrs);
        self::assertSame('<AB', $root->children[0]->text);
        self::assertSame('&raw', $root->children[1]->text);
        [$tree, $entries, $fmt] = Bodies::xmlTree($root, 32);
        self::assertSame('xml', $fmt);
        self::assertSame(['$.r' => 'ns:urn:x'], $entries);
        self::assertSame('{"r":{"#text":"t","@a":"x\u0009y z","c":["<AB","&raw"]}}', Json::write(Json::toOut($tree)));
    }

    public function testNamespacePatterns(): void
    {
        self::assertSame('ns:{none}', Bodies::nsPattern(''));
        self::assertSame('ns:http://schemas.xmlsoap.org/soap/envelope/', Bodies::nsPattern('http://schemas.xmlsoap.org/soap/envelope/'));
        self::assertSame('ns:http://a.example/customers/{*}/x', Bodies::nsPattern('http://a.example/customers/3912345678/x'));
        self::assertSame('ns:{*}', Bodies::nsPattern('mailto:mario.rossi@example.com'));
        self::assertSame('ns:urn:{*}', Bodies::nsPattern('urn:' . str_repeat('a', 65)));
    }

    public function testSoapActionNames(): void
    {
        self::assertSame('GetOrder', Bodies::soapActionName('"http://ws.example/orders/v2/GetOrder"'));
        self::assertSame('Renew', Bodies::soapActionName('urn:x#Renew'));
        self::assertNull(Bodies::soapActionName('""'));
        self::assertSame('{*}', Bodies::soapActionName('http://x.example/'));
        self::assertSame('Bare', Bodies::soapActionName(' Bare '));
    }

    public function testSoapThroughTheSanitizer(): void
    {
        $p = self::policy(self::policyJson(self::BODIES));
        $env = '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><Get xmlns="urn:shop"><id>A-1</id></Get></s:Body></s:Envelope>';
        $req = self::req($p, 'text/xml; charset=utf-8', $env, [['SOAPAction', '"urn:shop#Get"']]);
        self::assertStringContainsString('"fmt":"soap11"', $req);
        self::assertStringContainsString('"soap_action":"Get"', $req);
        self::assertStringContainsString('"body":{"Envelope":{"Body":{"Get":{"id":"drop:str:l8"}}}}', $req);
        self::assertStringContainsString('"$.Envelope.Body.Get":"ns:urn:shop"', $req);
        $bad = self::req($p, 'application/xml', '<!DOCTYPE a><a/>');
        self::assertStringContainsString('"body":"trunc:invalid-xml"', $bad);
        self::assertStringContainsString('"fmt":"xml"', $bad);
        self::assertStringNotContainsString('soap_action', $bad);
        // Without bodies.xml the body is not parsed.
        $off = self::req(self::policy(self::policyJson('')), 'text/xml', $env, [['SOAPAction', 'urn:shop#Get']]);
        self::assertStringContainsString('"body":"drop:bytes:l1024"', $off);
        self::assertStringNotContainsString('fmt', $off);
    }

    // --- multipart (22.3) ---------------------------------------------------------------

    public function testMultipartFraming(): void
    {
        $body = "preamble\r\n--XyZ \t\r\nContent-Disposition: form-data; name=\"a\\\"b\"; x\r\n\r\nv1\r\n"
            . "--XyZ\r\ncontent-disposition: FORM-DATA; name=f; filename=\"r.pdf\"\r\nContent-Type: application/octet-stream\r\n\r\n%PDF-1.7 x\r\n"
            . "--XyZ\r\n\r\nno headers\r\n--XyZ--\r\nepilogue";
        try {
            Bodies::parseMultipart($body, 'XyZ');
            self::fail('a part without headers has no content-disposition');
        } catch (BodyError) {
        }
        $body = str_replace("--XyZ\r\n\r\nno headers\r\n", '', $body);
        $parts = Bodies::parseMultipart($body, 'XyZ');
        self::assertCount(2, $parts);
        self::assertSame(['name' => 'a"b', 'file' => false, 'content' => 'v1', 'ct' => null], $parts[0]);
        self::assertTrue($parts[1]['file']);
        self::assertSame('drop:file:pdf:l1k', Bodies::fileToken($parts[1]['content'], $parts[1]['ct']));
        self::assertSame('drop:file:csv:l1k', Bodies::fileToken('a,b', 'text/csv'));
        self::assertSame('drop:file:bin:l1k', Bodies::fileToken('', null));
    }

    public function testMultipartRefusals(): void
    {
        $cases = [
            'no boundary' => ["--b\r\nContent-Disposition: form-data; name=a\r\n\r\nx\r\n--b--", null],
            'boundary ending with a space' => ["--b \r\n", 'b '],
            'boundary over 70 bytes' => ['', str_repeat('b', 71)],
            'no close delimiter' => ["--b\r\nContent-Disposition: form-data; name=a\r\n\r\nx", 'b'],
            'garbage after the delimiter' => ["--b x\r\nContent-Disposition: form-data; name=a\r\n\r\nx\r\n--b--", 'b'],
            'not form-data' => ["--b\r\nContent-Disposition: attachment; name=a\r\n\r\nx\r\n--b--", 'b'],
            'no name' => ["--b\r\nContent-Disposition: form-data; filename=a\r\n\r\nx\r\n--b--", 'b'],
            'unterminated quote' => ["--b\r\nContent-Disposition: form-data; name=\"a\r\n\r\nx\r\n--b--", 'b'],
            'garbage after quote' => ["--b\r\nContent-Disposition: form-data; name=\"a\"x\r\n\r\nx\r\n--b--", 'b'],
            'header continuation' => ["--b\r\nContent-Disposition: form-data; name=a\r\n folded\r\n\r\nx\r\n--b--", 'b'],
            'no blank line' => ["--b\r\nContent-Disposition: form-data; name=a\r\n--b--", 'b'],
            'disposition not UTF-8' => ["--b\r\nContent-Disposition: form-data; name=\xff\r\n\r\nx\r\n--b--", 'b'],
        ];
        foreach ($cases as $what => [$body, $boundary]) {
            try {
                Bodies::parseMultipart($body, $boundary);
                self::fail($what);
            } catch (BodyError) {
                self::addToAssertionCount(1);
            }
        }
        self::assertSame([], Bodies::parseMultipart("--b--\r\n", 'b'));
    }

    public function testMultipartThroughTheSanitizer(): void
    {
        $p = self::policy(self::policyJson(self::BODIES));
        $body = "--q\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n"
            . "--q\r\nContent-Disposition: form-data; name=\"doc\"; filename*=UTF-8''x.png\r\n\r\n\x89PNG\r\n\x1a\nrest\r\n--q--\r\n";
        $req = self::req($p, 'multipart/form-data; boundary="q"', $body);
        self::assertStringContainsString('"body":{"doc":["drop:file:png:l1k"],"note":["drop:str:l8"]}', $req);
        self::assertStringContainsString('"fmt":"multipart"', $req);
        $bad = self::req($p, 'multipart/form-data', $body);
        self::assertStringContainsString('"body":"trunc:invalid-multipart"', $bad);
    }

    // --- documents (22.4) ----------------------------------------------------------------

    public function testBase64Documents(): void
    {
        $pdf = '%PDF-1.7 ' . str_repeat('x', 40);
        self::assertSame('drop:doc:pdf:l1k', Bodies::base64Doc(base64_encode($pdf)));
        self::assertSame('drop:doc:pdf:l1k', Bodies::base64Doc('data:application/pdf;base64,' . base64_encode($pdf)));
        self::assertSame('drop:doc:pdf:l1k', Bodies::base64Doc(rtrim(strtr(base64_encode($pdf), '+/', '-_'), '=')));
        self::assertNull(Bodies::base64Doc('data:application/pdf,' . base64_encode($pdf)), 'no ;base64');
        self::assertNull(Bodies::base64Doc(base64_encode('just some plain text here')));
        self::assertNull(Bodies::base64Doc('JVBERi0xLjcg eHh4eHh4'), 'space');
        self::assertNull(Bodies::base64Doc('JVBERi0='), 'too short');
        self::assertNull(Bodies::base64Doc('JVBERi0xLjcgeHh4eHh4eA='), 'padding with a length not multiple of 4');
        self::assertSame('l16k', Bodies::docClass(1025));
        self::assertSame('lmax', Bodies::docClass(8388609));
    }

    // --- policy (22.1, 5.6) ---------------------------------------------------------------

    public function testBodiesFieldValidation(): void
    {
        $p = self::policy(self::policyJson('{"xml":true,"multipart":false,"docs":true,"max_large_body_bytes":4194304,"large_array":100,"large_nested_array":10}', '[]', '2048'));
        self::assertTrue($p->xml);
        self::assertFalse($p->multipart);
        self::assertSame(4194305, $p->bodyCaptureLimit());
        $off = self::policy(self::policyJson(''));
        self::assertFalse($off->xml || $off->multipart || $off->docs);
        self::assertSame(1048577, $off->bodyCaptureLimit());
        foreach ([
            '{"xml":true}',
            '{"xml":true,"multipart":true,"docs":true,"max_large_body_bytes":67108865,"large_array":1,"large_nested_array":1}',
            '{"xml":true,"multipart":true,"docs":true,"max_large_body_bytes":0,"large_array":1025,"large_nested_array":1}',
            '{"xml":1,"multipart":true,"docs":true,"max_large_body_bytes":0,"large_array":1,"large_nested_array":1}',
            '{"xml":true,"multipart":true,"docs":true,"max_large_body_bytes":0,"large_array":1,"large_nested_array":1,"yaml":true}',
        ] as $bad) {
            try {
                self::policy(self::policyJson($bad));
                self::fail($bad);
            } catch (Refused $r) {
                self::assertSame('policy_rejected', $r->reason);
            }
        }
    }

    public function testCodeShapeAndTtPathValidation(): void
    {
        $svc = static fn (string $path, string $action): string => '[{"name":"shop-api","match":{"inbound":true,"internal":false},"ops":[{"op":"GET /a","response":{"body":[{"path":"' . $path . '","action":' . $action . '}]}}]}]';
        self::policy(self::policyJson('', $svc('$.Envelope.order.@id', '{"action":"code","shape":"alnum"}')));
        self::policy(self::policyJson('', $svc('$.order.mixed.#text', '{"action":"code"}')));
        foreach ([
            [$svc('$.a', '{"action":"code","shape":"digits"}'), 'unknown shape'],
            [$svc('$.a', '{"action":"keep","shape":"alnum"}'), 'shape on keep'],
            [$svc('$.a.#value', '{"action":"keep"}'), '.#value'],
            [$svc('$.a.@', '{"action":"keep"}'), 'empty attribute'],
        ] as [$services, $what]) {
            try {
                self::policy(self::policyJson('', $services));
                self::fail($what);
            } catch (Refused $r) {
                self::assertSame('policy_rejected', $r->reason, $what);
            }
        }
    }
}
