<?php

declare(strict_types=1);

namespace TrafficTwin\Tests\Unit;

use PHPUnit\Framework\TestCase;
use TrafficTwin\Sanitizer\Exchange;
use TrafficTwin\Sanitizer\HostPattern;
use TrafficTwin\Sanitizer\Json;
use TrafficTwin\Sanitizer\KeyRing;
use TrafficTwin\Sanitizer\Policy;
use TrafficTwin\Sanitizer\PolicySchema;
use TrafficTwin\Sanitizer\PObj;
use TrafficTwin\Sanitizer\Refused;
use TrafficTwin\Sanitizer\Sanitizer;

/** Host autodiscovery (spec v1.5): the examples of sanitizer.md 3.5, the IPv6 parser, the class table, strict mode and G1 with host labels. */
final class HostPatternTest extends TestCase
{
    private const ROOT = __DIR__ . '/../../../../conformance';

    /** The shared empty policy with an optional top-level `hosts` member (raw JSON text, so `{}` stays an object). */
    private static function bodyJson(?string $hostsJson): string
    {
        $text = rtrim((string) file_get_contents(self::ROOT . '/policies/empty.json'));
        return $hostsJson === null ? $text : substr($text, 0, -1) . ',"hosts":' . $hostsJson . '}';
    }

    private static function validate(string $json): PObj
    {
        return PolicySchema::validate(Json::toPlain(Json::parse($json, 64), true));
    }

    private static function make(?string $discovery): Sanitizer
    {
        $policy = new Policy(self::validate(self::bodyJson($discovery === null ? null : '{"discovery":"' . $discovery . '"}')));
        $ring = KeyRing::parse('k1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8');
        return new Sanitizer($policy, $ring->select($policy));
    }

    private static function event(Sanitizer $s, string $urlBase): string
    {
        $ex = new Exchange();
        $ex->dir = 'outbound';
        $ex->method = 'GET';
        $ex->rawPath = '/x';
        $ex->urlBase = $urlBase;
        $ex->status = 200;
        $r = $s->run($ex, time());
        self::assertSame('event', $r->outcome);
        return (string) $r->canonical;
    }

    private static function service(Sanitizer $s, string $urlBase): string
    {
        self::assertSame(1, preg_match('/"service":"([^"]*)"/', self::event($s, $urlBase), $m));
        return $m[1];
    }

    public function testExamplesOfSection35(): void
    {
        $s = self::make(null);
        $cases = [
            'https://api.carrier.example' => 'host:api.carrier.example',
            'HTTPS://API.Carrier.example:443' => 'host:api.carrier.example',
            'https://api.carrier.example.:8443' => 'host:api.carrier.example:8443',
            'https://t-3912345678.tenant.example' => 'host:{*}.tenant.example',
            'https://cdn-9f8e7d6c5b4a.assets.example' => 'host:{*}.assets.example',
            'https://1password.example' => 'host:{*}.example',
            'https://xn--bcher-kva.example' => 'host:xn--bcher-kva.example',
            'http://10.0.0.5:8080' => 'host:ip:private:8080',
            'https://[2606:4700::1111]' => 'host:ip:public',
            'https://api..carrier.example' => 'host:invalid',
            'https://ab12cd34ef56.0012345678.cdn.example' => 'host:{*}.{*}.cdn.example',
            "https://b\u{00fc}cher.example" => 'host:invalid',
            'https://[fe80::1%25eth0]' => 'host:invalid',
            'https://[::1' => 'host:invalid',
            'https://[::1]x' => 'host:invalid',
            'https://010.0.0.1' => 'host:{*}.{*}.{*}.{*}',
            'https://2130706433' => 'host:{*}',
        ];
        foreach ($cases as $url => $want) {
            self::assertSame($want, self::service($s, (string) $url), (string) $url);
        }
    }

    public function testStrictModeKeepsUnlistedAndDiscoveryModeIsStillAPattern(): void
    {
        $strict = self::make('off');
        self::assertSame('host:unlisted', self::service($strict, 'https://api.carrier.example'));
        self::assertSame('host:unlisted', self::service($strict, 'http://10.0.0.5:8080'));
        self::assertSame('host:unlisted', self::service($strict, 'https://api..carrier.example'));
        self::assertSame('host:invalid', self::service($strict, 'https://[::1'));
        self::assertSame('host:unlisted', self::service($strict, 'https://[2606:4700::1111]'));
        self::assertSame('host:api.carrier.example', self::service(self::make('auto'), 'https://api.carrier.example'));
    }

    public function testPolicyHostsObjectIsValidated(): void
    {
        $bads = ['{"discovery":"on"}', '{"discovery":""}', '{"discovery":1}', '{"discovery":true}', '{"discovery":null}', '{"discovery":"off","extra":"x"}', '{}', '"off"', '[]', 'null'];
        foreach ($bads as $bad) {
            try {
                self::validate(self::bodyJson($bad));
                self::fail('accepted ' . $bad);
            } catch (Refused $e) {
                self::assertSame('policy_rejected', $e->reason);
            }
        }
        foreach (['auto', 'off'] as $ok) {
            self::assertNotNull(self::validate(self::bodyJson('{"discovery":"' . $ok . '"}')));
        }
    }

    public function testIpv6ParserFollowsTheSpecTextForm(): void
    {
        foreach (['::', '::1', '1::', '1:2:3:4:5:6:7:8', '1:2:3:4:5:6:7::', '::2:3:4:5:6:7:8', '::ffff:1.2.3.4', '64:ff9b::10.0.0.1', '1:2:3:4:5:6:1.2.3.4', '2001:db8::', 'abcd::'] as $ok) {
            self::assertNotNull(HostPattern::parseIpv6($ok), $ok);
        }
        $bad = ['', ':', ':::', '1::2::3', '1:2:3:4:5:6:7:8:9', '1:2:3:4:5:6:7', '1:2:3:4:5:6:7::8', '12345::', 'g::', '::1%eth0', '::01.2.3.4', '::1.2.3',
            '::1.2.3.256', '1.2.3.4::', '::1.2.3.4:1', '1:2:3:4:5:6:7:1.2.3.4', ':1:2:3:4:5:6:7', '1:2:3:4:5:6:7:', '::ffff:1.2.3.4.5', '[::1]', "::1\n", "1::\n"];
        foreach ($bad as $b) {
            self::assertNull(HostPattern::parseIpv6($b), (string) json_encode($b));
        }
    }

    public function testClassTableIsClosedAndEmbeddedIpv4IsLookedUpFirst(): void
    {
        $s = self::make(null);
        $cases = [
            'http://0.1.2.3' => 'private', 'http://100.64.0.1' => 'private', 'http://100.128.0.1' => 'public', 'http://172.15.0.1' => 'public',
            'http://172.31.255.255' => 'private', 'http://198.19.255.255' => 'private', 'http://198.20.0.0' => 'public',
            'http://169.254.169.254' => 'private', 'http://8.8.8.8' => 'public', 'http://[::ffff:8.8.8.8]' => 'public',
            'http://[::ffff:10.0.0.1]' => 'private', 'http://[64:ff9b::808:808]' => 'public', 'http://[64:ff9b::a00:1]' => 'private',
            'http://[64:ff9b:1::1]' => 'private', 'http://[::8.8.8.8]' => 'private', 'http://[100::1]' => 'private', 'http://[100:0:0:1::1]' => 'public',
            'http://[2001:1::1]' => 'private', 'http://[2001:200::1]' => 'public', 'http://[2001:db8::1]' => 'private', 'http://[fd00::1]' => 'private',
            'http://[fbff::1]' => 'public', 'http://[febf::1]' => 'private', 'http://[fec0::1]' => 'private', 'http://[ff02::1]' => 'private',
            'http://[2606:4700::1111]' => 'public',
        ];
        foreach ($cases as $url => $cls) {
            self::assertSame('host:ip:' . $cls, self::service($s, (string) $url), (string) $url);
        }
        self::assertSame('host:ip:private:8080', self::service($s, 'http://[::1]:8080'));
        self::assertSame('host:ip:private', self::service($s, 'http://[::1]:80'));
    }

    /** G1 (THREAT_MODEL) with host labels: with the empty policy no input value reaches the output; every literal label passes the rule. */
    public function testEmptyPolicyNeverEmitsAValueNorAnUnsafeHostLabel(): void
    {
        $s = self::make(null);
        mt_srand(20261023);
        $alphabet = 'abcdefghijklmnopqrstuvwxyz';
        $secret = static function (int $i) use ($alphabet): string {
            $v = 'zq';
            for ($k = 0; $k < 10; $k++) {
                $v .= $alphabet[mt_rand(0, 25)];
            }
            return $v . 'x' . $i;
        };
        for ($i = 0; $i < 400; $i++) {
            $sec = $secret($i);
            $label = match ($i % 4) {
                0 => 't-' . mt_rand(100000, 999999) . '-' . $sec,              // rule b
                1 => $sec . '-deadbeef' . sprintf('%04x', mt_rand(0, 65535)),  // rule c
                2 => '9' . $sec,                                               // rule a: starts with a digit
                default => 'tenant' . mt_rand(0, 99) . '_' . $sec,             // rule a: '_' is not allowed
            };
            $canon = self::event($s, 'https://' . $label . '.cdn.example:' . mt_rand(1, 65534));
            self::assertStringNotContainsString($sec, $canon);
            self::assertSame(1, preg_match('/"service":"([^"]*)"/', $canon, $m));
            self::assertLessThanOrEqual(518, strlen($m[1]));
            $pat = preg_replace('/:[0-9]+$/', '', substr($m[1], 5)) ?? '';
            if (!str_starts_with($pat, 'ip:') && $pat !== 'invalid') {
                foreach (explode('.', $pat) as $l) {
                    self::assertTrue($l === '{*}' || HostPattern::labelSafe($l), 'unsafe label ' . $l . ' in ' . $m[1]);
                }
            }
        }
    }
}
