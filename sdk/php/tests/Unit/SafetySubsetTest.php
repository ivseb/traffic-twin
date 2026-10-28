<?php

declare(strict_types=1);

namespace TrafficTwin\Tests\Unit;

use PHPUnit\Framework\TestCase;
use TrafficTwin\Sanitizer\Json;
use TrafficTwin\Sanitizer\PolicySchema;
use TrafficTwin\Sanitizer\Refused;

/** v1.3 source-side safety subset (docs/spec/hardening.md 2.1): H1, H2, H3. */
final class SafetySubsetTest extends TestCase
{
    private const CREATED = '2026-10-20T08:00:00Z';
    private const SEG = '{"auto_words":false,"allow":[],"hosts_allow":[]}';
    private const SVC_HEAD = '{"name":"shop-api","match":{"inbound":true,"internal":false}';

    private static function body(string $global, string $services, string $segments, string $discovery = ''): string
    {
        return '{"format":"tt.policy.body/v1","policy_id":"p-shop","version":1,"issued_seq":1,'
            . '"created_at":"' . self::CREATED . '","not_after":"2026-11-19T08:00:00Z",'
            . '"targets":{"groups":["shop"]},"hmac":{"kid":"k1","accept_kids":[],"epoch":"2026-10"},'
            . '"sampling":{"rate_bp":10000,"trust_baggage":false,"propagate_to":[]},'
            . '"segments":' . $segments . ','
            . '"limits":{"max_body_bytes":1048576,"max_depth":32,"max_array":32,"max_keys":256,"keep_max_bytes":64},'
            . ($discovery === '' ? '' : '"discovery":' . $discovery . ',')
            . '"global":' . $global . ',"services":' . $services . '}';
    }

    private static function outcome(string $json): string
    {
        try {
            PolicySchema::validate(Json::toPlain(Json::parse($json, 64), true));
            return 'accepted';
        } catch (Refused $r) {
            return $r->isUnsafe() ? 'unsafe' : $r->reason;
        }
    }

    public function testH1CredentialHeaders(): void
    {
        foreach (['authorization', 'cookie', 'set-cookie', 'proxy-authorization'] as $h) {
            foreach (['{"action":"keep"}', '{"action":"hmac","domain":"tok"}'] as $act) {
                $rule = '{"headers":{"' . $h . '":' . $act . '}}';
                $what = $h . ' ' . $act;
                self::assertSame('unsafe', self::outcome(self::body('{"request":' . $rule . '}', '[]', self::SEG)), 'global request ' . $what);
                self::assertSame('unsafe', self::outcome(self::body('{"response":' . $rule . '}', '[]', self::SEG)), 'global response ' . $what);
                self::assertSame('unsafe', self::outcome(self::body('{"errors":' . $rule . '}', '[]', self::SEG)), 'global errors ' . $what);
                self::assertSame('unsafe', self::outcome(self::body('{}', '[' . self::SVC_HEAD . ',"errors":' . $rule . ',"ops":[]}]', self::SEG)), 'service errors ' . $what);
                self::assertSame('unsafe', self::outcome(self::body('{}', '[' . self::SVC_HEAD . ',"ops":[{"op":"GET /a","request":' . $rule . '}]}]', self::SEG)), 'op request ' . $what);
                self::assertSame('unsafe', self::outcome(self::body('{}', '[' . self::SVC_HEAD . ',"ops":[{"op":"GET /a","response":' . $rule . '}]}]', self::SEG)), 'op response ' . $what);
            }
        }
        self::assertSame('accepted', self::outcome(self::body('{"request":{"headers":{"authorization":{"action":"drop"}}}}', '[]', self::SEG)));
    }

    public function testH2GlobalStar(): void
    {
        $keep = '{"response":{"body":[{"path":"$.a.*","action":{"action":"keep"}}]}}';
        $hmac = '{"response":{"body":[{"path":"$.items[*].*","action":{"action":"hmac","domain":"tok"}}]}}';
        $drop = '{"response":{"body":[{"path":"$.a.*","action":{"action":"drop"}}]}}';
        self::assertSame('unsafe', self::outcome(self::body($keep, '[]', self::SEG)));
        self::assertSame('unsafe', self::outcome(self::body($hmac, '[]', self::SEG)));
        self::assertSame('accepted', self::outcome(self::body($drop, '[]', self::SEG)));
        $rule = '{"body":[{"path":"$.*","action":{"action":"keep"}}]}';
        self::assertSame('accepted', self::outcome(self::body('{}', '[' . self::SVC_HEAD . ',"request":' . $rule . ',"ops":[]}]', self::SEG)));
        self::assertSame('accepted', self::outcome(self::body('{}', '[' . self::SVC_HEAD . ',"ops":[{"op":"GET /a","response":' . $rule . '}]}]', self::SEG)));
    }

    public function testH3Windows(): void
    {
        foreach ([0 => 'accepted', 1 => 'unsafe'] as $extra => $expect) {
            $when = gmdate('Y-m-d\TH:i:s\Z', strtotime(self::CREATED) + 7 * 86400 + $extra);
            self::assertSame($expect, self::outcome(self::body('{}', '[]', self::SEG, '{"enabled":true,"expires_at":"' . $when . '"}')), 'discovery +' . $extra);
            $seg = '{"auto_words":true,"auto_words_expires_at":"' . $when . '","allow":[],"hosts_allow":[]}';
            self::assertSame($expect, self::outcome(self::body('{}', '[]', $seg)), 'auto_words +' . $extra);
        }
        self::assertSame('accepted', self::outcome(self::body('{}', '[]', self::SEG, '{"enabled":false,"expires_at":"2026-12-20T08:00:00Z"}')));
    }
}
