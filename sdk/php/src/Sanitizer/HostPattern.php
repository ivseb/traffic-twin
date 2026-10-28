<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/**
 * Host patterns (sanitizer.md 3.1 point 5, 3.5, 3.6; spec v1.5): the IPv6 literal parser, the IPv4/IPv6
 * class tables and the label rule. Written out on purpose: no inet_pton, filter_var or ipaddress-like helpers,
 * because the forms they accept and classify differ between PHP versions and platforms.
 *
 * @internal
 */
final class HostPattern
{
    /** IPv4 private ranges (3.6): [a, b, c, d, prefix bits]. */
    private const V4_PRIVATE = [
        [0, 0, 0, 0, 8], [10, 0, 0, 0, 8], [100, 64, 0, 0, 10], [127, 0, 0, 0, 8], [169, 254, 0, 0, 16],
        [172, 16, 0, 0, 12], [192, 0, 0, 0, 24], [192, 0, 2, 0, 24], [192, 168, 0, 0, 16], [198, 18, 0, 0, 15],
        [198, 51, 100, 0, 24], [203, 0, 113, 0, 24], [224, 0, 0, 0, 4], [240, 0, 0, 0, 4],
    ];

    /** IPv6 private ranges (3.6): [leading bytes of the prefix, prefix bits]; every other byte of the prefix is 0. */
    private const V6_PRIVATE = [
        [[], 96],                                  // ::/96
        [[0x00, 0x64, 0xff, 0x9b, 0x00, 0x01], 48], // 64:ff9b:1::/48
        [[0x01, 0x00], 64],                        // 100::/64
        [[0x20, 0x01], 23],                        // 2001::/23
        [[0x20, 0x01, 0x0d, 0xb8], 32],            // 2001:db8::/32
        [[0xfc], 7],                               // fc00::/7
        [[0xfe, 0x80], 10],                        // fe80::/10
        [[0xfe, 0xc0], 10],                        // fec0::/10
        [[0xff], 8],                               // ff00::/8
    ];

    private const V4_MAPPED = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]; // ::ffff:0:0/96
    private const NAT64 = [0x00, 0x64, 0xff, 0x9b];                       // 64:ff9b::/96

    /**
     * One dotted IPv4 (6.3 `ipv4`: four 0-255 parts, no leading zeros) into 4 ints, or null.
     *
     * @return list<int>|null
     */
    public static function parseIpv4(string $s): ?array
    {
        if (preg_match('/^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$/D', $s, $m) !== 1) {
            return null;
        }
        $o = [(int) $m[1], (int) $m[2], (int) $m[3], (int) $m[4]];
        foreach ($o as $v) {
            if ($v > 255) {
                return null;
            }
        }
        return $o;
    }

    /**
     * @param list<string> $parts
     * @param list<int> $out
     */
    private static function groups(array $parts, bool $tailOk, array &$out): bool
    {
        $last = count($parts) - 1;
        foreach ($parts as $k => $g) {
            if ($tailOk && $k === $last && str_contains($g, '.')) {
                $o = self::parseIpv4($g);
                if ($o === null) {
                    return false;
                }
                $out[] = ($o[0] << 8) | $o[1];
                $out[] = ($o[2] << 8) | $o[3];
            } elseif (preg_match('/^[0-9a-f]{1,4}$/D', $g) === 1) {
                $out[] = (int) hexdec($g);
            } else {
                return false;
            }
        }
        return true;
    }

    /**
     * Parses the (lowercase) text between the brackets: 1-4 hex digit groups, at most one `::` standing for at least
     * one zero group (so at most 7 written groups with it, exactly 8 without), an optional IPv4 tail as the last
     * element, no zone. Returns the 16 bytes as a list of ints, or null.
     *
     * @return list<int>|null
     */
    public static function parseIpv6(string $s): ?array
    {
        $first = strpos($s, '::');
        if ($first !== false && strpos($s, '::', $first + 2) !== false) {
            return null;
        }
        $g = [];
        if ($first !== false) {
            $left = substr($s, 0, $first);
            $right = substr($s, $first + 2);
            $a = [];
            $b = [];
            if (!self::groups($left === '' ? [] : explode(':', $left), false, $a)) {
                return null;
            }
            if (!self::groups($right === '' ? [] : explode(':', $right), true, $b)) {
                return null;
            }
            if (count($a) + count($b) > 7) {
                return null;
            }
            $g = array_merge($a, array_fill(0, 8 - count($a) - count($b), 0), $b);
        } else {
            if (!self::groups(explode(':', $s), true, $g) || count($g) !== 8) {
                return null;
            }
        }
        $out = [];
        foreach ($g as $x) {
            $out[] = $x >> 8;
            $out[] = $x & 0xff;
        }
        return $out;
    }

    /**
     * @param list<int> $addr
     * @param list<int> $prefix leading bytes, the rest is 0
     */
    private static function inPrefix(array $addr, array $prefix, int $bits): bool
    {
        for ($i = 0; $i < $bits; $i++) {
            $p = ($prefix[intdiv($i, 8)] ?? 0);
            if ((($addr[intdiv($i, 8)] >> (7 - $i % 8)) & 1) !== (($p >> (7 - $i % 8)) & 1)) {
                return false;
            }
        }
        return true;
    }

    /** @param list<int> $a4 */
    public static function ipv4Private(array $a4): bool
    {
        foreach (self::V4_PRIVATE as $r) {
            if (self::inPrefix($a4, [$r[0], $r[1], $r[2], $r[3]], $r[4])) {
                return true;
            }
        }
        return false;
    }

    /** @param list<int> $a16 */
    public static function ipv6Private(array $a16): bool
    {
        // The two ranges with an embedded IPv4 come first (3.6): the class is the one of the last 32 bits.
        if (self::inPrefix($a16, self::V4_MAPPED, 96) || self::inPrefix($a16, self::NAT64, 96)) {
            return self::ipv4Private(array_slice($a16, 12, 4));
        }
        foreach (self::V6_PRIVATE as [$prefix, $bits]) {
            if (self::inPrefix($a16, $prefix, $bits)) {
                return true;
            }
        }
        return false;
    }

    /** Rules a-d of 3.5 (d is implied by c for a string that passes a, but is evaluated anyway). */
    public static function labelSafe(string $label): bool
    {
        return preg_match('/^[a-z][a-z0-9-]{0,62}$/D', $label) === 1
            && preg_match('/[0-9]{6}/', $label) !== 1
            && preg_match('/[0-9a-f]{12}/', $label) !== 1
            && Formats::detect($label) === null;
    }

    /**
     * The pattern of a valid host ($host lowercase, possibly with one final dot; $port without leading zeros, or ''
     * when absent or default; $ip6 the 16 bytes of a bracketed literal, else null), or null when a label is empty
     * (service `host:invalid`).
     *
     * @param list<int>|null $ip6
     */
    public static function pattern(string $host, string $port, ?array $ip6): ?string
    {
        $suffix = $port === '' ? '' : ':' . $port;
        if ($ip6 !== null) {
            return 'ip:' . (self::ipv6Private($ip6) ? 'private' : 'public') . $suffix;
        }
        $h = str_ends_with($host, '.') ? substr($host, 0, -1) : $host;
        $labels = explode('.', $h);
        foreach ($labels as $l) {
            if ($l === '') {
                return null;
            }
        }
        $v4 = self::parseIpv4($h);
        if ($v4 !== null) {
            return 'ip:' . (self::ipv4Private($v4) ? 'private' : 'public') . $suffix;
        }
        $out = [];
        foreach ($labels as $l) {
            $out[] = self::labelSafe($l) ? $l : '{*}';
        }
        return implode('.', $out) . $suffix;
    }
}
