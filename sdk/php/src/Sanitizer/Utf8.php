<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/**
 * Byte-string helpers (sanitizer.md 0.2, 4.1, 8.0). PHP strings are byte strings, so
 * "UTF-8 valid" is checked explicitly (PCRE /u is strict RFC 3629: no overlong forms,
 * no encoded surrogates, nothing above U+10FFFF) and case folding is ASCII-only and
 * locale independent.
 */
final class Utf8
{
    private const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    private const LOWER = 'abcdefghijklmnopqrstuvwxyz';

    public static function valid(string $s): bool
    {
        return $s === '' || preg_match('//u', $s) === 1;
    }

    /** The string itself when it is valid UTF-8, else null. */
    public static function decode(string $b): ?string
    {
        return $b === '' || preg_match('//u', $b) === 1 ? $b : null;
    }

    public static function lower(string $s): string
    {
        return strtr($s, self::UPPER, self::LOWER);
    }

    public static function upper(string $s): string
    {
        return strtr($s, self::LOWER, self::UPPER);
    }

    /** Strips space and horizontal tab on both sides. */
    public static function trimOws(string $s): string
    {
        return trim($s, " \t");
    }

    /** Percent-decoding of 4.1 ("+" untouched) or, with $plus, of 8.3 ("+" becomes a space first). */
    public static function pctDecode(string $b, bool $plus): string
    {
        if (!str_contains($b, '%') && (!$plus || !str_contains($b, '+'))) {
            return $b;
        }
        // urldecode maps "+" to a space and leaves a "%" not followed by two hex digits literal;
        // "%2B" stays "+" because both substitutions happen in one pass.
        return $plus ? urldecode($b) : rawurldecode($b);
    }

    public static function lenClass(int $n): string
    {
        if ($n <= 8) {
            return 'l8';
        }
        if ($n <= 32) {
            return 'l32';
        }
        if ($n <= 128) {
            return 'l128';
        }
        return $n <= 1024 ? 'l1024' : 'lmax';
    }

    /** UTF-8 encoding of a code point; surrogates get their 3-byte (WTF-8) form. */
    public static function fromCodePoint(int $cp): string
    {
        if ($cp < 0x80) {
            return chr($cp);
        }
        if ($cp < 0x800) {
            return chr(0xC0 | ($cp >> 6)) . chr(0x80 | ($cp & 0x3F));
        }
        if ($cp < 0x10000) {
            return chr(0xE0 | ($cp >> 12)) . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
        }
        return chr(0xF0 | ($cp >> 18)) . chr(0x80 | (($cp >> 12) & 0x3F)) . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
    }

    /** Strict base64url without padding (A-Z a-z 0-9 - _); null on any other character or impossible length. */
    public static function b64urlDecode(string $s): ?string
    {
        if (preg_match('/^[A-Za-z0-9_-]*$/D', $s) !== 1 || strlen($s) % 4 === 1) {
            return null;
        }
        $pad = (4 - strlen($s) % 4) % 4;
        $r = base64_decode(strtr($s, '-_', '+/') . str_repeat('=', $pad), true);
        return $r === false ? null : $r;
    }

    public static function b64url(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }
}
