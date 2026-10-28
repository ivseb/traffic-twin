<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/**
 * Shapes (6.2), recognized formats (6.3) and the name rule (9.3.3).
 *
 * Every regular expression is a whole-string, ASCII-only match (0.1): the `D` modifier makes
 * `$` match only at the very end (so "x\n" never matches) and no `u` flag is used.
 */
final class Formats
{
    private const FORMATS = [
        'uuid' => '/^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/D',
        'jwt' => '/^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/D',
        'email' => '/^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$/D',
        'datetime' => '/^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt ][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?([Zz]|[+-][0-9]{2}:[0-9]{2})$/D',
        'date' => '/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/D',
        'url' => '/^[A-Za-z][A-Za-z0-9+.-]{0,15}:\/\/[!-~]+$/D',
        'ipv4' => '/^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$/D',
        'phone' => '/^\+[1-9][0-9]{6,14}$/D',
        'digits' => '/^-?[0-9]{1,19}$/D',
        'hex' => '/^[0-9A-Fa-f]{16,}$/D',
    ];

    public const RE_DATETIME = self::FORMATS['datetime'];
    public const RE_DATE = self::FORMATS['date'];
    public const PATH_TOKEN = '/^[A-Za-z0-9._~-]{1,64}$/D';
    /** Code shape of the code action (sanitizer.md 5.6, spec v1.11). */
    public const CODE = '/^[A-Za-z_-]{2,32}$/D';
    /** Shape alnum of the code action (sanitizer.md 5.6, spec v1.19). */
    public const CODE_ALNUM = '/^[A-Za-z0-9_.-]{1,16}$/D';
    public const AUTO_WORD = '/^([a-z]+([-_][a-z]+)*|v[0-9]{1,3})$/D';

    private const KEY = '/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/D';
    private const HEADER_NAME = '/^[a-z0-9!#$%&\'*+.^_`|~-]{1,64}$/D';

    public static function isPrintableAscii(string $s): bool
    {
        return preg_match('/^[\x20-\x7e]*$/D', $s) === 1;
    }

    /** First matching format of 6.3, or null. Only printable ASCII strings are considered. */
    public static function detect(string $s): ?string
    {
        if (!self::isPrintableAscii($s)) {
            return null;
        }
        foreach (self::FORMATS as $name => $re) {
            if (preg_match($re, $s) === 1) {
                return $name;
            }
        }
        return null;
    }

    /** drop form of a valid UTF-8 string. */
    public static function strShape(string $s): string
    {
        $f = self::detect($s);
        return $f !== null ? 'drop:str:' . $f : 'drop:str:' . Utf8::lenClass(strlen($s));
    }

    private static function looksLikeValue(string $s): bool
    {
        return preg_match(self::FORMATS['uuid'], $s) === 1
            || preg_match(self::FORMATS['email'], $s) === 1
            || preg_match(self::FORMATS['hex'], $s) === 1
            || preg_match(self::FORMATS['digits'], $s) === 1
            || preg_match(self::FORMATS['jwt'], $s) === 1
            || preg_match('/[0-9]{6}/', $s) === 1;
    }

    /** 9.3.3: a JSON key, query, cookie or form name leaves as a literal only if this holds. */
    public static function isLiteralName(string $s): bool
    {
        return preg_match(self::KEY, $s) === 1 && !self::looksLikeValue($s);
    }

    /** 8.0.2: output name of a lowercased header name. */
    public static function headerOutName(string $lower): string
    {
        if (preg_match(self::HEADER_NAME, $lower) !== 1 || self::looksLikeValue($lower)) {
            return '{*}';
        }
        return $lower;
    }
}
