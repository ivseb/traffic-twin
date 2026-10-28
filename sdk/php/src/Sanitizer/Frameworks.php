<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/**
 * framework_route normalization (sanitizer.md 3.4 with A-FRAMEWORK-ID, normative since 1.1.1):
 * the route is rewritten with the table of the named framework. Every segment must be a
 * parameter syntax of that framework or a literal of the operation-key grammar; anything
 * else (every "not normalizable" case of the table) makes the normalization fail.
 */
final class Frameworks
{
    public const ALL = [
        'express' => true, 'koa' => true, 'fastify' => true, 'flask' => true, 'fastapi' => true,
        'django' => true, 'spring' => true, 'jaxrs' => true, 'aspnetcore' => true, 'gin' => true,
        'chi' => true, 'nethttp' => true, 'laravel' => true, 'symfony' => true,
    ];

    private const COLON = '/^:([A-Za-z_][A-Za-z0-9_]{0,63})$/D';
    private const COLON_REGEX = '/^:([A-Za-z_][A-Za-z0-9_]{0,63})\((.*)\)$/Ds';
    private const ANGLE = '/^<(?:([A-Za-z_][A-Za-z0-9_]*):)?([A-Za-z_][A-Za-z0-9_]{0,63})>$/D';
    private const BRACE = '/^\{([A-Za-z_][A-Za-z0-9_]{0,63})\}$/D';
    private const BRACE_CONV = '/^\{([A-Za-z_][A-Za-z0-9_]{0,63}):(.+)\}$/Ds';
    private const BRACE_SYMFONY = '/^\{([A-Za-z_][A-Za-z0-9_]{0,63})<(.+)>\}$/Ds';
    private const PNAME = '/^[A-Za-z_][A-Za-z0-9_]{0,63}$/D';

    /**
     * @return list<array{0: ?string, 1: ?string}>|null segments as [literal, param], or null when not normalizable
     */
    public static function normalize(string $route, string $framework): ?array
    {
        if (!isset(self::ALL[$framework])) {
            return null;
        }
        $raw = array_values(array_filter(explode('/', $route), static fn (string $s): bool => $s !== ''));
        $out = [];
        $n = count($raw);
        foreach ($raw as $i => $s) {
            if ($framework === 'nethttp' && $s === '{$}' && $i === $n - 1) {
                continue; // exact-match marker
            }
            $p = self::param($framework, $s);
            if ($p !== null) {
                $out[] = [null, $p];
            } elseif (preg_match(Formats::PATH_TOKEN, $s) === 1) {
                $out[] = [$s, null];
            } else {
                return null;
            }
        }
        return count($out) > 32 ? null : $out;
    }

    private static function param(string $fw, string $s): ?string
    {
        switch ($fw) {
            case 'express':
            case 'koa':
            case 'fastify':
                if (preg_match(self::COLON, $s, $m) === 1) {
                    return $m[1];
                }
                // ":name(regex)"; a regex holding another ":param" means several parameters.
                if (preg_match(self::COLON_REGEX, $s, $m) === 1 && preg_match('/:[A-Za-z_]/', preg_replace('/\\\\./s', '', $m[2]) ?? '') !== 1) {
                    return $m[1];
                }
                return null;
            case 'gin':
                return preg_match(self::COLON, $s, $m) === 1 ? $m[1] : null;
            case 'flask':
            case 'django':
                return preg_match(self::ANGLE, $s, $m) === 1 && ($m[1] ?? '') !== 'path' ? $m[2] : null;
            case 'fastapi':
                if (preg_match(self::BRACE, $s, $m) === 1) {
                    return $m[1];
                }
                return preg_match(self::BRACE_CONV, $s, $m) === 1 && $m[2] !== 'path' ? $m[1] : null;
            case 'spring':
            case 'chi':
                if (preg_match(self::BRACE, $s, $m) === 1) {
                    return $m[1];
                }
                return preg_match(self::BRACE_CONV, $s, $m) === 1 ? $m[1] : null;
            case 'jaxrs':
                // "{ name : regex }": spaces around the name and the colon are ignored.
                if ($s === '' || $s[0] !== '{' || $s[strlen($s) - 1] !== '}') {
                    return null;
                }
                $inner = substr($s, 1, -1);
                $c = strpos($inner, ':');
                $name = trim($c === false ? $inner : substr($inner, 0, $c), " \t\n\r\f\v");
                if (preg_match(self::PNAME, $name) !== 1) {
                    return null;
                }
                if ($c !== false && trim(substr($inner, $c + 1), " \t\n\r\f\v") === '') {
                    return null;
                }
                return $name;
            case 'aspnetcore':
                if (preg_match(self::BRACE, $s, $m) === 1) {
                    return $m[1];
                }
                // "{name:constraint[:constraint...]}"; "?" marks an optional parameter, "=" a default.
                if (preg_match(self::BRACE_CONV, $s, $m) === 1 && !str_ends_with($m[2], '?') && !str_contains($m[2], '=')) {
                    return $m[1];
                }
                return null;
            case 'nethttp':
            case 'laravel':
                return preg_match(self::BRACE, $s, $m) === 1 ? $m[1] : null;
            case 'symfony':
                if (preg_match(self::BRACE, $s, $m) === 1) {
                    return $m[1];
                }
                return preg_match(self::BRACE_SYMFONY, $s, $m) === 1 ? $m[1] : null;
            default:
                return null;
        }
    }
}
