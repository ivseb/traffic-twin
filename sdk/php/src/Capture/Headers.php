<?php

declare(strict_types=1);

namespace TrafficTwin\Capture;

/**
 * Raw-header access for PHP (sanitizer.md 8.0).
 *
 * PHP never shows the application the exact bytes a client sent. Two strategies, in order:
 *
 * 1. PSR-7 / framework header bags: the names and the separate values the factory kept. When
 *    a PSR-7 request was built from the globals, that factory already used getallheaders().
 * 2. Globals: `getallheaders()` (Apache, FPM and FrankenPHP provide it) and, where it does not
 *    exist (CLI server, some FastCGI setups), `$_SERVER`.
 *
 * Both are lossy in ways the spec calls out: the web server may already have merged repeated
 * headers with ", " (equivalent to 8.0 point 4) and, with FastCGI, `$_SERVER` carries
 * `HTTP_X_FOO_BAR`, so names are rebuilt as `x-foo-bar` (an underscore in the original name
 * becomes a dash; nginx drops such headers by default anyway). Pseudo-headers never reach PHP.
 * `Authorization` is missing from `$_SERVER` under Apache/CGI unless the server passes it
 * (`SetEnvIf Authorization ... HTTP_AUTHORIZATION`, `fastcgi_param HTTP_AUTHORIZATION`), so a
 * subject taken from that header needs that configuration. These are limits of the source and
 * only ever drop information; they never open data.
 */
final class Headers
{
    /**
     * @param array<string, mixed>|null $server defaults to $_SERVER
     * @return list<array{0: string, 1: string}>
     */
    public static function fromGlobals(?array $server = null): array
    {
        if ($server === null && function_exists('getallheaders')) {
            $all = getallheaders();
            if (is_array($all)) {
                $out = [];
                foreach ($all as $k => $v) {
                    $out[] = [(string) $k, (string) $v];
                }
                return $out;
            }
        }
        $server ??= $_SERVER;
        $out = [];
        foreach ($server as $k => $v) {
            if (!is_string($k) || !is_scalar($v)) {
                continue;
            }
            if (str_starts_with($k, 'HTTP_')) {
                $out[] = [strtolower(str_replace('_', '-', substr($k, 5))), (string) $v];
            } elseif ($k === 'CONTENT_TYPE' && $v !== '') {
                $out[] = ['content-type', (string) $v];
            } elseif ($k === 'CONTENT_LENGTH' && $v !== '') {
                $out[] = ['content-length', (string) $v];
            }
        }
        return $out;
    }

    /**
     * PSR-7 style header map (name => list of values; also a plain string value).
     *
     * @param array<array-key, mixed> $headers
     * @return list<array{0: string, 1: string}>
     */
    public static function fromMap(array $headers): array
    {
        $out = [];
        foreach ($headers as $name => $values) {
            foreach (is_array($values) ? $values : [$values] as $v) {
                if (is_scalar($v)) {
                    $out[] = [(string) $name, (string) $v];
                }
            }
        }
        return $out;
    }

    /**
     * Request headers of a Symfony / Laravel request bag (`$request->headers->all()`): the headers the
     * client sent, without the ones the framework adds to the bag itself. Symfony's HttpKernel::handle()
     * always sets `X-Php-Ob-Level` (the output-buffer level, for its error renderer) and overwrites any
     * client value, so it is never part of the request on the wire.
     *
     * @param array<array-key, mixed> $all
     * @return list<array{0: string, 1: string}>
     */
    public static function fromRequestBag(array $all): array
    {
        $out = [];
        foreach (self::fromMap($all) as $p) {
            if (strtolower($p[0]) !== 'x-php-ob-level') {
                $out[] = $p;
            }
        }
        return $out;
    }

    /**
     * Response headers of a Symfony / Laravel response (`ResponseHeaderBag`), each Set-Cookie once.
     * `allPreserveCase()` already carries the cookies as Set-Cookie strings in current Symfony
     * (all() appends `getCookies()`), older bags kept them out: the cookies of `getCookies()` are
     * added only when their exact string is not there yet. Order and multiplicity of distinct
     * cookies are kept; a cookie string present twice in the bag itself is kept as many times.
     *
     * @return list<array{0: string, 1: string}>
     */
    public static function fromResponseBag(object $headers): array
    {
        $out = self::fromMap($headers->allPreserveCase());
        if (!method_exists($headers, 'getCookies')) {
            return $out;
        }
        $have = [];
        foreach ($out as $p) {
            if (strtolower($p[0]) === 'set-cookie') {
                $have[$p[1]] = ($have[$p[1]] ?? 0) + 1;
            }
        }
        foreach ($headers->getCookies() as $c) {
            $v = (string) $c;
            if (($have[$v] ?? 0) > 0) {
                $have[$v]--;
                continue;
            }
            $out[] = ['set-cookie', $v];
        }
        return $out;
    }

    /**
     * @param list<array{0: string, 1: string}> $pairs
     * @param array<string, true> $names lowercase names to keep
     * @return list<array{0: string, 1: string}>
     */
    public static function only(array $pairs, array $names): array
    {
        $out = [];
        foreach ($pairs as $p) {
            if (isset($names[strtolower($p[0])])) {
                $out[] = $p;
            }
        }
        return $out;
    }

    /** First value of a header (case-insensitive) from pairs, or null. @param list<array{0: string, 1: string}> $pairs */
    public static function first(array $pairs, string $lower): ?string
    {
        foreach ($pairs as [$n, $v]) {
            if (strtolower($n) === $lower) {
                return $v;
            }
        }
        return null;
    }
}
