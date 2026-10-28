<?php

declare(strict_types=1);

namespace TrafficTwin\Capture;

/** Maps a transport failure to the event enum (event.md): timeout, reset, refused, dns, tls, other. */
final class NetError
{
    public static function fromThrowable(\Throwable $e): string
    {
        // Guzzle: ConnectException/RequestException carry the cURL handler context.
        $ctx = method_exists($e, 'getHandlerContext') ? $e->getHandlerContext() : [];
        $errno = is_array($ctx) && isset($ctx['errno']) ? (int) $ctx['errno'] : 0;
        if ($errno !== 0) {
            return self::fromCurl($errno);
        }
        $m = strtolower($e->getMessage());
        if (str_contains($m, 'timed out') || str_contains($m, 'timeout')) {
            return 'timeout';
        }
        if (str_contains($m, 'refused')) {
            return 'refused';
        }
        if (str_contains($m, 'resolve') || str_contains($m, 'getaddrinfo') || str_contains($m, 'name or service not known')) {
            return 'dns';
        }
        if (str_contains($m, 'ssl') || str_contains($m, 'tls') || str_contains($m, 'certificate')) {
            return 'tls';
        }
        if (str_contains($m, 'reset') || str_contains($m, 'broken pipe')) {
            return 'reset';
        }
        return 'other';
    }

    public static function fromCurl(int $errno): string
    {
        return match (true) {
            $errno === 28 => 'timeout',
            $errno === 7 => 'refused',
            $errno === 6 || $errno === 5 => 'dns',
            in_array($errno, [35, 51, 53, 54, 58, 59, 60, 64, 66, 77, 80, 82, 83, 90, 91], true) => 'tls',
            $errno === 52 || $errno === 55 || $errno === 56 => 'reset',
            default => 'other',
        };
    }
}
