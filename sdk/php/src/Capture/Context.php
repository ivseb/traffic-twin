<?php

declare(strict_types=1);

namespace TrafficTwin\Capture;

/**
 * Exchange context (event.md 1.1, sanitizer.md 12, ARCHITECTURE 3.2).
 *
 * PHP runs one request per process (or per worker loop iteration), so the context of the
 * inbound exchange being served is a plain static: outbound calls made while it is set share
 * its trace id and inherit its sampling decision. Coroutine runtimes (Swoole, OpenSwoole,
 * AMPHP fibers served concurrently) interleave requests in one process and are not supported
 * by this static: use the explicit `inherited` option of the Guzzle middleware there.
 *
 * W3C `traceparent` is read from the inbound request. If the application uses OpenTelemetry
 * for PHP, the active span context is only READ through the API classes when they are already
 * loaded by the app; this class never registers a tracer provider, propagator, context storage
 * or global, and never injects `traceparent`.
 */
final class Context
{
    private static ?ExchangeCtx $current = null;
    private static ?bool $otelPresent = null;

    public static function current(): ?ExchangeCtx
    {
        return self::$current;
    }

    public static function enter(ExchangeCtx $c): void
    {
        self::$current = $c;
    }

    public static function leave(): void
    {
        self::$current = null;
    }

    public static function newTraceId(): string
    {
        return self::nonZeroHex(16);
    }

    public static function newSpanId(): string
    {
        return self::nonZeroHex(8);
    }

    private static function nonZeroHex(int $bytes): string
    {
        for (;;) {
            $h = bin2hex(random_bytes($bytes));
            if (trim($h, '0') !== '') {
                return $h;
            }
        }
    }

    /** W3C trace context: ids from a traceparent value, or null if invalid. @return array{traceId: string, spanId: string}|null */
    public static function parseTraceparent(?string $v): ?array
    {
        if ($v === null || preg_match('/^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})(-.*)?$/D', trim($v), $m) !== 1) {
            return null;
        }
        if ($m[1] === 'ff' || ($m[1] === '00' && ($m[5] ?? '') !== '')) {
            return null;
        }
        if (trim($m[2], '0') === '' || trim($m[3], '0') === '') {
            return null;
        }
        return ['traceId' => $m[2], 'spanId' => $m[3]];
    }

    /**
     * Active OpenTelemetry span context, if the app has the OpenTelemetry API loaded and a valid
     * span is current. Read-only; never throws. @return array{traceId: string, spanId: string}|null
     */
    public static function otelActive(): ?array
    {
        $span = 'OpenTelemetry\\API\\Trace\\Span';
        // Loading the API class has no side effect (it registers nothing); the answer is cached.
        self::$otelPresent ??= class_exists($span);
        if (!self::$otelPresent) {
            return null;
        }
        try {
            $sc = $span::getCurrent()->getContext();
            if (!$sc->isValid()) {
                return null;
            }
            $t = $sc->getTraceId();
            $s = $sc->getSpanId();
            if (preg_match('/^[0-9a-f]{32}$/D', $t) !== 1 || trim($t, '0') === '') {
                return null;
            }
            return ['traceId' => $t, 'spanId' => preg_match('/^[0-9a-f]{16}$/D', $s) === 1 ? $s : ''];
        } catch (\Throwable) {
            return null;
        }
    }

    /** Adds tt.s to a baggage header value without touching the other members. */
    public static function withTtS(?string $existing, bool $sampled): string
    {
        $member = 'tt.s=' . ($sampled ? '1' : '0');
        if ($existing === null || trim($existing) === '') {
            return $member;
        }
        return $existing . ',' . $member;
    }
}
