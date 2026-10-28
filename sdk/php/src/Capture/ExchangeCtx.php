<?php

declare(strict_types=1);

namespace TrafficTwin\Capture;

/** Context of the inbound exchange being served (event.md 1.1, sanitizer.md 12). */
final class ExchangeCtx
{
    public function __construct(
        public bool $sampled,
        public string $traceId,
        /** true when traceId came from the request (traceparent) or from OpenTelemetry. */
        public bool $traceKnown,
        public string $spanId,
    ) {
    }
}
