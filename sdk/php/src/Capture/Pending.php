<?php

declare(strict_types=1);

namespace TrafficTwin\Capture;

use TrafficTwin\Sanitizer\Decision;
use TrafficTwin\Sanitizer\Exchange;
use TrafficTwin\Sanitizer\Sanitizer;

/** A finished exchange waiting to be sanitized (after the response has been sent, where the SAPI allows). */
final class Pending
{
    /**
     * @param \Closure(): Exchange $build converts to sanitizer input lazily
     */
    public function __construct(
        public Sanitizer $san,
        public Decision $decision,
        public \Closure $build,
        public string $dir,
        public int $tsMs,
        public int $latencyMs,
        public ?string $traceId,
        public ?string $spanId,
        public ?string $parentSpanId,
        public ?int $status,
        public ?string $netError,
        public int $heldBytes,
    ) {
    }
}
