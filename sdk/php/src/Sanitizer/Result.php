<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/**
 * Outcome of Sanitizer::run(): 'event', 'not_sampled', or 'too_large' (10.3 step 4: no event;
 * the source counts it in `sanitizer_errors`).
 */
final class Result
{
    /**
     * @param array<string, string> $parts top-level members, already serialized
     */
    public function __construct(
        public readonly string $outcome,
        public readonly string $sampledBy,
        public readonly string $canonical = '',
        public readonly array $parts = [],
    ) {
    }
}
