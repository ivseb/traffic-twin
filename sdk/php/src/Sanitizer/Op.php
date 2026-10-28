<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/** One operation of a service: METHOD /template. Template segments are [literal|null, param|null]. */
final class Op
{
    /** @param list<array{0: ?string, 1: ?string}> $segs */
    public function __construct(
        public string $key,
        public string $method,
        public array $segs,
        public int $literals,
        public ?Part $request,
        public ?Part $response,
    ) {
    }
}
