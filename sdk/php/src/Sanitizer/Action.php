<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/** A compiled rule action (policy.md 2). */
final class Action
{
    /**
     * @param list<array{canon: string, d: float}>|null $bounds
     */
    public function __construct(
        public string $action,
        public ?string $domain = null,
        public ?string $kind = null,
        public ?array $bounds = null,
        public ?string $unit = null,
        /** code only (sanitizer.md 5.6): 'alnum' (v1.19) or null for the v1.11 code shape. */
        public ?string $shape = null,
    ) {
    }
}
