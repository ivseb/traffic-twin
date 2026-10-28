<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/** A tt-path rule on a body. Steps are [type, name]: type 0 = .name, 1 = .*, 2 = [*]. */
final class BodyRule
{
    public const NAME = 0;
    public const ANY = 1;
    public const IDX = 2;

    /** @param list<array{0: int, 1: string}> $steps */
    public function __construct(
        public string $path,
        public array $steps,
        public int $names,
        public Action $action,
    ) {
    }
}
