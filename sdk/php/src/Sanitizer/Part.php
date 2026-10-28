<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/** Rules of one part of one scope (operation, service, errors, global). */
final class Part
{
    /**
     * @param array<string, Action> $query
     * @param array<string, Action> $headers
     * @param array<string, Action> $cookies
     * @param array<string, Action> $path
     * @param list<BodyRule> $body
     */
    public function __construct(
        public array $query = [],
        public array $headers = [],
        public array $cookies = [],
        public array $path = [],
        public array $body = [],
    ) {
    }
}
