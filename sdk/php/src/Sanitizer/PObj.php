<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/** A JSON object inside a plain (policy or vector) document; distinguishes {} from []. */
final class PObj
{
    /** @param array<string, mixed> $m */
    public function __construct(public array $m = [])
    {
    }
}
