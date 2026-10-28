<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/** Output object (tt-cjson object): keys are sorted when written. */
final class Obj
{
    /** @param array<string, mixed> $m */
    public function __construct(public array $m = [])
    {
    }
}
