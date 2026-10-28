<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/** A number already in canonical form (10.2), ready to be written. */
final class CNum
{
    public function __construct(public string $canon)
    {
    }
}
