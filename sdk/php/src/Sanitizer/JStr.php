<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/** JSON string node; $bad marks a lone surrogate escape (kept as its 3-byte form). */
final class JStr
{
    public function __construct(public string $s, public bool $bad = false)
    {
    }
}
