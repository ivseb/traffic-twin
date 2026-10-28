<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/** Sampling decision (sanitizer.md 12): $by is baggage, subject, trace, random or inherited. */
final class Decision
{
    public function __construct(public readonly bool $sampled, public readonly string $by)
    {
    }
}
