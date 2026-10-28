<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

final class Service
{
    /** @var list<Op> */
    public array $ops = [];
    public ?array $base = null; // [origin, list<segment>]
    public ?Part $request = null;
    public ?Part $response = null;
    public ?Part $errors = null;

    public function __construct(public string $name, public bool $inbound, public bool $internal)
    {
    }
}
