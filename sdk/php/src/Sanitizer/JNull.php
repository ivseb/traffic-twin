<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

final class JNull
{
    public static ?JNull $instance = null;

    public static function get(): self
    {
        return self::$instance ??= new self();
    }
}
