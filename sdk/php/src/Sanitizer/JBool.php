<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

final class JBool
{
    public static ?JBool $true = null;
    public static ?JBool $false = null;

    private function __construct(public bool $v)
    {
    }

    public static function of(bool $v): self
    {
        return $v ? (self::$true ??= new self(true)) : (self::$false ??= new self(false));
    }
}
