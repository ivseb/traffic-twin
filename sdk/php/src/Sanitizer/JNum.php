<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/** JSON number node: the lexeme is kept as written. */
final class JNum
{
    public function __construct(public string $lex)
    {
    }
}
