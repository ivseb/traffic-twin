<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/** A JSON number inside a plain (policy) document: the lexeme, never a float. */
final class Lex
{
    public function __construct(public string $lex)
    {
    }

    public function int(): int
    {
        return (int) $this->lex;
    }

    public function isInt(): bool
    {
        return preg_match("/^-?(0|[1-9][0-9]*)\$/D", $this->lex) === 1;
    }
}
