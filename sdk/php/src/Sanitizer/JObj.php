<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/** JSON object node: ordered members as [JStr key, node] pairs, duplicates kept. */
final class JObj
{
    /** @var list<array{0: JStr, 1: object}> */
    public array $m = [];
}
