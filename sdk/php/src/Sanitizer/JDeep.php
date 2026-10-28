<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/**
 * Placeholder for a container nested deeper than the parser's depth limit. The document is still
 * validated to the end (9.2), but the structure is not built: a 1 MiB body of `[[[[...` would
 * otherwise become a million nested objects, and PHP frees nested values recursively.
 */
final class JDeep
{
    private static ?JDeep $instance = null;

    public static function get(): self
    {
        return self::$instance ??= new self();
    }
}
