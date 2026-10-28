<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/** One element of an XML body (sanitizer.md 22.2): local name, namespace, attributes, children, direct text. */
final class XmlElem
{
    /** @var list<XmlElem> */
    public array $children = [];
    public string $text = '';

    /** @param list<array{0: string, 1: string}> $attrs (local name, value), namespace declarations excluded */
    public function __construct(public string $local, public string $ns, public array $attrs)
    {
    }
}
