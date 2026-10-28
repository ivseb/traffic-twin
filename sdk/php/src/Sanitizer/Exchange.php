<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/**
 * Normalized exchange (sanitizer.md 1). Strings are raw bytes. Headers are lists of
 * [name, value] pairs in the order the source saw them, duplicates included; normalization
 * (8.0) is the sanitizer's job.
 */
final class Exchange
{
    public string $dir = 'inbound';
    public ?string $serviceName = null;
    public ?string $urlBase = null;
    public string $method = '';
    public string $rawPath = '';
    /** null = the URL had no "?". */
    public ?string $rawQuery = null;
    /** A-FRAMEWORK-ID: identifier of the 3.4 table; required with frameworkRoute. */
    public ?string $framework = null;
    public ?string $frameworkRoute = null;
    public ?string $traceId = null;
    public ?bool $inherited = null;
    /** @var list<array{0: string, 1: string}> */
    public array $reqHeaders = [];
    public string $reqBody = '';
    /** @var int|'unknown'|null */
    public int|string|null $reqBodyTotal = null;
    public ?bool $reqBodyConsumed = null;
    public ?bool $reqBodyDecoded = null;
    public ?int $status = null;
    public ?string $netError = null;
    /** @var list<array{0: string, 1: string}> */
    public array $respHeaders = [];
    public string $respBody = '';
    /** @var int|'unknown'|null */
    public int|string|null $respBodyTotal = null;
    public ?bool $respBodyConsumed = null;
    public ?bool $respBodyDecoded = null;
}
