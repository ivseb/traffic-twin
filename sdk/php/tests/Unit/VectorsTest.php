<?php

declare(strict_types=1);

namespace TrafficTwin\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use TrafficTwin\Sanitizer\VectorRunner;

/** Every conformance vector, byte for byte (sanitizer.md 16, conformance/README.md). */
final class VectorsTest extends TestCase
{
    private const ROOT = __DIR__ . '/../../../../conformance';

    /** @return iterable<string, array{string}> */
    public static function vectors(): iterable
    {
        $files = glob(self::ROOT . '/vectors/*.json') ?: [];
        sort($files);
        foreach ($files as $f) {
            yield basename($f, '.json') => [$f];
        }
    }

    public function testSuiteIsComplete(): void
    {
        self::assertGreaterThanOrEqual(756, count(glob(self::ROOT . '/vectors/*.json') ?: []));
    }

    #[DataProvider('vectors')]
    public function testVector(string $file): void
    {
        $vec = VectorRunner::parse((string) file_get_contents($file));
        $exp = $vec->m['expected']->m;
        $got = VectorRunner::run($vec, self::ROOT);
        self::assertSame($exp['outcome'], $got['outcome'], basename($file));
        if ($exp['outcome'] === 'event') {
            self::assertSame($exp['canonical'], $got['canonical'], basename($file));
        } elseif ($exp['outcome'] === 'not_sampled') {
            self::assertSame($exp['sampled_by'], $got['sampled_by']);
        } else {
            self::assertSame($exp['code'], $got['code']);
        }
    }
}
