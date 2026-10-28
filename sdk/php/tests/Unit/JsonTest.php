<?php

declare(strict_types=1);

namespace TrafficTwin\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use TrafficTwin\Sanitizer\JArr;
use TrafficTwin\Sanitizer\JNum;
use TrafficTwin\Sanitizer\JObj;
use TrafficTwin\Sanitizer\Json;
use TrafficTwin\Sanitizer\JsonError;

final class JsonTest extends TestCase
{
    public function testKeepsNumberLexemes(): void
    {
        $n = Json::parse('[1.50, 15e-1, 1E3, -0.0, 123456789012345678901234567890]');
        self::assertInstanceOf(JArr::class, $n);
        self::assertSame(['1.50', '15e-1', '1E3', '-0.0', '123456789012345678901234567890'], array_map(static fn (JNum $x): string => $x->lex, $n->a));
    }

    /** @return iterable<string, array{string, string}> */
    public static function canonical(): iterable
    {
        yield '1.50' => ['1.50', '1.5'];
        yield '15e-1' => ['15e-1', '1.5'];
        yield '-0.0' => ['-0.0', '0'];
        yield '1E3' => ['1E3', '1000'];
        yield '73.40' => ['73.40', '73.4'];
        yield '0.0015' => ['0.0015', '0.0015'];
        yield '1e21' => ['1e21', '1e+21'];
        yield '1e-7' => ['1.5e-7', '1.5e-7'];
        yield 'big' => ['123456789012345678901234567890', '1.2345678901234567890123456789e+29'];
        yield '1e20' => ['1e20', '100000000000000000000'];
    }

    #[DataProvider('canonical')]
    public function testCanonicalNumbers(string $lex, string $expected): void
    {
        self::assertSame($expected, Json::canonicalNumber($lex));
    }

    /** @return iterable<string, array{string}> */
    public static function invalid(): iterable
    {
        yield 'trailing comma' => ['[1,]'];
        yield 'comment' => ['[1] // x'];
        yield 'NaN' => ['NaN'];
        yield 'two values' => ['1 2'];
        yield 'bom' => ["\xEF\xBB\xBF{}"];
        yield 'bad utf8' => ["[\"\xC3\x28\"]"];
        yield 'overlong' => ["[\"\xC0\xAF\"]"];
        yield 'encoded surrogate' => ["[\"\xED\xA0\x80\"]"];
        yield 'control char' => ["[\"a\x01b\"]"];
        yield 'leading zero' => ['[01]'];
        yield 'single quote' => ["{'a':1}"];
        yield 'unterminated' => ['{"a":'];
        yield 'bad escape' => ['["\\x"]'];
        yield 'empty' => [''];
    }

    #[DataProvider('invalid')]
    public function testRejectsNonRfc8259(string $doc): void
    {
        $this->expectException(JsonError::class);
        Json::parse($doc);
    }

    public function testDeepNestingIsValidatedWithoutRecursion(): void
    {
        // A 1 MiB body of "[[[[..." must be validated to the end but never built as nested values.
        $depth = 500000;
        $doc = str_repeat('[', $depth) . str_repeat(']', $depth);
        $root = Json::parse($doc, 32);
        self::assertInstanceOf(JArr::class, $root);
        $this->expectException(JsonError::class);
        Json::parse(str_repeat('[', $depth) . str_repeat(']', $depth - 1), 32);
    }

    public function testLoneSurrogateIsFlagged(): void
    {
        $o = Json::parse('{"a\\ud800":"x\\udc00y","b":"\\ud83d\\ude00"}');
        self::assertInstanceOf(JObj::class, $o);
        self::assertTrue($o->m[0][0]->bad);
        self::assertTrue($o->m[0][1]->bad);
        self::assertFalse($o->m[1][1]->bad);
        self::assertSame("\u{1F600}", $o->m[1][1]->s);
    }

    public function testWriterEscapesAsSpecified(): void
    {
        self::assertSame('"a\\u0001\\u007f\\u00e9\\ud83d\\ude00\\"\\\\/"', Json::write("a\x01\x7f\u{e9}\u{1F600}\"\\/"));
    }
}
