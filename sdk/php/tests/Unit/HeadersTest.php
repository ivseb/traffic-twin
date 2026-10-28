<?php

declare(strict_types=1);

namespace TrafficTwin\Tests\Unit;

use PHPUnit\Framework\TestCase;
use TrafficTwin\Capture\Headers;
use TrafficTwin\Sanitizer\Run;

final class HeadersTest extends TestCase
{
    public function testServerVariablesAreRebuiltIntoHeaderNames(): void
    {
        $h = Headers::fromGlobals([
            'HTTP_HOST' => 'shop.example',
            'HTTP_X_REQUEST_ID' => 'abc',
            'HTTP_AUTHORIZATION' => 'Bearer x',
            'CONTENT_TYPE' => 'application/json',
            'CONTENT_LENGTH' => '12',
            'REQUEST_METHOD' => 'POST',
            'SERVER_NAME' => 'internal',
            'argv' => ['x'],
        ]);
        self::assertSame([['host', 'shop.example'], ['x-request-id', 'abc'], ['authorization', 'Bearer x'], ['content-type', 'application/json'], ['content-length', '12']], $h);
    }

    public function testMergedUnderscoreAndDashNamesAreNormalizedLikeTheSpecSays(): void
    {
        // $_SERVER cannot tell X-Foo-Bar from X_Foo_Bar: both become x-foo-bar and, after 8.0
        // normalization, one value joined with ", " in order of arrival.
        [$order, $map] = Run::normalizeHeaders([['x-foo-bar', '1'], ['X-FOO-BAR', ' 2 '], [':authority', 'x'], ['Cookie', 'a=1'], ['cookie', 'b=2']]);
        self::assertSame(['x-foo-bar', 'cookie'], $order);
        self::assertSame(['1', '2'], $map['x-foo-bar']['values']);
        self::assertSame(['a=1', 'b=2'], $map['cookie']['values']);
    }

    public function testPsr7StyleMaps(): void
    {
        self::assertSame([['Set-Cookie', 'a=1'], ['Set-Cookie', 'b=2'], ['Content-Type', 'text/plain']], Headers::fromMap(['Set-Cookie' => ['a=1', 'b=2'], 'Content-Type' => ['text/plain']]));
    }

    public function testRequestBagWithoutTheHeaderSymfonyAddsItself(): void
    {
        // HttpKernel::handle() sets X-Php-Ob-Level on every request and overwrites a client value.
        $bag = ['host' => ['shop.example'], 'x-php-ob-level' => ['1'], 'x-foo' => ['a', 'b']];
        self::assertSame([['host', 'shop.example'], ['x-foo', 'a'], ['x-foo', 'b']], Headers::fromRequestBag($bag));
    }

    public function testResponseBagListsEachSetCookieOnceInOrder(): void
    {
        $h = new \Symfony\Component\HttpFoundation\ResponseHeaderBag(['Content-Type' => 'text/plain']);
        $h->setCookie(\Symfony\Component\HttpFoundation\Cookie::create('a', '1'));
        $h->setCookie(\Symfony\Component\HttpFoundation\Cookie::create('b', '2'));
        $h->setCookie(\Symfony\Component\HttpFoundation\Cookie::create('a', '3', 0, '/x'));
        $sc = array_values(array_filter(Headers::fromResponseBag($h), static fn (array $p): bool => strtolower($p[0]) === 'set-cookie'));
        self::assertCount(3, $sc);
        self::assertStringStartsWith('a=1', $sc[0][1]);
        self::assertStringStartsWith('b=2', $sc[1][1]);
        self::assertStringStartsWith('a=3', $sc[2][1]);
        self::assertContains('Content-Type', array_column(Headers::fromResponseBag($h), 0));
    }

    public function testResponseBagThatKeepsCookiesOutOfItsHeaderMapStillGetsThem(): void
    {
        // Older bags: allPreserveCase() has no Set-Cookie, getCookies() has the objects.
        $bag = new class () {
            public function allPreserveCase(): array
            {
                return ['Content-Type' => ['text/plain']];
            }

            public function getCookies(): array
            {
                return ['a=1; path=/', 'b=2; path=/'];
            }
        };
        self::assertSame([['Content-Type', 'text/plain'], ['set-cookie', 'a=1; path=/'], ['set-cookie', 'b=2; path=/']], Headers::fromResponseBag($bag));
    }
}
