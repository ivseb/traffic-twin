<?php

declare(strict_types=1);

namespace TrafficTwin\Tests\Unit;

use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\TestCase;
use TrafficTwin\Capture\Context;
use TrafficTwin\Integration\Psr15Middleware;
use TrafficTwin\Runtime;
use TrafficTwin\Tests\Support\CallbackHandler;
use TrafficTwin\Tests\Support\Fixture;

final class Psr15Test extends TestCase
{
    private string $emitted = '';

    private function fixture(array $policy = []): Fixture
    {
        return (new Fixture())->write(Fixture::policy($policy + [
            'services' => [[
                'name' => 'shop-api',
                'match' => ['inbound' => true, 'internal' => false],
                'ops' => [
                    ['op' => 'POST /orders', 'response' => ['body' => [
                        ['path' => '$.id', 'action' => ['action' => 'hmac', 'domain' => 'order']],
                        ['path' => '$.status', 'action' => ['action' => 'keep']],
                        ['path' => '$.total', 'action' => ['action' => 'bucket', 'kind' => 'num', 'bounds' => [0, 50, 100, 250]]],
                    ]]],
                    ['op' => 'GET /orders/{orderId}', 'request' => ['path' => ['orderId' => ['action' => 'hmac', 'domain' => 'order']]]],
                ],
            ]],
        ]));
    }

    private function exec(Fixture $f, ServerRequest $req, \Closure $handler, ?\Closure $resolver = null): array
    {
        $rt = $f->runtime();
        Runtime::set($rt);
        $mw = new Psr15Middleware($rt, $resolver);
        $resp = $mw->process($req, new CallbackHandler($handler));
        // The emitter sends the response before the deferred sanitization runs.
        $this->emitted = (string) $resp->getBody();
        $rt->processPending();
        return [$resp, $f->events()];
    }

    protected function tearDown(): void
    {
        Runtime::set(null);
        Context::leave();
    }

    public function testCapturesAnExchangeWithoutChangingIt(): void
    {
        $f = $this->fixture();
        $reqBody = '{"items":[{"sku":"TSHIRT-RED-M","qty":2}],"email":"giulia.neri@example.com"}';
        $req = (new ServerRequest('POST', 'http://shop.example/orders?promo=AUTUMN10', [
            'Content-Type' => 'application/json',
            'Cookie' => 'sid=9f8e7d6c5b4a',
            'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjLTEwMDQyIn0.c2ln',
        ], $reqBody))->withBody(Utils::streamFor($reqBody));
        $seen = null;
        [$resp, $events] = $this->exec($f, $req, function ($r) use (&$seen) {
            $seen = (string) $r->getBody();
            return new Response(201, ['Content-Type' => 'application/json; charset=utf-8', 'Set-Cookie' => 'sid=9f8e7d6c5b4a; Path=/; HttpOnly'], '{"id":"ORD-2026-000184","status":"CREATED","total":73.40}');
        });
        self::assertSame($reqBody, $seen, 'the app sees the body unchanged');
        self::assertSame('{"id":"ORD-2026-000184","status":"CREATED","total":73.40}', $this->emitted);
        self::assertCount(1, $events);
        $e = $events[0];
        self::assertSame('POST /orders', $e['op']);
        self::assertSame('policy', $e['route_source']);
        self::assertSame('inbound', $e['dir']);
        self::assertSame('shop-api', $e['service']);
        self::assertSame(201, $e['status']);
        self::assertSame('num:50-100', $e['resp']['body']['total']);
        self::assertSame('keep:CREATED', $e['resp']['body']['status']);
        self::assertMatchesRegularExpression('/^tk1:k1:[A-Za-z0-9_-]{22}$/', $e['resp']['body']['id']);
        self::assertSame('drop:str:email', $e['req']['body']['email']);
        self::assertSame('tt.http.exchange/v1', $e['schema']);
        self::assertSame('sdk-php', $e['source']['kind']);
        self::assertSame('src-test0001', $e['source']['id']);
        self::assertMatchesRegularExpression('/^tk1:k1:/', $e['subject'] ?? 'tk1:k1:x'); // no subject configured: absent
        $text = $f->spoolText();
        foreach (['giulia', 'TSHIRT', '9f8e7d6c5b4a', 'ORD-2026', 'AUTUMN10', 'c-10042'] as $raw) {
            self::assertStringNotContainsString($raw, $text, "raw value $raw must never reach the spool");
        }
    }

    public function testNonSeekableBodiesAreTeedAndPassThroughUnchanged(): void
    {
        $f = $this->fixture();
        $gen = static function (): \Generator {
            yield '{"a":';
            yield '1}';
        };
        $req = (new ServerRequest('POST', 'http://shop.example/orders', ['Content-Type' => 'application/json']))
            ->withBody(Utils::streamFor((static function () {
                yield '{"x":';
                yield '"abc"}';
            })()));
        $got = '';
        [$resp, $events] = $this->exec($f, $req, function ($r) use (&$got, $gen) {
            $body = $r->getBody();
            while (!$body->eof()) {
                $got .= $body->read(3);
            }
            return new Response(200, ['Content-Type' => 'application/json'], Utils::streamFor($gen()));
        });
        self::assertSame('{"x":"abc"}', $got);
        // The emitter reads the response through the decorator.
        self::assertSame('{"a":1}', $this->emitted);
        $f2 = $f->events();
        self::assertSame('drop:str:l8', $f2[0]['req']['body']['x']);
        self::assertSame('drop:int', $f2[0]['resp']['body']['a'] ?? null);
    }

    public function testImmediateModeDoesNotWaitForStreamingResponses(): void
    {
        $f = $this->fixture();
        $rt = $f->runtime();
        $rt->deferMode = 'now';
        $resp = (new Psr15Middleware($rt))->process(
            new ServerRequest('GET', 'http://shop.example/orders/1'),
            new CallbackHandler(static fn () => new Response(200, ['Content-Type' => 'application/json'], Utils::streamFor((static function () {
                yield '{"a":1}';
            })()))),
        );
        self::assertSame('{"a":1}', (string) $resp->getBody(), 'the body is not decorated and passes through');
        $e = $f->events();
        self::assertCount(1, $e);
        self::assertSame('trunc:size', $e[0]['resp']['body']);
    }

    public function testUnreadRequestBodyIsReportedAsTruncated(): void
    {
        $f = $this->fixture();
        $req = (new ServerRequest('POST', 'http://shop.example/orders', ['Content-Type' => 'application/json']))
            ->withBody(Utils::streamFor((static function () {
                yield '{"secret":"value"}';
            })()));
        [, $events] = $this->exec($f, $req, static fn () => new Response(204));
        self::assertSame('trunc:size', $events[0]['req']['body']);
        self::assertSame('lmax', $events[0]['req']['size']);
        self::assertStringNotContainsString('secret', $f->spoolText());
    }

    public function testCompressedBodiesAreDecodedByTheSanitizer(): void
    {
        $f = $this->fixture();
        $req = (new ServerRequest('POST', 'http://shop.example/orders', ['Content-Type' => 'application/json', 'Content-Encoding' => 'gzip']))
            ->withBody(Utils::streamFor((string) gzencode('{"status":"CREATED","id":"ORD-1"}')));
        $read = static function ($r) {
            (string) $r->getBody(); // the app reads its body
            return new Response(200, ['Content-Type' => 'application/json', 'Content-Encoding' => 'deflate'], (string) gzcompress('{"id":"ORD-2","total":10}'));
        };
        [, $events] = $this->exec($f, $req, $read);
        self::assertSame('drop:str:l8', $events[0]['req']['body']['status']);
        self::assertSame('l128', $events[0]['req']['size']);
        self::assertSame('num:0-50', $events[0]['resp']['body']['total']);
        $f2 = $this->fixture();
        [, $events] = $this->exec($f2, (new ServerRequest('POST', 'http://shop.example/orders', ['Content-Type' => 'application/json', 'Content-Encoding' => 'br']))->withBody(Utils::streamFor('xxxx')), static function ($r) {
            (string) $r->getBody();
            return new Response(200);
        });
        self::assertSame('drop:bytes', $events[0]['req']['body']);
        self::assertArrayNotHasKey('size', $events[0]['req']);
        $f3 = $this->fixture();
        $gz = (string) gzencode(str_repeat('{"a":1}', 10));
        [, $events] = $this->exec($f3, (new ServerRequest('POST', 'http://shop.example/orders', ['Content-Type' => 'application/json', 'Content-Encoding' => 'gzip']))->withBody(Utils::streamFor(substr($gz, 0, -5))), static function ($r) {
            (string) $r->getBody();
            return new Response(200);
        });
        self::assertSame('drop:bytes', $events[0]['req']['body'], 'a truncated stream is an error (A-GZIP-STRICT)');
    }

    public function testBodiesOverTheLimitAreNotAnalyzed(): void
    {
        $f = $this->fixture(['limits' => ['max_body_bytes' => 1024, 'max_depth' => 32, 'max_array' => 32, 'max_keys' => 256, 'keep_max_bytes' => 64]]);
        $big = '{"note":"' . str_repeat('x', 5000) . '"}';
        [, $events] = $this->exec($f, (new ServerRequest('POST', 'http://shop.example/orders', ['Content-Type' => 'application/json']))->withBody(Utils::streamFor($big)), static function ($r) {
            (string) $r->getBody();
            return new Response(200);
        });
        self::assertSame('trunc:size', $events[0]['req']['body']);
        self::assertSame('lmax', $events[0]['req']['size']);
        self::assertStringNotContainsString('xxxxxxxx', $f->spoolText());
    }

    public function testNoBodyResponsesAndHead(): void
    {
        $f = $this->fixture();
        [, $events] = $this->exec($f, new ServerRequest('HEAD', 'http://shop.example/orders/7'), static fn () => new Response(200, ['Content-Type' => 'application/json'], '{"id":"x"}'));
        self::assertArrayNotHasKey('body', $events[0]['resp']);
        self::assertSame('l8', $events[0]['resp']['size']);
    }

    public function testFrameworkRouteUsesTheResolver(): void
    {
        $f = $this->fixture();
        [, $events] = $this->exec(
            $f,
            new ServerRequest('GET', 'http://shop.example/orders/ORD-1'),
            static fn () => new Response(200),
            static fn () => ['laravel', '/orders/{id}'],
        );
        self::assertSame('framework', $events[0]['route_source']);
        self::assertSame('GET /orders/{orderId}', $events[0]['op']);
        self::assertMatchesRegularExpression('#^/orders/\{tk1:k1:#', $events[0]['req']['path']);
    }

    public function testAResolverThatCannotProvideTheRouteFallsBackToThePolicy(): void
    {
        $f = $this->fixture();
        [, $events] = $this->exec(
            $f,
            new ServerRequest('GET', 'http://shop.example/orders/ORD-1'),
            static fn () => new Response(200),
            static fn () => ['laravel', '/orders/{id?}'],
        );
        self::assertSame('policy', $events[0]['route_source']);
    }

    public function testResolverFailureNeverBreaksTheRequest(): void
    {
        $f = $this->fixture();
        [$resp, $events] = $this->exec(
            $f,
            new ServerRequest('GET', 'http://shop.example/orders/ORD-1'),
            static fn () => new Response(200),
            static function (): array {
                throw new \RuntimeException('boom');
            },
        );
        self::assertSame(200, $resp->getStatusCode());
        self::assertSame('policy', $events[0]['route_source']);
    }

    public function testHandlerExceptionPropagatesAndLeavesNoContext(): void
    {
        $f = $this->fixture();
        $rt = $f->runtime();
        $mw = new Psr15Middleware($rt);
        try {
            $mw->process(new ServerRequest('GET', 'http://shop.example/orders/1'), new CallbackHandler(static function () {
                throw new \DomainException('app error');
            }));
            self::fail('expected exception');
        } catch (\DomainException) {
        }
        self::assertNull(Context::current());
        $rt->processPending();
        self::assertSame([], $f->events());
    }

    public function testGateClosedMeansAPurePassThrough(): void
    {
        $f = new Fixture(); // no state at all
        $rt = $f->runtime();
        $called = false;
        $resp = (new Psr15Middleware($rt))->process(new ServerRequest('GET', 'http://shop.example/x'), new CallbackHandler(function () use (&$called) {
            $called = true;
            return new Response(200, [], 'ok');
        }));
        self::assertTrue($called);
        self::assertSame('ok', (string) $resp->getBody());
        self::assertSame([], $f->events());
    }

    public function testNotSampledExchangesProduceNothingButSetTheContext(): void
    {
        $f = new Fixture();
        $f->write(Fixture::policy(['sampling' => ['rate_bp' => 0, 'trust_baggage' => false, 'propagate_to' => []]]));
        $rt = $f->runtime();
        $inside = null;
        (new Psr15Middleware($rt))->process(new ServerRequest('GET', 'http://shop.example/x'), new CallbackHandler(function () use (&$inside) {
            $inside = Context::current();
            return new Response(200);
        }));
        self::assertNotNull($inside);
        self::assertFalse($inside->sampled);
        self::assertNull(Context::current());
        $rt->processPending();
        self::assertSame([], $f->events());
    }

    public function testTraceparentIsReadAndNeverInjected(): void
    {
        $f = $this->fixture();
        $tp = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
        $seenHeaders = null;
        [$resp, $events] = $this->exec($f, new ServerRequest('GET', 'http://shop.example/orders/1', ['traceparent' => $tp]), function ($r) use (&$seenHeaders) {
            $seenHeaders = $r->getHeaders();
            return new Response(200);
        });
        self::assertSame('4bf92f3577b34da6a3ce929d0e0e4736', $events[0]['trace_id']);
        self::assertSame('00f067aa0ba902b7', $events[0]['parent_span_id']);
        $names = array_keys($seenHeaders);
        sort($names);
        self::assertSame(['Host', 'traceparent'], $names, 'no header added to the request');
        self::assertSame([$tp], $seenHeaders['traceparent']);
        self::assertSame([], $resp->getHeaders(), 'no header added to the response');
    }

    public function testSubjectDecidesSamplingForAllCallsOfTheSameUser(): void
    {
        $f = new Fixture();
        $f->write(Fixture::policy([
            'identity' => ['subject' => ['from' => 'header', 'name' => 'authorization', 'jwt_claim' => 'sub']],
            'sampling' => ['rate_bp' => 5000, 'trust_baggage' => false, 'propagate_to' => []],
        ]));
        $rt = $f->runtime();
        $payload = static fn (string $sub): string => 'Bearer h.' . rtrim(strtr(base64_encode('{"sub":"' . $sub . '"}'), '+/', '-_'), '=') . '.s';
        $decide = function (string $sub) use ($rt, $payload): bool {
            $sampled = null;
            (new Psr15Middleware($rt))->process(
                new ServerRequest('GET', 'http://shop.example/x', ['Authorization' => $payload($sub)]),
                new CallbackHandler(function () use (&$sampled) {
                    $sampled = Context::current()?->sampled;
                    return new Response(200);
                }),
            );
            return (bool) $sampled;
        };
        $in = $out = 0;
        for ($i = 0; $i < 200; $i++) {
            $first = $decide("c-$i");
            self::assertSame($first, $decide("c-$i"), 'stable per subject');
            $first ? $in++ : $out++;
        }
        self::assertGreaterThan(60, $in);
        self::assertGreaterThan(60, $out);
    }

    public function testQueueLimitDropsAndCounts(): void
    {
        $f = $this->fixture();
        $rt = $f->runtime();
        $rt->deferMode = 'shutdown';
        $rt->finishRequest = false;
        $mw = new Psr15Middleware($rt);
        for ($i = 0; $i < 2005; $i++) {
            $mw->process(new ServerRequest('GET', 'http://shop.example/orders/1'), new CallbackHandler(static fn () => new Response(200)));
        }
        self::assertSame(5, $rt->counters->eventsDroppedQueue);
        $rt->processPending();
        self::assertCount(2000, $f->events());
    }
}
