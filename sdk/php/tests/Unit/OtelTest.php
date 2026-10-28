<?php

declare(strict_types=1);

namespace TrafficTwin\Tests\Unit;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use OpenTelemetry\API\Globals;
use OpenTelemetry\API\Trace\NoopTracerProvider;
use OpenTelemetry\API\Trace\Span;
use OpenTelemetry\API\Trace\SpanContext;
use OpenTelemetry\API\Trace\TraceFlags;
use PHPUnit\Framework\TestCase;
use TrafficTwin\Capture\Context;
use TrafficTwin\Integration\GuzzleMiddleware;
use TrafficTwin\Integration\Psr15Middleware;
use TrafficTwin\Tests\Support\CallbackHandler;
use TrafficTwin\Tests\Support\Fixture;

/** ARCHITECTURE 3.2: read the OpenTelemetry context if present, never register or change anything. */
final class OtelTest extends TestCase
{
    protected function setUp(): void
    {
        if (!class_exists(Span::class)) {
            self::markTestSkipped('open-telemetry/api not installed');
        }
    }

    public function testTraceIdComesFromTheActiveSpanAndNothingIsRegistered(): void
    {
        $providerBefore = Globals::tracerProvider();
        $propagatorBefore = Globals::propagator();
        $sc = SpanContext::create('4bf92f3577b34da6a3ce929d0e0e4736', '00f067aa0ba902b7', TraceFlags::SAMPLED);
        $scope = Span::wrap($sc)->activate();
        try {
            $f = (new Fixture())->write();
            $rt = $f->runtime();
            $stack = HandlerStack::create(new MockHandler([new Response(200)]));
            $stack->push(GuzzleMiddleware::create($rt));
            $client = new Client(['handler' => $stack]);
            (new Psr15Middleware($rt))->process(new ServerRequest('GET', 'http://shop.example/orders/1'), new CallbackHandler(static function () use ($client) {
                $client->get('https://api.carrier.example/v1/shipments');
                return new Response(200);
            }));
            $rt->processPending();
            $events = $f->events();
            self::assertCount(2, $events);
            foreach ($events as $e) {
                self::assertSame('4bf92f3577b34da6a3ce929d0e0e4736', $e['trace_id']);
            }
            // The active span is the app's: still there, untouched.
            self::assertSame('00f067aa0ba902b7', Span::getCurrent()->getContext()->getSpanId());
        } finally {
            $scope->detach();
        }
        self::assertSame($providerBefore, Globals::tracerProvider());
        self::assertSame($propagatorBefore, Globals::propagator());
        self::assertInstanceOf(NoopTracerProvider::class, Globals::tracerProvider(), 'no TracerProvider was registered');
        self::assertNull(Context::current());
    }

    public function testTraceparentWinsOverNothingAndIsNeverInjected(): void
    {
        $f = (new Fixture())->write();
        $rt = $f->runtime();
        $seen = [];
        $stack = HandlerStack::create(new MockHandler([static function ($req) use (&$seen) {
            $seen = $req->getHeaders();
            return new Response(200);
        }]));
        $stack->push(GuzzleMiddleware::create($rt));
        $client = new Client(['handler' => $stack]);
        (new Psr15Middleware($rt))->process(
            new ServerRequest('GET', 'http://shop.example/x', ['traceparent' => '00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01']),
            new CallbackHandler(static function () use ($client) {
                $client->get('https://api.carrier.example/y');
                return new Response(200);
            }),
        );
        self::assertArrayNotHasKey('traceparent', $seen, 'tt does not change the traffic of the app');
        self::assertArrayNotHasKey('baggage', $seen);
        $rt->processPending();
        self::assertSame('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', $f->events()[0]['trace_id']);
    }

    public function testNoSourceFileTouchesOpenTelemetryGlobals(): void
    {
        $bad = ['Globals::', 'registerInitializer', 'setLogger', 'Configurator', 'Context::storage', '->attach(', 'TracerProvider', 'ContextStorage'];
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(__DIR__ . '/../../src'));
        foreach ($it as $file) {
            if (!$file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }
            $code = (string) file_get_contents($file->getPathname());
            foreach ($bad as $needle) {
                self::assertStringNotContainsString($needle, $code, $file->getPathname() . ' must not use ' . $needle);
            }
        }
    }
}
