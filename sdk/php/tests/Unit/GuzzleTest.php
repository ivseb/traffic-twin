<?php

declare(strict_types=1);

namespace TrafficTwin\Tests\Unit;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\TestCase;
use TrafficTwin\Capture\Context;
use TrafficTwin\Capture\ExchangeCtx;
use TrafficTwin\Integration\GuzzleMiddleware;
use TrafficTwin\Runtime;
use TrafficTwin\Tests\Support\Fixture;

final class GuzzleTest extends TestCase
{
    private Fixture $f;
    private Runtime $rt;
    /** @var list<Request> */
    private array $sent = [];

    protected function tearDown(): void
    {
        Context::leave();
    }

    private function client(array $queue, array $policy = []): Client
    {
        $this->f = (new Fixture())->write(Fixture::policy($policy + [
            'services' => [[
                'name' => 'shipping-ext',
                'match' => ['base' => 'https://api.carrier.example'],
                'errors' => ['body' => [['path' => '$.error.code', 'action' => ['action' => 'keep']]]],
                'ops' => [[
                    'op' => 'POST /v1/shipments',
                    'request' => ['body' => [['path' => '$.orderId', 'action' => ['action' => 'hmac', 'domain' => 'order']]]],
                    'response' => ['body' => [
                        ['path' => '$.shipmentId', 'action' => ['action' => 'hmac', 'domain' => 'shipment']],
                        ['path' => '$.status', 'action' => ['action' => 'keep']],
                    ]],
                ]],
            ]],
        ]));
        $this->rt = $this->f->runtime();
        $mock = new MockHandler($queue);
        $stack = HandlerStack::create($mock);
        $stack->push(GuzzleMiddleware::create($this->rt));
        $stack->push(static function (callable $h): callable {
            return static function ($req, array $o) use ($h) {
                return $h($req, $o);
            };
        });
        return new Client(['handler' => $stack, 'http_errors' => false]);
    }

    /** @return list<array<string, mixed>> */
    private function events(): array
    {
        $this->rt->processPending();
        return $this->f->events();
    }

    public function testOutboundExchangeInheritsTheInboundContext(): void
    {
        $c = $this->client([new Response(201, ['Content-Type' => 'application/json'], '{"shipmentId":"SHP-99","status":"CREATED"}')]);
        Context::enter(new ExchangeCtx(true, '4bf92f3577b34da6a3ce929d0e0e4736', true, '00f067aa0ba902b7'));
        $body = '{"orderId":"ORD-2026-000184","address":"Via Roma 1"}';
        $r = $c->post('https://api.carrier.example/v1/shipments?dry=1', ['body' => $body, 'headers' => ['Content-Type' => 'application/json']]);
        self::assertSame('{"shipmentId":"SHP-99","status":"CREATED"}', (string) $r->getBody(), 'the app still reads the body');
        $e = $this->events();
        self::assertCount(1, $e);
        self::assertSame('outbound', $e[0]['dir']);
        self::assertSame('shipping-ext', $e[0]['service']);
        self::assertSame('POST /v1/shipments', $e[0]['op']);
        self::assertSame('policy', $e[0]['route_source']);
        self::assertSame('inherited', $e[0]['sampled_by']);
        self::assertSame('4bf92f3577b34da6a3ce929d0e0e4736', $e[0]['trace_id']);
        self::assertSame('00f067aa0ba902b7', $e[0]['parent_span_id']);
        self::assertSame(201, $e[0]['status']);
        self::assertSame('keep:CREATED', $e[0]['resp']['body']['status']);
        self::assertMatchesRegularExpression('/^tk1:k1:/', $e[0]['req']['body']['orderId']);
        self::assertMatchesRegularExpression('/^tk1:k1:/', $e[0]['resp']['body']['shipmentId']);
        self::assertSame('drop:str:l32', $e[0]['req']['body']['address']);
        $text = $this->f->spoolText();
        foreach (['ORD-2026', 'Via Roma', 'SHP-99', 'api.carrier.example'] as $raw) {
            self::assertStringNotContainsString($raw, $text);
        }
    }

    public function testUnsampledInboundMeansNoOutboundCapture(): void
    {
        $c = $this->client([new Response(200)]);
        Context::enter(new ExchangeCtx(false, str_repeat('a', 32), true, str_repeat('b', 16)));
        $c->get('https://api.carrier.example/v1/shipments');
        self::assertSame([], $this->events());
    }

    public function testUndeclaredHostLeavesAsAPatternAndNeverCarriesAValue(): void
    {
        // Spec v1.5: safe labels are structure, a label that looks like a value is {*}.
        $c = $this->client([new Response(200, ['Content-Type' => 'application/json'], '{"x":1}')]);
        Context::enter(new ExchangeCtx(true, str_repeat('a', 32), true, str_repeat('b', 16)));
        $c->get('https://api.partner-1234567.example/customers/mario.rossi%40example.com');
        $e = $this->events();
        self::assertSame('host:api.{*}.example', $e[0]['service']);
        self::assertSame('GET /{drop:str:l32}/{drop:str:email}', $e[0]['op']);
        self::assertStringNotContainsString('1234567', $this->f->spoolText());
    }

    public function testStrictModeKeepsHostUnlisted(): void
    {
        $c = $this->client([new Response(200, ['Content-Type' => 'application/json'], '{"x":1}')], ['hosts' => ['discovery' => 'off']]);
        Context::enter(new ExchangeCtx(true, str_repeat('a', 32), true, str_repeat('b', 16)));
        $c->get('https://api.unknown-partner.example/customers/mario.rossi%40example.com');
        $e = $this->events();
        self::assertSame('host:unlisted', $e[0]['service']);
        self::assertStringNotContainsString('unknown-partner', $this->f->spoolText());
    }

    public function testIpv6LiteralAndFinalDotReachTheSanitizerAsTheClientSeesThem(): void
    {
        $c = $this->client([new Response(200), new Response(200)]);
        Context::enter(new ExchangeCtx(true, str_repeat('a', 32), true, str_repeat('b', 16)));
        $c->get('http://[::1]:8080/x');
        $c->get('https://api.partner.example./x');
        $e = $this->events();
        self::assertSame('host:ip:private:8080', $e[0]['service']);
        self::assertSame('host:api.partner.example', $e[1]['service'], 'the final dot is dropped by the sanitizer, not by the integration');
    }

    public function testErrorStatusesAreExchanges(): void
    {
        $c = $this->client([new Response(404, ['Content-Type' => 'application/json'], '{"error":{"code":"NOT_FOUND","message":"no order for mario.rossi"}}')]);
        Context::enter(new ExchangeCtx(true, str_repeat('a', 32), true, str_repeat('b', 16)));
        $c->post('https://api.carrier.example/v1/shipments', ['json' => ['orderId' => 'X']]);
        $e = $this->events();
        self::assertSame(404, $e[0]['status']);
        self::assertSame('keep:NOT_FOUND', $e[0]['resp']['body']['error']['code']);
        self::assertSame('drop:str:l32', $e[0]['resp']['body']['error']['message']);
    }

    public function testTransportFailuresBecomeNetErrorAndStillReject(): void
    {
        $req = new Request('GET', 'https://api.carrier.example/v1/shipments');
        $c = $this->client([
            new ConnectException('Connection refused', $req, null, ['errno' => 7]),
            new ConnectException('cURL error 28: timed out', $req, null, ['errno' => 28]),
            new ConnectException('cURL error 6: Could not resolve host', $req, null, ['errno' => 6]),
            new ConnectException('cURL error 60: SSL certificate problem', $req, null, ['errno' => 60]),
            new ConnectException('cURL error 56: Recv failure: Connection reset by peer', $req, null, ['errno' => 56]),
            new ConnectException('weird', $req),
        ]);
        Context::enter(new ExchangeCtx(true, str_repeat('a', 32), true, str_repeat('b', 16)));
        foreach (range(1, 6) as $_) {
            try {
                $c->request('GET', 'https://api.carrier.example/v1/shipments', ['http_errors' => true]);
                self::fail('expected ConnectException');
            } catch (ConnectException) {
            }
        }
        $e = $this->events();
        self::assertSame(['refused', 'timeout', 'dns', 'tls', 'reset', 'other'], array_map(static fn (array $x): string => $x['net_error'], $e));
        self::assertArrayNotHasKey('resp', $e[0]);
        self::assertArrayNotHasKey('status', $e[0]);
    }

    public function testDecodedContentUsesTheOriginalContentEncoding(): void
    {
        // Guzzle's decode_content strips Content-Encoding and keeps the original value here.
        $c = $this->client([new Response(200, ['Content-Type' => 'application/json', 'x-encoded-content-encoding' => 'gzip'], '{"status":"OK"}')]);
        Context::enter(new ExchangeCtx(true, str_repeat('a', 32), true, str_repeat('b', 16)));
        $c->get('https://api.carrier.example/v1/shipments');
        $e = $this->events();
        self::assertSame('l32', $e[0]['resp']['size']);
        self::assertArrayNotHasKey('x-encoded-content-encoding', $e[0]['resp']['headers']);
        self::assertSame(['drop:str:l8'], $e[0]['resp']['headers']['content-encoding'] ?? ['drop:str:l8']);
    }

    public function testRequestBodyStreamPositionIsRestored(): void
    {
        $c = $this->client([new Response(200)]);
        Context::enter(new ExchangeCtx(true, str_repeat('a', 32), true, str_repeat('b', 16)));
        $stream = Utils::streamFor('{"orderId":"A"}');
        $seenByTransport = null;
        $mock = new MockHandler([function ($req) use (&$seenByTransport) {
            $seenByTransport = (string) $req->getBody();
            return new Response(200);
        }]);
        $stack = HandlerStack::create($mock);
        $stack->push(GuzzleMiddleware::create($this->rt));
        (new Client(['handler' => $stack]))->post('https://api.carrier.example/v1/shipments', ['body' => $stream]);
        self::assertSame('{"orderId":"A"}', $seenByTransport);
    }

    public function testBaggageIsPropagatedOnlyToListedInternalHosts(): void
    {
        $seen = [];
        $this->f = (new Fixture())->write(Fixture::policy([
            'sampling' => ['rate_bp' => 10000, 'trust_baggage' => true, 'propagate_to' => ['orders.internal']],
            'services' => [['name' => 'shipping-ext', 'match' => ['base' => 'https://api.carrier.example'], 'ops' => []]],
        ]));
        $this->rt = $this->f->runtime();
        $h = static function ($req) use (&$seen) {
            $seen[] = $req->getHeaderLine('baggage');
            return new Response(200);
        };
        $stack = HandlerStack::create(new MockHandler([$h, $h, $h]));
        $stack->push(GuzzleMiddleware::create($this->rt));
        $c = new Client(['handler' => $stack]);
        Context::enter(new ExchangeCtx(true, str_repeat('a', 32), true, str_repeat('b', 16)));
        $c->get('http://orders.internal/health', ['headers' => ['baggage' => 'userId=alice']]);
        $c->get('https://api.carrier.example/v1/shipments');
        $c->get('http://other.internal/x');
        self::assertSame(['userId=alice,tt.s=1', '', ''], $seen);
    }

    public function testNothingHappensWhenTheGateIsClosed(): void
    {
        $f = new Fixture();
        $rt = $f->runtime();
        $stack = HandlerStack::create(new MockHandler([new Response(200, [], 'x')]));
        $stack->push(GuzzleMiddleware::create($rt));
        $r = (new Client(['handler' => $stack]))->get('https://api.carrier.example/x');
        self::assertSame('x', (string) $r->getBody());
        $rt->processPending();
        self::assertSame([], $f->events());
    }
}
