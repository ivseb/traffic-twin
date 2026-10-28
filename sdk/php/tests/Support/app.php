<?php

declare(strict_types=1);

/**
 * A tiny PSR-15 application for the built-in server (cli-server SAPI), instrumented with the
 * SDK: an e-commerce order API that calls a carrier (second built-in server) through Guzzle.
 * Configuration comes from the environment (TT_STATE_DIR, TT_HMAC_KEY, TT_TEST_CARRIER_PORT).
 */

use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use Psr\Http\Message\ServerRequestInterface;
use TrafficTwin\Integration\GuzzleMiddleware;
use TrafficTwin\Integration\Psr15Middleware;
use TrafficTwin\Tests\Support\CallbackHandler;

require __DIR__ . '/../../vendor/autoload.php';

$stack = HandlerStack::create();
$stack->push(GuzzleMiddleware::create());
$carrier = new Client(['handler' => $stack, 'http_errors' => false, 'timeout' => 5]);

$app = new CallbackHandler(static function (ServerRequestInterface $r) use ($carrier): Response {
    $path = $r->getUri()->getPath();
    if ($r->getMethod() === 'POST' && $path === '/api/v1/orders') {
        $order = json_decode((string) $r->getBody(), true) ?: [];
        $res = $carrier->post('http://127.0.0.1:' . getenv('TT_TEST_CARRIER_PORT') . '/v1/shipments', [
            'json' => ['orderId' => 'ORD-2026-000184', 'address' => 'Via Roma 1, Milano', 'note' => $order['note'] ?? ''],
        ]);
        $ship = json_decode((string) $res->getBody(), true) ?: [];
        return new Response(201, ['Content-Type' => 'application/json; charset=utf-8', 'Set-Cookie' => 'sid=9f8e7d6c5b4a; Path=/; HttpOnly'], json_encode(['id' => 'ORD-2026-000184', 'status' => 'CREATED', 'total' => 73.40, 'shipmentId' => $ship['shipmentId'] ?? null]));
    }
    if ($r->getMethod() === 'GET' && preg_match('#^/api/v1/orders/([A-Za-z0-9-]+)$#', $path, $m) === 1) {
        return new Response(200, ['Content-Type' => 'application/json'], json_encode(['id' => $m[1], 'status' => 'SHIPPED']));
    }
    return new Response(404, ['Content-Type' => 'application/json'], '{"error":{"code":"NOT_FOUND"}}');
});

$resp = (new Psr15Middleware())->process(ServerRequest::fromGlobals(), $app);
http_response_code($resp->getStatusCode());
foreach ($resp->getHeaders() as $name => $values) {
    foreach ($values as $v) {
        header($name . ': ' . $v, false);
    }
}
echo $resp->getBody();
