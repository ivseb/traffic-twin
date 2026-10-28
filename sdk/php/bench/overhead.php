<?php

declare(strict_types=1);

/**
 * Overhead micro-benchmark of the PHP SDK, in process (no network), PSR-7 messages from
 * guzzlehttp/psr7. Reports microseconds per request (p50, p99, mean).
 *
 *   php -d opcache.enable_cli=1 bench/overhead.php [--iterations N] [--json]
 *
 * Scenarios:
 *   baseline         the application handler alone
 *   gate-closed      SDK installed, no policy / not capturing (the fast path of every request)
 *   not-sampled      capturing, this request not sampled (rate 0)
 *   sampled-request  capturing and sampled: what the request itself waits for (decision, body peek, hand-off)
 *   sampled-deferred sanitize + serialize + spool append for that request: runs after the response
 *                    (shutdown function after fastcgi_finish_request under PHP-FPM)
 *   cold-gate        first request of a fresh PHP-FPM worker: read status + signed policy, verify the
 *                    Ed25519 signature, validate the schema, parse the policy, read the HMAC key
 *   outbound         Guzzle middleware, sampled, around a mock transport (request path only)
 *   outbound-deferred sanitize + spool for that outbound exchange
 */

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use GuzzleHttp\Psr7\Utils;
use TrafficTwin\Capture\Context;
use TrafficTwin\Integration\GuzzleMiddleware;
use TrafficTwin\Integration\Psr15Middleware;
use TrafficTwin\Runtime;
use TrafficTwin\Tests\Support\CallbackHandler;
use TrafficTwin\Tests\Support\Fixture;

require __DIR__ . '/../vendor/autoload.php';

$n = 3000;
$json = false;
foreach (array_slice($argv, 1) as $i => $a) {
    if ($a === '--iterations') {
        $n = (int) $argv[$i + 2];
    } elseif ($a === '--json') {
        $json = true;
    }
}

$hm = static fn (string $d): array => ['action' => 'hmac', 'domain' => $d];
$policy = static fn (int $rate): array => Fixture::policy([
    'sampling' => ['rate_bp' => $rate, 'trust_baggage' => false, 'propagate_to' => []],
    'identity' => ['subject' => ['from' => 'header', 'name' => 'authorization', 'jwt_claim' => 'sub']],
    'services' => [
        ['name' => 'shop-api', 'match' => ['inbound' => true, 'internal' => false], 'ops' => [
            ['op' => 'POST /api/v1/orders', 'response' => ['body' => [
                ['path' => '$.id', 'action' => $hm('order')],
                ['path' => '$.status', 'action' => ['action' => 'keep']],
                ['path' => '$.total', 'action' => ['action' => 'bucket', 'kind' => 'num', 'bounds' => [0, 50, 100, 250]]],
                ['path' => '$.items[*].sku', 'action' => $hm('sku')],
            ]]],
            ['op' => 'GET /api/v1/orders/{orderId}', 'request' => ['path' => ['orderId' => $hm('order')]]],
        ]],
        ['name' => 'shipping-ext', 'match' => ['base' => 'https://api.carrier.example'], 'ops' => [
            ['op' => 'POST /v1/shipments', 'request' => ['body' => [['path' => '$.orderId', 'action' => $hm('order')]]], 'response' => ['body' => [['path' => '$.shipmentId', 'action' => $hm('shipment')]]]],
        ]],
    ],
]);

$reqBody = '{"items":[{"sku":"TSHIRT-RED-M","qty":2,"price":19.90},{"sku":"MUG-WHITE","qty":1,"price":8.50}],"email":"giulia.neri@example.com","note":"suonare al secondo piano","gift":false,"coupon":null}';
$respBody = '{"id":"ORD-2026-000184","status":"CREATED","total":73.40,"items":[{"sku":"TSHIRT-RED-M"},{"sku":"MUG-WHITE"}],"eta":"2026-10-21"}';
$mkReq = static fn (): ServerRequest => (new ServerRequest('POST', 'https://shop.example/api/v1/orders?promo=AUTUMN10', [
    'Content-Type' => 'application/json', 'Accept' => 'application/json', 'User-Agent' => 'Mozilla/5.0 (X11; Linux x86_64)',
    'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjLTEwMDQyIn0.c2ln', 'Cookie' => 'sid=9f8e7d6c5b4a; cart=CART-778812',
    'X-Request-Id' => '550e8400-e29b-41d4-a716-446655440000', 'Accept-Encoding' => 'gzip',
], $reqBody))->withBody(Utils::streamFor($reqBody));
$app = new CallbackHandler(static fn () => new Response(201, ['Content-Type' => 'application/json; charset=utf-8', 'Cache-Control' => 'no-store'], $respBody));

/** @param callable(): void $fn @return array{p50: float, p99: float, mean: float} */
$measure = static function (callable $fn) use ($n): array {
    for ($i = 0; $i < 200; $i++) {
        $fn();
    }
    $t = [];
    for ($i = 0; $i < $n; $i++) {
        $s = hrtime(true);
        $fn();
        $t[] = (hrtime(true) - $s) / 1000;
    }
    sort($t);
    return ['p50' => $t[(int) ($n * 0.5)], 'p99' => $t[(int) ($n * 0.99)], 'mean' => array_sum($t) / $n];
};

$results = [];
$results['baseline'] = $measure(static fn () => $app->handle($mkReq()));
$base = $results['baseline']['p50'];
$reqOnly = static function (array $r) use ($base): array {
    $r['over_p50'] = $r['p50'] - $base;
    return $r;
};

// Request construction is part of every scenario; subtract it through the baseline.
$f0 = new Fixture();
$rt0 = $f0->runtime();
$mw0 = new Psr15Middleware($rt0);
$results['gate-closed'] = $reqOnly($measure(static fn () => $mw0->process($mkReq(), $app)));

$f1 = (new Fixture())->write($policy(0));
$rt1 = $f1->runtime();
$mw1 = new Psr15Middleware($rt1);
$results['not-sampled'] = $reqOnly($measure(static fn () => $mw1->process($mkReq(), $app)));

$f2 = (new Fixture())->write($policy(10000));
$rt2 = $f2->runtime();
$mw2 = new Psr15Middleware($rt2);
$results['sampled-request'] = $reqOnly($measure(static function () use ($mw2, $mkReq, $app, $rt2): void {
    $mw2->process($mkReq(), $app)->getBody()->__toString();
    $rt2->discardPending();
}));
$results['sampled-deferred'] = $measure(static function () use ($mw2, $mkReq, $app, $rt2): void {
    $mw2->process($mkReq(), $app)->getBody()->__toString();
    $rt2->processPending();
});
$results['sampled-deferred']['over_p50'] = $results['sampled-deferred']['p50'] - $base;
// Isolate the deferred part: total minus the request-path part.
$results['sampled-deferred']['deferred_only_p50'] = max(0.0, $results['sampled-deferred']['p50'] - $results['sampled-request']['p50']);

$results['cold-gate'] = $measure(static function () use ($f2): void {
    $rt = $f2->runtime();
    $rt->sanitizer();
});

$mock = new MockHandler(array_fill(0, 2 * $n + 400, new Response(201, ['Content-Type' => 'application/json'], '{"shipmentId":"SHP-99","status":"CREATED"}')));
$stack = HandlerStack::create($mock);
$plainClient = new Client(['handler' => $stack]);
$stack2 = HandlerStack::create(new MockHandler(array_fill(0, 2 * $n + 400, new Response(201, ['Content-Type' => 'application/json'], '{"shipmentId":"SHP-99","status":"CREATED"}'))));
$stack2->push(GuzzleMiddleware::create($rt2));
$client = new Client(['handler' => $stack2]);
Context::enter(new TrafficTwin\Capture\ExchangeCtx(true, bin2hex(random_bytes(16)), true, bin2hex(random_bytes(8))));
$post = ['body' => '{"orderId":"ORD-2026-000184","address":"Via Roma 1, Milano"}', 'headers' => ['Content-Type' => 'application/json']];
$outBase = $measure(static fn () => $plainClient->post('https://api.carrier.example/v1/shipments', $post));
$out = $measure(static function () use ($client, $post, $rt2): void {
    $client->post('https://api.carrier.example/v1/shipments', $post);
    $rt2->discardPending();
});
$out['over_p50'] = $out['p50'] - $outBase['p50'];
$results['outbound'] = $out;
$od = $measure(static function () use ($client, $post, $rt2): void {
    $client->post('https://api.carrier.example/v1/shipments', $post);
    $rt2->processPending();
});
$od['deferred_only_p50'] = max(0.0, $od['p50'] - $out['p50']);
$results['outbound-deferred'] = $od;
Context::leave();

if ($json) {
    echo json_encode(['php' => PHP_VERSION, 'opcache' => (bool) ini_get('opcache.enable_cli'), 'iterations' => $n, 'results' => $results], JSON_PRETTY_PRINT) . "\n";
    exit(0);
}
printf("PHP %s, opcache.enable_cli=%s, %d iterations (microseconds per request)\n\n", PHP_VERSION, ini_get('opcache.enable_cli') ?: '0', $n);
printf("%-18s %9s %9s %9s %12s\n", 'scenario', 'p50', 'p99', 'mean', 'over base p50');
foreach ($results as $name => $r) {
    $extra = isset($r['deferred_only_p50']) ? sprintf('%9.1f (deferred part)', $r['deferred_only_p50']) : (isset($r['over_p50']) ? sprintf('%+12.1f', $r['over_p50']) : '');
    printf("%-18s %9.1f %9.1f %9.1f %s\n", $name, $r['p50'], $r['p99'], $r['mean'], $extra);
}
