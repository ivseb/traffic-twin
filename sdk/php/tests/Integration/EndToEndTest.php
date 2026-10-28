<?php

declare(strict_types=1);

namespace TrafficTwin\Tests\Integration;

use PHPUnit\Framework\TestCase;
use TrafficTwin\Sanitizer\Json;
use TrafficTwin\Tests\Support\FakeCore;
use TrafficTwin\Tests\Support\Fixture;
use TrafficTwin\Tests\Support\Proc;

/**
 * The whole path: tt-shipper enrolls (token + CA pin + CSR) with a fake tt-core over TLS, gets the
 * signed policy and the heartbeat, a PHP built-in server instrumented with the SDK serves requests
 * and calls a carrier through Guzzle, events land in the spool, tt-shipper ships them over mTLS.
 */
final class EndToEndTest extends TestCase
{
    private static FakeCore $core;
    private static ?Proc $app = null;
    private static ?Proc $carrier = null;
    private static int $appPort;
    private static int $carrierPort;
    private string $state;

    public static function setUpBeforeClass(): void
    {
        self::$core = new FakeCore();
        self::$carrierPort = self::freePort();
        self::$appPort = self::freePort();
        self::$carrier = new Proc([PHP_BINARY, '-S', '127.0.0.1:' . self::$carrierPort, __DIR__ . '/../support/carrier.php']);
        // Each request is a fresh PHP request, like PHP-FPM: nothing is shared between them.
        self::$app = new Proc([PHP_BINARY, '-S', '127.0.0.1:' . self::$appPort, __DIR__ . '/../support/app.php'], [
            'TT_TEST_CARRIER_PORT' => (string) self::$carrierPort,
        ]);
        foreach ([self::$appPort, self::$carrierPort] as $port) {
            $t0 = microtime(true);
            while (!@fsockopen('127.0.0.1', $port)) {
                if (microtime(true) - $t0 > 10) {
                    throw new \RuntimeException('built-in server did not start');
                }
                usleep(50000);
            }
        }
    }

    public static function tearDownAfterClass(): void
    {
        self::$app?->kill();
        self::$carrier?->kill();
        self::$core->stop();
    }

    private static function freePort(): int
    {
        $s = stream_socket_server('tcp://127.0.0.1:0');
        $port = (int) substr((string) strrchr((string) stream_socket_get_name($s, false), ':'), 1);
        fclose($s);
        return $port;
    }

    protected function setUp(): void
    {
        $this->state = sys_get_temp_dir() . '/tt-e2e-' . bin2hex(random_bytes(4));
        foreach (['events.ndjson', 'log.ndjson'] as $f) {
            @unlink(self::$core->dir . '/' . $f);
        }
        self::$core->control(['policy' => $this->policy(), 'kill' => null, 'revoked' => null, 'logs_status' => null, 'policy_tamper' => null, 'min_issued_seq' => null, 'renew_before' => null, 'add_signing_keys' => null, 'revoke_signing_keys' => null, 'policy_sign_secret' => null, 'policy_signing_kid' => null]);
    }

    protected function tearDown(): void
    {
        Fixture::rmrf($this->state);
    }

    /** @return array<string, mixed> */
    private function policy(int $seq = 1): array
    {
        $hm = static fn (string $d): array => ['action' => 'hmac', 'domain' => $d];
        return Fixture::policy([
            'issued_seq' => $seq,
            'services' => [
                [
                    'name' => 'shop-api',
                    'match' => ['inbound' => true, 'internal' => false],
                    'errors' => ['body' => [['path' => '$.error.code', 'action' => ['action' => 'keep']]]],
                    'ops' => [
                        ['op' => 'POST /api/v1/orders', 'response' => ['body' => [
                            ['path' => '$.id', 'action' => $hm('order')],
                            ['path' => '$.status', 'action' => ['action' => 'keep']],
                            ['path' => '$.total', 'action' => ['action' => 'bucket', 'kind' => 'num', 'bounds' => [0, 50, 100, 250]]],
                            ['path' => '$.shipmentId', 'action' => $hm('shipment')],
                        ]]],
                        ['op' => 'GET /api/v1/orders/{orderId}', 'request' => ['path' => ['orderId' => $hm('order')]]],
                    ],
                ],
                [
                    'name' => 'shipping-ext',
                    'match' => ['base' => 'http://127.0.0.1:' . self::$carrierPort],
                    'ops' => [['op' => 'POST /v1/shipments',
                        'request' => ['body' => [['path' => '$.orderId', 'action' => $hm('order')]]],
                        'response' => ['body' => [['path' => '$.shipmentId', 'action' => $hm('shipment')], ['path' => '$.status', 'action' => ['action' => 'keep']]]],
                    ]],
                ],
            ],
        ]);
    }

    /** @param array<string, string> $over @return array<string, string> */
    private function env(array $over = []): array
    {
        return $over + [
            'TT_STATE_DIR' => $this->state,
            'TT_ENROLL_URL' => self::$core->enrollUrl(),
            'TT_ENROLL_TOKEN' => self::$core->token(),
            'TT_SERVICE_NAME' => 'shop-api',
            'TT_HMAC_KEY' => Fixture::HMAC_KEY,
        ];
    }

    /** @return array{0: int, 1: string} */
    private function shipperOnce(array $envOver = []): array
    {
        return Proc::run([PHP_BINARY, __DIR__ . '/../../bin/tt-shipper', '--once', '--verbose'], $this->env($envOver), 90);
    }

    /** @return array<string, mixed> */
    private function shipperStatus(): array
    {
        return json_decode((string) file_get_contents($this->state . '/status.json'), true);
    }

    /** @return array{0: int, 1: string} */
    private function http(string $method, string $path, ?string $body = null, array $headers = []): array
    {
        $h = '';
        foreach ($headers as $k => $v) {
            $h .= "$k: $v\r\n";
        }
        $ctx = stream_context_create(['http' => ['method' => $method, 'header' => $h, 'content' => $body ?? '', 'ignore_errors' => true, 'timeout' => 10]]);
        $r = file_get_contents('http://127.0.0.1:' . self::$appPort . $path, false, $ctx);
        preg_match('#HTTP/\S+ (\d+)#', $http_response_header[0] ?? '', $m);
        return [(int) ($m[1] ?? 0), (string) $r];
    }

    private function appEnv(): void
    {
        // The app server was started without TT_STATE_DIR; restart it for this test's state dir.
        self::$app?->kill();
        self::$app = new Proc([PHP_BINARY, '-S', '127.0.0.1:' . self::$appPort, __DIR__ . '/../support/app.php'], $this->env() + ['TT_TEST_CARRIER_PORT' => (string) self::$carrierPort]);
        $t0 = microtime(true);
        while (!@fsockopen('127.0.0.1', self::$appPort)) {
            if (microtime(true) - $t0 > 10) {
                throw new \RuntimeException('app did not restart');
            }
            usleep(50000);
        }
    }

    /** @return int number of events in the spool */
    private function waitSpool(int $n, float $timeoutS = 10): int
    {
        $t0 = microtime(true);
        $count = 0;
        while (microtime(true) - $t0 < $timeoutS) {
            $count = 0;
            foreach (glob($this->state . '/spool/seg-*') ?: [] as $f) {
                $count += substr_count((string) file_get_contents($f), "\n");
            }
            if ($count >= $n) {
                return $count;
            }
            usleep(100000);
        }
        return $count;
    }

    public function testEnrollmentPolicyCaptureAndShipping(): void
    {
        // Before the shipper has run nothing is captured: fail closed.
        $this->appEnv();
        [$code] = $this->http('GET', '/api/v1/orders/ORD-2026-000184');
        self::assertSame(200, $code);
        usleep(300000);
        self::assertSame(0, $this->waitSpool(1, 0.5), 'no status.json, no capture');

        [$exit, $out] = $this->shipperOnce();
        self::assertSame(0, $exit, $out);
        self::assertStringContainsString('state=capturing', $out);
        $st = $this->shipperStatus();
        self::assertTrue($st['heartbeat_ok']);
        self::assertFalse($st['kill']);
        self::assertSame('shop-api', $st['service_name']);
        self::assertMatchesRegularExpression('/^src-/', $st['source_id']);
        self::assertSame('0600', substr(sprintf('%o', fileperms($this->state . '/client.key')), -4));
        self::assertSame('0600', substr(sprintf('%o', fileperms($this->state . '/status.json')), -4));
        self::assertSame('0600', substr(sprintf('%o', fileperms($this->state . '/policy.envelope.json')), -4));
        self::assertSame('0700', substr(sprintf('%o', fileperms($this->state)), -4));

        $log = self::$core->log();
        self::assertSame('/fleet/v1/enroll', $log[0]['path']);
        self::assertTrue($log[0]['enroll']['csr'], 'enrollment with a CSR: the private key never left the host');
        self::assertSame('sdk-php', $log[0]['enroll']['source']['kind']);
        self::assertSame(['k1'], $log[0]['enroll']['source']['hmac_kids']);
        $hb = array_values(array_filter($log, static fn (array $l): bool => $l['path'] === '/fleet/v1/heartbeat'));
        self::assertNotEmpty($hb);
        self::assertTrue($hb[0]['mtls']);
        self::assertSame($st['source_id'], $hb[0]['san']);
        self::assertContains($hb[0]['heartbeat']['state'], ['starting', 'no_policy'], 'the first heartbeat is sent before any capture');

        // Traffic.
        [$c1, $b1] = $this->http('POST', '/api/v1/orders', '{"items":[{"sku":"TSHIRT-RED-M","qty":2}],"email":"giulia.neri@example.com","note":"suonare al secondo piano"}', [
            'Content-Type' => 'application/json',
            'Cookie' => 'sid=9f8e7d6c5b4a',
            'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjLTEwMDQyIn0.c2ln',
            'X-Request-Id' => '550e8400-e29b-41d4-a716-446655440000',
        ]);
        self::assertSame(201, $c1);
        self::assertStringContainsString('"shipmentId":"SHP-', $b1, 'the application response is untouched');
        [$c2] = $this->http('GET', '/api/v1/orders/ORD-2026-000184');
        self::assertSame(200, $c2);
        [$c3] = $this->http('GET', '/api/v1/nothing/here');
        self::assertSame(404, $c3);
        // 3 inbound + 1 outbound (the carrier call made while serving the POST).
        self::assertSame(4, $this->waitSpool(4), 'deferred sanitization wrote the events');

        // The spool holds sanitized events only, owner-readable.
        foreach (glob($this->state . '/spool/seg-*') ?: [] as $f) {
            self::assertSame('0600', substr(sprintf('%o', fileperms($f)), -4));
        }
        $spool = '';
        foreach (glob($this->state . '/spool/seg-*') ?: [] as $f) {
            $spool .= file_get_contents($f);
        }
        foreach (['giulia', 'TSHIRT', '9f8e7d6c5b4a', 'ORD-2026', 'secondo piano', 'Via Roma', 'c-10042', '550e8400', 'SHP-'] as $raw) {
            self::assertStringNotContainsString($raw, $spool, "raw value '$raw' reached the spool");
        }

        [$exit, $out] = $this->shipperOnce();
        self::assertSame(0, $exit, $out);
        self::assertTrue(self::$core->waitEvents(4), 'events delivered: ' . $out);

        $events = array_map(static fn (string $l): array => json_decode($l, true), self::$core->events());
        foreach (self::$core->events() as $line) {
            self::assertSame($line, Json::write(Json::toOut(Json::parse($line))), 'the intake accepts only the exact canonical form (event.md 5.1)');
        }
        $byOp = [];
        foreach ($events as $e) {
            $byOp[$e['dir'] . ' ' . $e['op']] = $e;
            self::assertSame($st['source_id'], $e['source']['id']);
        }
        self::assertArrayHasKey('inbound POST /api/v1/orders', $byOp);
        self::assertArrayHasKey('inbound GET /api/v1/orders/{orderId}', $byOp);
        self::assertArrayHasKey('outbound POST /v1/shipments', $byOp);
        $post = $byOp['inbound POST /api/v1/orders'];
        $out1 = $byOp['outbound POST /v1/shipments'];
        self::assertSame($post['trace_id'], $out1['trace_id'], 'the carrier call shares the trace of the order request');
        self::assertSame($post['span_id'], $out1['parent_span_id']);
        self::assertSame('inherited', $out1['sampled_by']);
        self::assertSame('random', $post['sampled_by'], 'no subject in this policy: random sampling at 100%');
        self::assertSame('num:50-100', $post['resp']['body']['total']);
        self::assertSame('keep:CREATED', $post['resp']['body']['status']);
        self::assertSame($out1['req']['body']['orderId'], $post['resp']['body']['id'], 'same HMAC domain, same token: the miner can link them');
        self::assertSame($out1['resp']['body']['shipmentId'], $post['resp']['body']['shipmentId']);
        self::assertSame('shipping-ext', $out1['service']);
        self::assertSame('drop:str:uuid', $post['req']['headers']['x-request-id'][0]);
        self::assertSame(['drop:str:l32'], $post['req']['cookies']['sid']);
        self::assertSame('keep:NOT_FOUND', $byOp['inbound GET /api/v1/{drop:str:l8}/{drop:str:l8}']['resp']['body']['error']['code'], 'error rules apply to unknown operations');
        self::assertSame('raw', $byOp['inbound GET /api/v1/{drop:str:l8}/{drop:str:l8}']['route_source']);
        self::assertCount(0, glob($this->state . '/spool/seg-*') ?: [], 'shipped segments are deleted');

        // The next heartbeat reports what happened.
        [$exit] = $this->shipperOnce();
        $hb = array_values(array_filter(self::$core->log(), static fn (array $l): bool => $l['path'] === '/fleet/v1/heartbeat'));
        $last = end($hb)['heartbeat'];
        self::assertContains($last['state'], ['starting', 'capturing'], 'a fresh shipper process reports starting until its own first heartbeat is answered');
        self::assertGreaterThanOrEqual(4, $last['counters']['exchanges_seen'], 'worker counters are aggregated');
        self::assertGreaterThanOrEqual(4, $last['counters']['exchanges_sampled']);
        self::assertSame(0, $last['counters']['sanitizer_errors']);
        self::assertArrayHasKey('p99', $last['overhead_us']);
        self::assertSame('p-shop', $last['policy']['id']);
    }

    public function testKillSwitchStopsCaptureDropsTheSpoolAndSurvivesARestart(): void
    {
        $this->appEnv();
        $this->shipperOnce();
        $this->http('GET', '/api/v1/orders/ORD-1');
        self::assertSame(1, $this->waitSpool(1));
        self::$core->control(['kill' => true]);
        [, $out] = $this->shipperOnce();
        $st = $this->shipperStatus();
        self::assertTrue($st['kill']);
        self::assertSame(0, $this->waitSpool(0, 0.1));
        self::assertSame([], glob($this->state . '/spool/seg-*') ?: [], 'queues are dropped');
        $this->http('GET', '/api/v1/orders/ORD-2');
        usleep(500000);
        self::assertSame(0, $this->waitSpool(1, 0.5), 'no capture while killed');
        self::assertSame(0, count(self::$core->events()));

        // A restart with tt-core unreachable must not re-enable capture: the switch is persisted.
        [$exit, $out] = $this->shipperOnce(['TT_ENROLL_URL' => self::$core->enrollUrl()] + ['TT_HEARTBEAT_INTERVAL_MS' => '100']);
        self::$core->control(['kill' => false]);
        $state = json_decode((string) file_get_contents($this->state . '/state.json'), true);
        self::assertTrue($state['kill']);
        // When tt-core says kill=false on a later heartbeat, capture resumes.
        $this->shipperOnce();
        self::assertFalse($this->shipperStatus()['kill']);
        $this->http('GET', '/api/v1/orders/ORD-3');
        self::assertSame(1, $this->waitSpool(1));
    }

    public function testPersistedKillSurvivesWhenTheCoreIsDown(): void
    {
        $this->appEnv();
        self::$core->control(['kill' => true]);
        $this->shipperOnce();
        self::assertTrue($this->shipperStatus()['kill']);
        // Same state dir, enrollment URL that does not answer: heartbeat fails, kill stays.
        [, $out] = $this->shipperOnce(['TT_ENROLL_URL' => 'https://localhost:' . self::freePort()]);
        // The enrollment record is bound to its URL, so the shipper tries to enroll again and fails closed.
        $st = $this->shipperStatus();
        self::assertNotSame('capturing', $st['state']);
        $this->http('GET', '/api/v1/orders/ORD-1');
        usleep(400000);
        self::assertSame(0, $this->waitSpool(1, 0.3));
    }

    public function testTamperedPolicyIsRefusedAndTheOldOneKept(): void
    {
        $this->appEnv();
        $this->shipperOnce();
        self::assertSame('capturing', $this->shipperStatus()['state']);
        $hash = $this->shipperStatus()['policy_hash'];
        self::$core->control(['policy' => $this->policy(2), 'policy_tamper' => true]);
        $this->shipperOnce();
        $st = $this->shipperStatus();
        self::assertSame($hash, $st['policy_hash'], 'the previous valid policy is kept');
        self::assertSame('capturing', $st['state']);
    }

    public function testReplayedOldPolicyIsRefused(): void
    {
        $this->appEnv();
        self::$core->control(['policy' => $this->policy(5)]);
        $this->shipperOnce();
        $h5 = $this->shipperStatus()['policy_hash'];
        self::$core->control(['policy' => $this->policy(3)]);
        $this->shipperOnce();
        self::assertSame($h5, $this->shipperStatus()['policy_hash'], 'issued_seq must increase (policy.md 4)');
        // min_issued_seq from the heartbeat drops the current policy and stops the capture.
        self::$core->control(['policy' => $this->policy(7), 'min_issued_seq' => 6]);
        $this->shipperOnce();
        self::assertNotSame($h5, $this->shipperStatus()['policy_hash']);
        self::$core->control(['min_issued_seq' => 9]);
        $this->shipperOnce();
        self::assertNotSame('capturing', $this->shipperStatus()['state']);
    }

    // Usability test 4: tt-core moves min_issued_seq to the new policy in the same heartbeat that
    // announces it; the shipper switches without an error line.
    public function testNormalPolicyChangeReportsNoError(): void
    {
        $this->appEnv();
        $this->shipperOnce();
        self::assertSame('capturing', $this->shipperStatus()['state']);
        for ($seq = 2; $seq <= 4; $seq++) {
            self::$core->control(['policy' => $this->policy($seq), 'min_issued_seq' => $seq]);
            [, $out] = $this->shipperOnce();
            self::assertSame('capturing', $this->shipperStatus()['state'], $out);
            self::assertStringNotContainsString('error policy_below_min_issued_seq', $out);
            self::assertStringNotContainsString('error policy_rejected', $out);
        }
    }

    public function testNoPolicyMeansNoCapture(): void
    {
        $this->appEnv();
        self::$core->control(['policy' => null]);
        $this->shipperOnce();
        self::assertSame('no_policy', $this->shipperStatus()['state']);
        $this->http('GET', '/api/v1/orders/ORD-1');
        usleep(400000);
        self::assertSame(0, $this->waitSpool(1, 0.3));
    }

    public function testRevokedSourceStopsAndDropsQueues(): void
    {
        $this->appEnv();
        $this->shipperOnce();
        $this->http('GET', '/api/v1/orders/ORD-1');
        self::assertSame(1, $this->waitSpool(1));
        self::$core->control(['revoked' => true]);
        $this->shipperOnce();
        self::assertTrue($this->shipperStatus()['revoked']);
        self::assertSame([], glob($this->state . '/spool/seg-*') ?: []);
    }

    public function testWrongCaPinFailsEnrollment(): void
    {
        $token = preg_replace('/.$/', self::$core->token()[-1] === 'A' ? 'B' : 'A', self::$core->token());
        [, $out] = $this->shipperOnce(['TT_ENROLL_TOKEN' => $token]);
        self::assertFileDoesNotExist($this->state . '/enrollment.json');
        self::assertStringContainsString('enroll_pin_mismatch', $out);
        self::assertNotSame('capturing', $this->shipperStatus()['state']);
        self::assertSame([], self::$core->log(), 'nothing was sent to a server that does not match the pin');
    }

    public function testSecondShipperOnTheSameStateIsRefused(): void
    {
        $first = new Proc([PHP_BINARY, __DIR__ . '/../../bin/tt-shipper'], $this->env());
        $t0 = microtime(true);
        while (!is_file($this->state . '/status.json') || ($this->shipperStatus()['heartbeat_ok'] ?? false) !== true) {
            if (microtime(true) - $t0 > 30) {
                $first->kill();
                self::fail('shipper did not become ready: ' . $first->output());
            }
            usleep(100000);
        }
        [$exit] = $this->shipperOnce();
        self::assertSame(3, $exit);
        $first->terminate(15);
        self::assertSame(0, $first->wait(10), 'SIGTERM ends the loop cleanly');
    }

    public function testRetriesAfterTransientIntakeFailures(): void
    {
        $this->appEnv();
        $this->shipperOnce();
        $this->http('GET', '/api/v1/orders/ORD-1');
        self::assertSame(1, $this->waitSpool(1));
        self::$core->control(['logs_status' => 503, 'logs_fail_n' => 2, 'retry_after' => 1]);
        $shipper = new Proc([PHP_BINARY, __DIR__ . '/../../bin/tt-shipper', '--verbose'], $this->env(['TT_EXPORT_FLUSH_MS' => '200']));
        self::assertTrue(self::$core->waitEvents(1, 40), 'delivered after retries: ' . $shipper->output());
        $shipper->terminate(15);
        $shipper->wait(10);
        $statuses = array_values(array_map(static fn (array $l): int => $l['status'], array_filter(self::$core->log(), static fn (array $l): bool => $l['path'] === '/v1/logs')));
        self::assertSame([503, 503, 200], $statuses);
        self::assertCount(1, self::$core->events(), 'delivered exactly once');
    }

    public function testPlainPhpScriptWithNativeInstall(): void
    {
        $this->shipperOnce();
        $port = self::freePort();
        $srv = new Proc([PHP_BINARY, '-S', '127.0.0.1:' . $port, __DIR__ . '/../support/native.php'], $this->env());
        try {
            $t0 = microtime(true);
            while (!@fsockopen('127.0.0.1', $port)) {
                if (microtime(true) - $t0 > 10) {
                    self::fail('server did not start');
                }
                usleep(50000);
            }
            $ctx = stream_context_create(['http' => ['method' => 'POST', 'header' => "Content-Type: application/json\r\nX-Request-Id: 550e8400-e29b-41d4-a716-446655440000\r\nX_Underscore: 1\r\n", 'content' => '{"note":"suonare al secondo piano"}', 'ignore_errors' => true]]);
            $body = file_get_contents('http://127.0.0.1:' . $port . '/shop/orders?promo=AUTUMN10', false, $ctx);
            self::assertStringContainsString('"status":"CREATED"', (string) $body, 'the response reaches the client unchanged');
            $big = file_get_contents('http://127.0.0.1:' . $port . '/shop/health');
            self::assertSame(20000, strlen((string) json_decode((string) $big, true)['big']), 'large and streamed output passes through the buffer');
            self::assertSame(2, $this->waitSpool(2));
        } finally {
            $srv->kill();
        }
        $events = [];
        foreach (glob($this->state . '/spool/seg-*') ?: [] as $f) {
            foreach (file($f, FILE_IGNORE_NEW_LINES) as $line) {
                $events[] = json_decode(explode("\t", $line, 5)[4], true);
            }
        }
        usort($events, static fn (array $a, array $b): int => strcmp($a['ts'], $b['ts']));
        $post = $events[0];
        self::assertSame('POST /{drop:str:l8}/{drop:str:l8}', $post['op']);
        self::assertSame('raw', $post['route_source']);
        self::assertSame(201, $post['status']);
        self::assertSame(['drop:str:uuid'], $post['req']['headers']['x-request-id'], 'getallheaders() names are lowercased');
        self::assertArrayHasKey('host', $post['req']['headers']);
        self::assertSame('drop:str:l32', $post['resp']['body']['echo']);
        self::assertSame(['drop:str:l32'], $post['resp']['cookies']['sid']);
        self::assertSame('drop:str:l32', $post['req']['body']['note']);
        self::assertSame('lmax', $events[1]['resp']['size'], 'a 20 kB response is counted to the end through the buffer');
        self::assertEquals(['status' => 'drop:str:l8', 'big' => 'drop:str:lmax'], $events[1]['resp']['body']);
        $text = json_encode($events);
        foreach (['suonare', '9f8e7d6c5b4a', 'ORD-2026', 'AUTUMN10'] as $raw) {
            self::assertStringNotContainsString($raw, $text);
        }
    }

    public function testEnrollmentWithoutCsrUsesTheKeyGeneratedByTheCore(): void
    {
        [$exit, $out] = $this->shipperOnce(['TT_ENROLL_CSR' => '0']);
        self::assertSame(0, $exit, $out);
        self::assertFalse(self::$core->log()[0]['enroll']['csr']);
        self::assertSame('capturing', $this->shipperStatus()['state']);
        self::assertSame('0600', substr(sprintf('%o', fileperms($this->state . '/client.key')), -4));
        self::assertStringContainsString('PRIVATE KEY', (string) file_get_contents($this->state . '/client.key'));
    }

    public function testCertificateRenewal(): void
    {
        $this->shipperOnce();
        $before = json_decode((string) file_get_contents($this->state . '/enrollment.json'), true)['client_cert'];
        self::$core->control(['renew_before' => gmdate('Y-m-d\TH:i:s\Z', time() - 60)]);
        $this->shipperOnce();
        $after = json_decode((string) file_get_contents($this->state . '/enrollment.json'), true)['client_cert'];
        self::assertNotSame($before, $after, 'a new certificate was installed');
        $renew = array_values(array_filter(self::$core->log(), static fn (array $l): bool => $l['path'] === '/fleet/v1/renew'));
        self::assertSame(200, $renew[0]['status']);
        self::$core->control(['renew_before' => null]);
        // The renewed certificate works for mTLS: the next cycle still reaches tt-core.
        $n = count(self::$core->log());
        $this->shipperOnce();
        $hb = array_filter(array_slice(self::$core->log(), $n), static fn (array $l): bool => $l['path'] === '/fleet/v1/heartbeat' && $l['status'] === 200);
        self::assertNotEmpty($hb);
    }

    public function testSigningKeyRotationAndRevocation(): void
    {
        $this->shipperOnce();
        $first = $this->shipperStatus()['policy_hash'];
        // A new key, endorsed by the pinned one (fleet-api HeartbeatResponse.add_signing_keys).
        $kp = sodium_crypto_sign_keypair();
        $newPub = sodium_crypto_sign_publickey($kp);
        $newSecret = sodium_crypto_sign_secretkey($kp);
        $endorser = \TrafficTwin\Sanitizer\Utf8::b64urlDecode(self::$core->info['signing_secret']);
        $endorsement = sodium_crypto_sign_detached("tt-fleet-key/v1\0policy-test-2\0" . $newPub, (string) $endorser);
        $b64 = static fn (string $b): string => rtrim(strtr(base64_encode($b), '+/', '-_'), '=');
        $key = ['kid' => 'policy-test-2', 'alg' => 'Ed25519', 'public_key' => $b64($newPub), 'endorsed_by' => 'policy-test-1', 'endorsement' => $b64($endorsement)];
        $forged = $key;
        $forged['kid'] = 'policy-forged';
        self::$core->control(['add_signing_keys' => [$key, $forged], 'policy' => $this->policy(2), 'policy_sign_secret' => $b64($newSecret), 'policy_signing_kid' => 'policy-test-2']);
        $this->shipperOnce();
        $st = $this->shipperStatus();
        self::assertArrayHasKey('policy-test-2', (array) $st['signing_keys']);
        self::assertArrayNotHasKey('policy-forged', (array) $st['signing_keys'], 'an endorsement that does not verify is ignored');
        self::assertNotSame($first, $st['policy_hash'], 'the policy signed with the rotated key was accepted');
        self::assertSame('capturing', $st['state']);
        // Revoking the key that signed the current policy drops the policy: no capture.
        self::$core->control(['revoke_signing_keys' => ['policy-test-2']]);
        $this->shipperOnce();
        self::assertNotSame('capturing', $this->shipperStatus()['state']);
        self::assertArrayNotHasKey('policy-test-2', (array) $this->shipperStatus()['signing_keys']);
        self::$core->control(['add_signing_keys' => null, 'revoke_signing_keys' => null, 'policy_sign_secret' => null, 'policy_signing_kid' => null]);
    }

    /** @return array{0: string, 1: string} kid entry of add_signing_keys endorsed by $bySecret, and the new secret key */
    private static function endorsedKey(string $kid, string $byKid, string $bySecret): array
    {
        $kp = sodium_crypto_sign_keypair();
        $pub = sodium_crypto_sign_publickey($kp);
        $b64 = static fn (string $b): string => rtrim(strtr(base64_encode($b), '+/', '-_'), '=');
        $sig = sodium_crypto_sign_detached("tt-fleet-key/v1\0" . $kid . "\0" . $pub, $bySecret);
        return [['kid' => $kid, 'alg' => 'Ed25519', 'public_key' => $b64($pub), 'endorsed_by' => $byKid, 'endorsement' => $b64($sig)], sodium_crypto_sign_secretkey($kp)];
    }

    private static function b64(string $b): string
    {
        return rtrim(strtr(base64_encode($b), '+/', '-_'), '=');
    }

    /** signing_kids of the last heartbeat logged by the fake core, as JSON text */
    private function lastSigningKids(): ?string
    {
        $hb = array_values(array_filter(self::$core->log(), static fn (array $l): bool => $l['path'] === '/fleet/v1/heartbeat' && $l['status'] === 200));
        self::assertNotEmpty($hb);
        return $hb[count($hb) - 1]['signing_kids_json'] ?? null;
    }

    public function testHeartbeatCarriesTheTrustedSigningKids(): void
    {
        $this->shipperOnce();
        $this->shipperOnce();
        self::assertSame('["policy-test-1"]', $this->lastSigningKids());
        $root = (string) \TrafficTwin\Sanitizer\Utf8::b64urlDecode(self::$core->info['signing_secret']);
        // A key pinned earlier in the list endorses a later one.
        [$k2, $s2] = self::endorsedKey('policy-test-2', 'policy-test-1', $root);
        [$k0] = self::endorsedKey('policy-test-0', 'policy-test-2', $s2);
        self::$core->control(['add_signing_keys' => [$k2, $k0]]);
        $this->shipperOnce();
        $this->shipperOnce();
        self::assertSame('["policy-test-0","policy-test-1","policy-test-2"]', $this->lastSigningKids());
        self::$core->control(['revoke_signing_keys' => ['policy-test-1', 'policy-test-0', 'policy-test-2']]);
        $this->shipperOnce();
        $this->shipperOnce();
        self::assertSame('[]', $this->lastSigningKids(), 'an empty signing_kids is a JSON array');
    }

    public function testKeyEndorsedByAKidRevokedInTheSameHeartbeatIsNotPinned(): void
    {
        $this->shipperOnce();
        self::assertSame('capturing', $this->shipperStatus()['state']);
        $root = (string) \TrafficTwin\Sanitizer\Utf8::b64urlDecode(self::$core->info['signing_secret']);
        [$k2, $s2] = self::endorsedKey('policy-test-2', 'policy-test-1', $root);
        // Same response: the endorser is revoked, the key it endorsed comes along; the policy is signed by the new key.
        self::$core->control(['add_signing_keys' => [$k2], 'revoke_signing_keys' => ['policy-test-1'],
            'policy' => $this->policy(2), 'policy_sign_secret' => self::b64($s2), 'policy_signing_kid' => 'policy-test-2']);
        [, $out] = $this->shipperOnce();
        $st = $this->shipperStatus();
        self::assertSame([], (array) $st['signing_keys']);
        self::assertNotSame('capturing', $st['state'], 'a policy signed by the refused key is not accepted');
        self::assertStringContainsString('signing_key_endorser_unknown', $out);
        $this->shipperOnce();
        $st = $this->shipperStatus();
        self::assertNotSame('capturing', $st['state']);
        self::assertNull($st['policy_hash']);
        self::assertSame('[]', $this->lastSigningKids());
        $state = json_decode((string) file_get_contents($this->state . '/state.json'), true);
        self::assertSame([], $state['added_keys'] ?? []);
        self::assertContains('policy-test-1', $state['revoked_kids']);
    }

    public function testEndorsedRotationSurvivesTheRevocationOfTheOldKeyAndRestarts(): void
    {
        $this->shipperOnce();
        $first = $this->shipperStatus()['policy_hash'];
        $root = (string) \TrafficTwin\Sanitizer\Utf8::b64urlDecode(self::$core->info['signing_secret']);
        [$k2, $s2] = self::endorsedKey('policy-test-2', 'policy-test-1', $root);
        // tt-core repeats every endorsed key at every heartbeat.
        self::$core->control(['add_signing_keys' => [$k2], 'policy' => $this->policy(2), 'policy_sign_secret' => self::b64($s2), 'policy_signing_kid' => 'policy-test-2']);
        [, $out] = $this->shipperOnce();
        $st = $this->shipperStatus();
        self::assertSame('capturing', $st['state']);
        self::assertNotSame($first, $st['policy_hash'], 'the policy signed by the new key is accepted');
        $rotated = $st['policy_hash'];
        self::assertStringNotContainsString('error signing_key', $out);
        // Each --once run is a restart: the already pinned key, repeated, is not an error.
        [, $out] = $this->shipperOnce();
        self::assertStringNotContainsString('error signing_key', $out);
        self::assertSame('["policy-test-1","policy-test-2"]', $this->lastSigningKids());
        // The old key is revoked: still capturing under the new one.
        self::$core->control(['revoke_signing_keys' => ['policy-test-1']]);
        [, $out] = $this->shipperOnce();
        self::assertStringNotContainsString('error signing_key', $out);
        self::assertSame('capturing', $this->shipperStatus()['state']);
        // Restart: the rotated key and the revocation come from the state directory.
        [, $out] = $this->shipperOnce();
        self::assertStringNotContainsString('error signing_key', $out);
        $st = $this->shipperStatus();
        self::assertSame('capturing', $st['state']);
        self::assertSame($rotated, $st['policy_hash']);
        self::assertSame(['policy-test-2'], array_keys((array) $st['signing_keys']));
        self::assertSame('["policy-test-2"]', $this->lastSigningKids());
        $state = json_decode((string) file_get_contents($this->state . '/state.json'), true);
        self::assertContains('policy-test-1', $state['revoked_kids']);
        self::assertSame(['policy-test-2'], array_column($state['added_keys'], 'kid'));
    }

    public function testWithoutSodiumTheWorkerRefusesToCapture(): void
    {
        $this->appEnv();
        $this->shipperOnce();
        $probe = tempnam(sys_get_temp_dir(), 'ttprobe');
        file_put_contents($probe, '<?php require ' . var_export(__DIR__ . '/../../src/autoload.php', true) . '; echo (new TrafficTwin\Runtime(TrafficTwin\Config::fromEnv()))->state();');
        [, $normal] = Proc::run([PHP_BINARY, $probe], $this->env());
        [, $blocked] = Proc::run([PHP_BINARY, '-d', 'disable_functions=sodium_crypto_sign_verify_detached', $probe], $this->env());
        unlink($probe);
        self::assertSame('capturing', $normal);
        self::assertSame('sodium_missing', $blocked);
    }
}
