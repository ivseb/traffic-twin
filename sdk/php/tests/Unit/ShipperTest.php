<?php

declare(strict_types=1);

namespace TrafficTwin\Tests\Unit;

use PHPUnit\Framework\TestCase;
use TrafficTwin\Shipper\Shipper;
use TrafficTwin\Tests\Support\Fixture;

final class ShipperTest extends TestCase
{
    /** An enrolled state whose tt-core does not answer: nothing but the local files matters. */
    private function enrolledFixture(bool $heartbeatOk): Fixture
    {
        $f = new Fixture();
        $f->status['heartbeat_ok'] = $heartbeatOk;
        $f->write();
        $port = (function (): int {
            $s = stream_socket_server('tcp://127.0.0.1:0');
            $p = (int) substr((string) strrchr((string) stream_socket_get_name($s, false), ':'), 1);
            fclose($s);
            return $p;
        })();
        file_put_contents($f->dir . '/enrollment.json', json_encode([
            'source_id' => 'src-test0001', 'group' => 'shop', 'service_name' => 'shop-api',
            'client_cert' => "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", 'ca_chain' => "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
            'policy_signing_keys' => [['kid' => Fixture::KID, 'alg' => 'Ed25519', 'public_key' => $f->public]],
            'intake_url' => "https://localhost:$port/v1/logs", 'fleet_url' => "https://localhost:$port",
            'policy_max_age_s' => 86400, 'heartbeat_interval_s' => 30, 'policy_poll_interval_s' => 60,
            'enroll_url' => 'https://core.example:4318', 'pin' => 'x',
        ]));
        file_put_contents($f->dir . '/client.key', 'key');
        return $f;
    }

    private function shipper(Fixture $f): Shipper
    {
        $c = $f->config();
        $c->enrollUrl = 'https://core.example:4318';
        $c->enrollToken = 'tte_x';
        $c->serviceName = 'shop-api';
        return new Shipper($c);
    }

    public function testALongRunningShipperDoesNotCaptureUntilItsFirstHeartbeat(): void
    {
        $f = $this->enrolledFixture(true);
        $s = $this->shipper($f);
        $s->init();
        $st = json_decode((string) file_get_contents($f->dir . '/status.json'), true);
        self::assertFalse($st['heartbeat_ok'], 'policy.md 4: heartbeat before the first capture, after every start');
        self::assertSame('starting', $s->state());
    }

    public function testCronRunsKeepTheKnowledgeOfTheLastHeartbeat(): void
    {
        $f = $this->enrolledFixture(true);
        $before = $f->status['last_contact'];
        $s = $this->shipper($f);
        $s->runOnce(); // tt-core does not answer: the heartbeat fails
        $st = json_decode((string) file_get_contents($f->dir . '/status.json'), true);
        self::assertTrue($st['heartbeat_ok']);
        self::assertSame($before, $st['last_contact'], 'no new contact: the clock toward policy_max_age keeps running');
        self::assertFalse($st['kill']);
    }

    public function testCronRunWithoutAPreviousHeartbeatStaysClosed(): void
    {
        $f = $this->enrolledFixture(false);
        $s = $this->shipper($f);
        $s->runOnce();
        $st = json_decode((string) file_get_contents($f->dir . '/status.json'), true);
        self::assertFalse($st['heartbeat_ok']);
    }

    public function testPersistedKillStaysAcrossRuns(): void
    {
        $f = $this->enrolledFixture(true);
        file_put_contents($f->dir . '/state.json', json_encode(['kill' => true, 'last_issued_seq' => 1]));
        $s = $this->shipper($f);
        $s->runOnce();
        $st = json_decode((string) file_get_contents($f->dir . '/status.json'), true);
        self::assertTrue($st['kill']);
        self::assertSame('killed', $st['state']);
        self::assertNull($f->runtime()->sanitizer());
    }

    public function testRecordParsing(): void
    {
        self::assertSame(['ts' => 5, 'trace' => null, 'span' => null, 'hash' => 'sha256:x', 'json' => '{"a":1}'], Shipper::parseRecord("5\t-\t-\tsha256:x\t{\"a\":1}"));
        self::assertNull(Shipper::parseRecord("x\t-\t-\tsha256:x\t{}"));
        self::assertNull(Shipper::parseRecord("5\t-\t-\tbad\t{}"));
        self::assertNull(Shipper::parseRecord("5\t-\t-\tsha256:x\tnot json"));
        self::assertNull(Shipper::parseRecord('garbage'));
    }
}
