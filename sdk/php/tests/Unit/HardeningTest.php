<?php

declare(strict_types=1);

namespace TrafficTwin\Tests\Unit;

use PHPUnit\Framework\TestCase;
use TrafficTwin\Capture\Spool;
use TrafficTwin\Shipper\FleetError;
use TrafficTwin\Shipper\Http;
use TrafficTwin\State\Store;
use TrafficTwin\Tests\Support\Fixture;

/** Red team round 2: RT-PHP-2 (gzip cap) and RT-PHP-3 (pre-existing loose directories). */
final class HardeningTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/tt-hard-' . bin2hex(random_bytes(4));
    }

    protected function tearDown(): void
    {
        Fixture::rmrf($this->dir);
    }

    public function testGunzipWithinCap(): void
    {
        self::assertSame('{"a":1}', Http::gunzip((string) gzencode('{"a":1}'), 100));
    }

    public function testGunzipRefusesBombAfterDecompression(): void
    {
        $bomb = (string) gzencode('{' . str_repeat(' ', 4 << 20) . '}', 9);
        self::assertLessThan(64 << 10, strlen($bomb));
        $this->expectException(FleetError::class);
        $this->expectExceptionMessage('response_too_large');
        Http::gunzip($bomb, 1 << 20);
    }

    public function testGunzipRefusesGarbage(): void
    {
        $this->expectException(FleetError::class);
        Http::gunzip('not gzip at all', 1 << 20);
    }

    public function testPreExistingLooseDirectoriesAreNarrowed(): void
    {
        mkdir($this->dir, 0777);
        chmod($this->dir, 0777);
        mkdir($this->dir . '/spool', 0777);
        chmod($this->dir . '/spool', 0777);
        $st = new Store($this->dir);
        self::assertTrue($st->writeJson('status.json', ['kill' => false]));
        self::assertTrue((new Spool($this->dir . '/spool'))->append("0\t-\t-\tsha256:x\t{}"));
        clearstatcache();
        self::assertSame(0700, fileperms($this->dir) & 0777);
        self::assertSame(0700, fileperms($this->dir . '/spool') & 0777);
        self::assertSame(0600, fileperms($this->dir . '/status.json') & 0777);
    }

    public function testRequestNeedsTrustAnchor(): void
    {
        $this->expectException(FleetError::class);
        $this->expectExceptionMessage('tls_no_trust_anchor');
        Http::request('GET', 'https://localhost:1/x', [], null, ['cafile' => $this->dir . '/missing.pem'], 1);
    }
}
