<?php

declare(strict_types=1);

namespace TrafficTwin\Tests\Unit;

use PHPUnit\Framework\TestCase;
use TrafficTwin\Capture\Counters;
use TrafficTwin\Capture\Spool;
use TrafficTwin\State\Store;
use TrafficTwin\Tests\Support\Fixture;

final class SpoolTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/tt-spool-' . bin2hex(random_bytes(4));
    }

    protected function tearDown(): void
    {
        Fixture::rmrf($this->dir);
    }

    public function testFilesAreOwnerOnly(): void
    {
        $s = new Spool($this->dir . '/spool');
        self::assertTrue($s->append('1' . "\t-\t-\tsha256:x\t{}"));
        self::assertSame('0700', substr(sprintf('%o', fileperms($this->dir . '/spool')), -4));
        foreach (glob($this->dir . '/spool/seg-*') ?: [] as $f) {
            self::assertSame('0600', substr(sprintf('%o', fileperms($f)), -4));
        }
    }

    public function testStateStoreWritesAtomicallyWithPrivateModes(): void
    {
        $st = new Store($this->dir . '/state');
        self::assertTrue($st->writeJson('status.json', ['a' => 1]));
        self::assertSame('0600', substr(sprintf('%o', fileperms($this->dir . '/state/status.json')), -4));
        self::assertSame('0700', substr(sprintf('%o', fileperms($this->dir . '/state')), -4));
        self::assertSame(['a' => 1], $st->readJson('status.json'));
        self::assertSame([], glob($this->dir . '/state/.*.tmp') ?: []);
    }

    public function testConcurrentWritersAndAClaimingShipperLoseNothing(): void
    {
        $dir = $this->dir . '/spool';
        $script = tempnam(sys_get_temp_dir(), 'ttw');
        file_put_contents($script, '<?php require ' . var_export(__DIR__ . '/../../src/autoload.php', true) . ';'
            . '$s = new TrafficTwin\Capture\Spool($argv[1], 1);'
            . 'for ($i = 0; $i < 300; $i++) { $s->append($argv[2] . "-" . $i . "\t" . str_repeat("x", 200)); if ($i % 50 === 0) usleep(300000); }');
        $procs = [];
        foreach (range(1, 4) as $w) {
            $procs[] = proc_open([PHP_BINARY, $script, $dir, "w$w"], [1 => ['file', '/dev/null', 'w']], $pipes);
        }
        // The "shipper": keeps claiming closed segments while the writers run.
        $seen = [];
        $spool = new Spool($dir, 1);
        $deadline = microtime(true) + 60;
        $running = true;
        while ($running && microtime(true) < $deadline) {
            $running = false;
            foreach ($procs as $p) {
                $running = $running || proc_get_status($p)['running'];
            }
            foreach ($spool->closedSegments() as $seg) {
                $c = $spool->claim($seg);
                if ($c === null) {
                    continue;
                }
                foreach (file($c, FILE_IGNORE_NEW_LINES) as $line) {
                    $seen[] = explode("\t", $line)[0];
                }
                unlink($c);
            }
            usleep(100000);
        }
        foreach ($procs as $p) {
            proc_close($p);
        }
        sleep(2);
        foreach (glob($dir . '/seg-*') ?: [] as $f) {
            $c = $spool->claim($f) ?? $f;
            foreach (file($c, FILE_IGNORE_NEW_LINES) as $line) {
                $seen[] = explode("\t", $line)[0];
            }
            unlink($c);
        }
        unlink($script);
        self::assertCount(1200, $seen, 'no event lost');
        self::assertCount(1200, array_unique($seen), 'no event duplicated or torn');
    }

    public function testCountersAreSummedAcrossWorkersAndCompacted(): void
    {
        $store = new Store($this->dir);
        $a = new Counters($store, 0.0);
        $b = new Counters($store, 0.0);
        $a->seen();
        $a->seen();
        $a->sampled();
        $b->seen();
        $b->dropped(3);
        $b->sanitizerError();
        $b->overhead(120);
        $b->error('spool_write_failed');
        $a->flush(true);
        $b->flush(true);
        $agg = Counters::aggregate($store);
        self::assertSame(3, $agg['seen']);
        self::assertSame(1, $agg['sampled']);
        self::assertSame(3, $agg['dropped']);
        self::assertSame(1, $agg['sanitizer_errors']);
        self::assertSame([120], $agg['ov']);
        self::assertSame('spool_write_failed', $agg['errors'][0]['code']);
        // Old files are folded into base.json without changing the totals.
        foreach (glob($this->dir . '/counters/*.json') ?: [] as $f) {
            touch($f, time() - 7200);
        }
        $agg = Counters::aggregate($store);
        self::assertSame(3, $agg['seen']);
        self::assertSame(['base.json'], array_map('basename', glob($this->dir . '/counters/*.json') ?: []));
        self::assertSame(3, Counters::aggregate($store)['seen']);
    }
}
