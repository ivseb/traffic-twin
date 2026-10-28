<?php

declare(strict_types=1);

namespace TrafficTwin\Tests\Support;

/** Starts tests/support/fake-core.php and drives it through control.json. */
final class FakeCore
{
    public string $dir;
    private Proc $proc;
    /** @var array<string, mixed> */
    public array $info;
    /** @var array<string, mixed> */
    private array $control = [];

    public function __construct()
    {
        $this->dir = sys_get_temp_dir() . '/tt-fakecore-' . bin2hex(random_bytes(4));
        mkdir($this->dir, 0700, true);
        $this->proc = new Proc([PHP_BINARY, __DIR__ . '/../support/fake-core.php', $this->dir]);
        $t0 = microtime(true);
        while (!is_file($this->dir . '/info.json')) {
            if (microtime(true) - $t0 > 20 || !$this->proc->running()) {
                throw new \RuntimeException('fake core did not start: ' . $this->proc->output());
            }
            usleep(50000);
        }
        $this->info = json_decode((string) file_get_contents($this->dir . '/info.json'), true);
    }

    public function stop(): void
    {
        $this->proc->terminate();
        usleep(200000);
        $this->proc->kill();
        Fixture::rmrf($this->dir);
    }

    public function enrollUrl(): string
    {
        return 'https://localhost:' . $this->info['enroll_port'];
    }

    public function token(): string
    {
        return $this->info['token'];
    }

    /** @param array<string, mixed> $over merged over the current control document; null values remove a key */
    public function control(array $over): void
    {
        foreach ($over as $k => $v) {
            if ($v === null) {
                unset($this->control[$k]);
            } else {
                $this->control[$k] = $v;
            }
        }
        file_put_contents($this->dir . '/control.json.tmp', json_encode($this->control, JSON_UNESCAPED_SLASHES));
        rename($this->dir . '/control.json.tmp', $this->dir . '/control.json');
    }

    /** @return list<string> events received, as the canonical JSON the sources sent */
    public function events(): array
    {
        $f = $this->dir . '/events.ndjson';
        return is_file($f) ? (file($f, FILE_IGNORE_NEW_LINES) ?: []) : [];
    }

    /** @return list<array<string, mixed>> */
    public function log(): array
    {
        $f = $this->dir . '/log.ndjson';
        $out = [];
        foreach (is_file($f) ? (file($f, FILE_IGNORE_NEW_LINES) ?: []) : [] as $l) {
            $out[] = json_decode($l, true);
        }
        return $out;
    }

    public function waitEvents(int $n, float $timeoutS = 20): bool
    {
        $t0 = microtime(true);
        while (count($this->events()) < $n) {
            if (microtime(true) - $t0 > $timeoutS) {
                return false;
            }
            usleep(100000);
        }
        return true;
    }
}
