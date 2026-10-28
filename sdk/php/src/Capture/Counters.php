<?php

declare(strict_types=1);

namespace TrafficTwin\Capture;

use TrafficTwin\State\Store;

/**
 * Counters for the heartbeat (fleet-api Heartbeat.counters). PHP workers do not share memory,
 * so each worker keeps its own monotonic counters and, every couple of seconds (and when it
 * writes an event), writes them to `counters/<pid>-<token>.json` in the state directory. The
 * shipper sums the files. The numbers are therefore approximate: a worker that goes idle can
 * hold back up to its last interval until the next request.
 */
final class Counters
{
    public int $exchangesSeen = 0;
    public int $exchangesSampled = 0;
    public int $eventsDroppedQueue = 0;
    public int $sanitizerErrors = 0;
    /** @var list<int> last overhead samples, microseconds */
    private array $overhead = [];
    /** @var list<array{code: string, at: string}> */
    private array $errors = [];
    private bool $dirty = false;
    private float $lastFlush = 0.0;
    private string $file;
    private bool $dirChecked = false;

    public function __construct(private ?Store $store, private float $flushEverySeconds = 2.0)
    {
        $this->file = 'counters/' . getmypid() . '-' . bin2hex(random_bytes(3)) . '.json';
    }

    public function seen(): void
    {
        $this->exchangesSeen++;
        $this->dirty = true;
    }

    public function sampled(): void
    {
        $this->exchangesSampled++;
        $this->dirty = true;
    }

    public function dropped(int $n = 1): void
    {
        $this->eventsDroppedQueue += $n;
        $this->dirty = true;
    }

    public function sanitizerError(): void
    {
        $this->sanitizerErrors++;
        $this->dirty = true;
    }

    public function overhead(int $micros): void
    {
        $this->overhead[] = $micros;
        if (count($this->overhead) > 128) {
            array_shift($this->overhead);
        }
        $this->dirty = true;
    }

    /** Error code only; never payload values. */
    public function error(string $code): void
    {
        $this->errors[] = ['code' => substr($code, 0, 64), 'at' => gmdate('Y-m-d\TH:i:s\Z')];
        if (count($this->errors) > 20) {
            array_shift($this->errors);
        }
        $this->dirty = true;
    }

    /** Writes the counters if something changed and the interval elapsed (or $force). */
    public function flush(bool $force = false): void
    {
        if ($this->store === null || !$this->dirty) {
            return;
        }
        $now = microtime(true);
        if (!$force && $now - $this->lastFlush < $this->flushEverySeconds) {
            return;
        }
        if (!$this->dirChecked) {
            if (!$this->store->ensure() || !Store::secureDir($this->store->path('counters'))) {
                return;
            }
            $this->dirChecked = true;
        }
        $this->lastFlush = $now;
        $this->dirty = false;
        $this->store->writeJson($this->file, [
            'seen' => $this->exchangesSeen,
            'sampled' => $this->exchangesSampled,
            'dropped' => $this->eventsDroppedQueue,
            'sanitizer_errors' => $this->sanitizerErrors,
            'ov' => $this->overhead,
            'errors' => $this->errors,
        ]);
    }

    /**
     * Sums the worker files (shipper side). Files untouched for an hour are folded into
     * counters/base.json so the directory does not grow with pid churn.
     *
     * @return array{seen: int, sampled: int, dropped: int, sanitizer_errors: int, ov: list<int>, errors: list<array{code: string, at: string}>}
     */
    public static function aggregate(Store $store, bool $compact = true): array
    {
        $sum = ['seen' => 0, 'sampled' => 0, 'dropped' => 0, 'sanitizer_errors' => 0, 'ov' => [], 'errors' => []];
        $dir = $store->path('counters');
        $now = time();
        foreach (glob($dir . '/*.json') ?: [] as $f) {
            $raw = @file_get_contents($f);
            $j = $raw !== false ? json_decode($raw, true) : null;
            if (!is_array($j)) {
                continue;
            }
            foreach (['seen', 'sampled', 'dropped', 'sanitizer_errors'] as $k) {
                $sum[$k] += (int) ($j[$k] ?? 0);
            }
            $mtime = @filemtime($f) ?: $now;
            if ($now - $mtime < 300) {
                foreach ((array) ($j['ov'] ?? []) as $x) {
                    $sum['ov'][] = (int) $x;
                }
            }
            foreach ((array) ($j['errors'] ?? []) as $e) {
                if (is_array($e) && isset($e['code'], $e['at'])) {
                    $sum['errors'][] = ['code' => (string) $e['code'], 'at' => (string) $e['at']];
                }
            }
        }
        if ($compact) {
            self::compact($dir, $now);
        }
        usort($sum['errors'], static fn (array $a, array $b): int => strcmp($a['at'], $b['at']));
        $sum['errors'] = array_slice($sum['errors'], -20);
        return $sum;
    }

    private static function compact(string $dir, int $now): void
    {
        $base = ['seen' => 0, 'sampled' => 0, 'dropped' => 0, 'sanitizer_errors' => 0];
        $old = [];
        foreach (glob($dir . '/*.json') ?: [] as $f) {
            if (basename($f) === 'base.json' || ($now - (@filemtime($f) ?: $now)) < 3600) {
                continue;
            }
            $old[] = $f;
        }
        if ($old === []) {
            return;
        }
        $bf = $dir . '/base.json';
        $cur = @json_decode((string) @file_get_contents($bf), true);
        if (is_array($cur)) {
            foreach ($base as $k => $_) {
                $base[$k] = (int) ($cur[$k] ?? 0);
            }
        }
        foreach ($old as $f) {
            $j = @json_decode((string) @file_get_contents($f), true);
            if (is_array($j)) {
                foreach ($base as $k => $_) {
                    $base[$k] += (int) ($j[$k] ?? 0);
                }
            }
        }
        $tmp = $bf . '.tmp';
        if (@file_put_contents($tmp, json_encode($base)) !== false && @rename($tmp, $bf)) {
            foreach ($old as $f) {
                @unlink($f);
            }
        }
    }
}
