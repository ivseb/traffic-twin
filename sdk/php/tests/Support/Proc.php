<?php

declare(strict_types=1);

namespace TrafficTwin\Tests\Support;

/** A child process with output captured to a file. */
final class Proc
{
    /** @var resource */
    private $proc;
    public string $outFile;
    /** @var array<int, self> every child started by the tests, killed at exit so none outlives the run */
    private static array $all = [];
    private static bool $hooked = false;

    /** @param list<string> $cmd @param array<string, string> $env */
    public function __construct(array $cmd, array $env = [], ?string $cwd = null)
    {
        $this->outFile = tempnam(sys_get_temp_dir(), 'ttproc');
        $env = array_merge(getenv(), $env);
        $p = proc_open($cmd, [0 => ['file', '/dev/null', 'r'], 1 => ['file', $this->outFile, 'w'], 2 => ['file', $this->outFile, 'a']], $pipes, $cwd, $env);
        if (!is_resource($p)) {
            throw new \RuntimeException('cannot start ' . $cmd[0]);
        }
        $this->proc = $p;
        self::$all[spl_object_id($this)] = $this;
        if (!self::$hooked) {
            self::$hooked = true;
            register_shutdown_function([self::class, 'killAll']);
        }
    }

    public static function killAll(): void
    {
        foreach (self::$all as $p) {
            $p->kill();
        }
        self::$all = [];
    }

    public function pid(): int
    {
        return (int) proc_get_status($this->proc)['pid'];
    }

    private ?int $exit = null;

    public function running(): bool
    {
        if ($this->exit !== null) {
            return false;
        }
        $st = proc_get_status($this->proc);
        if (!$st['running']) {
            // PHP before 8.3 reports the exit code only on the first call after the exit.
            $this->exit = $st['exitcode'];
        }
        return $st['running'];
    }

    public function output(): string
    {
        return (string) @file_get_contents($this->outFile);
    }

    /** Waits for the process to end; returns its exit code (or null on timeout, after killing it). */
    public function wait(float $timeoutS = 60): ?int
    {
        $t0 = microtime(true);
        $code = null;
        while (microtime(true) - $t0 < $timeoutS) {
            if (!$this->running()) {
                $code = $this->exit;
                break;
            }
            usleep(20000);
        }
        if ($code === null) {
            $this->kill();
            return null;
        }
        proc_close($this->proc);
        @unlink($this->outFile);
        unset(self::$all[spl_object_id($this)]);
        return $code;
    }

    public function terminate(int $signal = 15): void
    {
        if ($this->running()) {
            proc_terminate($this->proc, $signal);
        }
    }

    public function kill(): void
    {
        if ($this->running()) {
            proc_terminate($this->proc, 9);
        }
        @proc_close($this->proc);
        @unlink($this->outFile);
        unset(self::$all[spl_object_id($this)]);
    }

    /** Runs a command to completion. @param list<string> $cmd @param array<string, string> $env @return array{0: int, 1: string} */
    public static function run(array $cmd, array $env = [], float $timeoutS = 60, ?string $cwd = null): array
    {
        $p = new self($cmd, $env, $cwd);
        $out = '';
        $t0 = microtime(true);
        while ($p->running() && microtime(true) - $t0 < $timeoutS) {
            usleep(20000);
        }
        $out = $p->output();
        $code = $p->wait(1);
        return [$code ?? -1, $out];
    }
}
