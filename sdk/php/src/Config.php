<?php

declare(strict_types=1);

namespace TrafficTwin;

/**
 * Configuration, read from the environment (same variable names as the Node SDK).
 *
 * With PHP-FPM, remember that `clear_env = yes` (the default) hides the process environment
 * from workers: pass the variables with `env[TT_STATE_DIR] = ...` in the pool configuration.
 */
final class Config
{
    public bool $disabled = false;
    public bool $debug = false;
    /** Where certificates, the policy cache, the kill switch and the spool live. Required: without it the SDK stays inert. */
    public ?string $stateDir = null;
    public ?string $spoolDir = null;
    public ?string $hmacKey = null;
    public ?string $hmacKeyFile = null;
    public ?string $enrollUrl = null;
    public ?string $enrollToken = null;
    public ?string $serviceName = null;
    public ?string $instance = null;
    /** Send a CSR at enrollment so the private key never leaves the host. */
    public bool $useCsr = true;
    /** Spool size above which the shipper drops the oldest segments. */
    public int $spoolMaxBytes = 67108864;
    /** Shipper timings (milliseconds); null = the values received from tt-core. */
    public ?int $heartbeatIntervalMs = null;
    public ?int $policyPollIntervalMs = null;
    public ?int $exportFlushMs = null;
    /** Seconds per spool segment file. */
    public int $spoolSegmentSeconds = 2;

    /** @param array<string, string>|null $env defaults to the process environment */
    public static function fromEnv(?array $env = null): self
    {
        $get = static function (string $k) use ($env): ?string {
            if ($env !== null) {
                $v = $env[$k] ?? null;
            } else {
                $g = getenv($k);
                $v = $g !== false ? $g : ($_SERVER[$k] ?? $_ENV[$k] ?? null);
            }
            return is_string($v) && $v !== '' ? $v : null;
        };
        $c = new self();
        $c->disabled = $get('TT_DISABLED') === '1';
        $c->debug = preg_match('/^(1|true|yes|debug)$/i', $get('TT_DEBUG') ?? '') === 1;
        $c->stateDir = $get('TT_STATE_DIR');
        $c->spoolDir = $get('TT_SPOOL_DIR');
        $c->hmacKey = $get('TT_HMAC_KEY');
        $c->hmacKeyFile = $get('TT_HMAC_KEY_FILE');
        $c->enrollUrl = $get('TT_ENROLL_URL');
        $c->enrollToken = $get('TT_ENROLL_TOKEN');
        $c->serviceName = self::serviceName($get('TT_SERVICE_NAME') ?? $get('OTEL_SERVICE_NAME'));
        $c->instance = $get('TT_INSTANCE');
        $c->useCsr = $get('TT_ENROLL_CSR') !== '0';
        $ms = static fn (?string $v): ?int => $v !== null && preg_match('/^[0-9]{1,9}$/D', $v) === 1 ? max(100, (int) $v) : null;
        $c->heartbeatIntervalMs = $ms($get('TT_HEARTBEAT_INTERVAL_MS'));
        $c->policyPollIntervalMs = $ms($get('TT_POLICY_POLL_INTERVAL_MS'));
        $c->exportFlushMs = $ms($get('TT_EXPORT_FLUSH_MS'));
        $max = $get('TT_SPOOL_MAX_BYTES');
        if ($max !== null && preg_match('/^[0-9]{1,12}$/D', $max) === 1) {
            $c->spoolMaxBytes = max(1048576, (int) $max);
        }
        return $c;
    }

    /** Service name requested at enrollment: lowercase, [a-z0-9._-], at most 63 characters. */
    public static function serviceName(?string $raw): ?string
    {
        if ($raw === null) {
            return null;
        }
        $s = strtolower($raw);
        $s = preg_replace('/[^a-z0-9._-]/', '-', $s) ?? '';
        $s = preg_replace('/^[^a-z0-9]+/', '', $s) ?? '';
        $s = substr($s, 0, 63);
        return preg_match('/^[a-z0-9][a-z0-9._-]{0,62}$/D', $s) === 1 ? $s : null;
    }

    public function spoolPath(): ?string
    {
        if ($this->spoolDir !== null) {
            return $this->spoolDir;
        }
        return $this->stateDir !== null ? $this->stateDir . '/spool' : null;
    }
}
