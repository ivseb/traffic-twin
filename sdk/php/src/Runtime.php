<?php

declare(strict_types=1);

namespace TrafficTwin;

use TrafficTwin\Capture\Counters;
use TrafficTwin\Capture\EventBuilder;
use TrafficTwin\Capture\Pending;
use TrafficTwin\Capture\Spool;
use TrafficTwin\Sanitizer\Envelope;
use TrafficTwin\Sanitizer\Json;
use TrafficTwin\Sanitizer\JsonError;
use TrafficTwin\Sanitizer\KeyRing;
use TrafficTwin\Sanitizer\Policy;
use TrafficTwin\Sanitizer\Refused;
use TrafficTwin\Sanitizer\Sanitizer;
use TrafficTwin\Sanitizer\Utf8;
use TrafficTwin\State\Store;

/**
 * The capture side of the SDK inside a PHP process (worker). It never talks to the network.
 *
 * State comes from the files the shipper (bin/tt-shipper) maintains in the state directory:
 * `status.json` (kill switch, revocation, last contact with tt-core, pinned policy signing
 * keys, minimum issued_seq) and `policy.envelope.json` (the signed policy exactly as received).
 * Every process re-verifies the policy itself (signature, schema, group, expiry,
 * min_issued_seq) and reads the HMAC key from its own environment. Anything missing or
 * doubtful means "do not capture" (policy.md 4). The decision is memoized for one second in
 * processes that live longer than a request (CLI workers, RoadRunner, Swoole, FrankenPHP worker
 * mode); a short-lived PHP-FPM request pays for it once.
 *
 * Sanitized events are appended to the spool; a finished exchange is sanitized after the
 * response has been sent where the SAPI allows it (see $deferMode).
 */
final class Runtime
{
    private const PENDING_MAX = 2000;
    private const PENDING_MAX_BYTES = 64 << 20;
    private const GATE_TTL_NS = 1_000_000_000;

    private static ?self $instance = null;

    public readonly Config $config;
    public readonly Counters $counters;
    public readonly ?Store $store;
    private ?Spool $spool = null;

    /**
     * When finished exchanges are sanitized: 'shutdown' (a shutdown function, after
     * fastcgi_finish_request() when available; the default under FPM, Apache, litespeed and the
     * CLI server), 'now' (inside the middleware; the default for long-running CLI workers) or
     * 'manual' (queued until the worker loop calls processPending() after sending the response,
     * for RoadRunner/FrankenPHP/Swoole style loops).
     */
    public string $deferMode;
    /** Call fastcgi_finish_request() before the deferred work, when the SAPI provides it. */
    public bool $finishRequest = true;

    private ?Sanitizer $san = null;
    private string $reason = 'starting';
    private int $checkedNs = 0;
    private int $validUntilMs = 0;
    /** @var array<string, mixed>|null */
    private ?array $status = null;
    /** @var array<string, array{0: Policy, 1: array<string, string>}> */
    private array $policyMemo = [];
    /** @var list<Pending> */
    private array $pending = [];
    private int $pendingBytes = 0;
    private bool $shutdownRegistered = false;
    private bool $sodiumReported = false;
    /** @var array<string, true> */
    private array $decisionNames = ['baggage' => true, 'cookie' => true];
    private ?Sanitizer $lastSan = null;

    public function __construct(Config $config)
    {
        $this->config = $config;
        $this->store = $config->stateDir !== null ? new Store($config->stateDir) : null;
        $this->counters = new Counters($this->store);
        $p = $config->spoolPath();
        $this->spool = $p !== null ? new Spool($p, $config->spoolSegmentSeconds) : null;
        $this->deferMode = in_array(PHP_SAPI, ['fpm-fcgi', 'cgi-fcgi', 'apache2handler', 'apache2filter', 'litespeed', 'cli-server', 'phpdbg'], true)
            ? 'shutdown' : 'now';
    }

    public static function get(): self
    {
        return self::$instance ??= new self(Config::fromEnv());
    }

    /** Replaces the process-wide instance (tests, explicit configuration). */
    public static function set(?self $r): void
    {
        self::$instance = $r;
    }

    // --- gate --------------------------------------------------------------------------

    /** The sanitizer while capture is allowed, else null (the fast path of every request). */
    public function sanitizer(): ?Sanitizer
    {
        $now = hrtime(true);
        if ($this->checkedNs !== 0 && $now - $this->checkedNs < self::GATE_TTL_NS) {
            if ($this->san !== null && (int) (microtime(true) * 1000) >= $this->validUntilMs) {
                $this->san = null;
                $this->reason = 'expired_policy';
            }
            return $this->san;
        }
        $this->checkedNs = $now;
        $this->san = $this->evaluate();
        return $this->san;
    }

    /** Why capture is (not) active: capturing, disabled, not_configured, sodium_missing, no_status, killed, starting, ... */
    public function state(): string
    {
        $this->sanitizer();
        return $this->san !== null ? 'capturing' : $this->reason;
    }

    private function evaluate(): ?Sanitizer
    {
        $c = $this->config;
        if ($c->disabled) {
            $this->reason = 'disabled';
            return null;
        }
        if ($this->store === null) {
            $this->reason = 'not_configured';
            return null;
        }
        if (!Envelope::sodiumAvailable()) {
            // Fail closed: policies cannot be verified without Ed25519.
            if (!$this->sodiumReported) {
                $this->sodiumReported = true;
                $this->counters->error('sodium_missing');
            }
            $this->reason = 'sodium_missing';
            return null;
        }
        $st = $this->store->readJson('status.json');
        if ($st === null) {
            $this->reason = 'no_status';
            return null;
        }
        $this->status = $st;
        if (($st['kill'] ?? false) === true || ($st['revoked'] ?? false) === true) {
            $this->reason = 'killed';
            return null;
        }
        if (($st['heartbeat_ok'] ?? false) !== true) {
            $this->reason = 'starting';
            return null;
        }
        $maxAgeMs = max(1, (int) ($st['policy_max_age_s'] ?? 86400)) * 1000;
        $lastMs = (int) ($st['last_contact'] ?? 0) * 1000;
        $nowMs = (int) (microtime(true) * 1000);
        if ($lastMs <= 0 || $nowMs - $lastMs > $maxAgeMs) {
            $this->reason = 'expired_policy';
            return null;
        }
        $envText = $this->store->readText('policy.envelope.json');
        if ($envText === null) {
            $this->reason = 'no_policy';
            return null;
        }
        /** @var array<string, string> $pinned */
        $pinned = [];
        foreach ((array) ($st['signing_keys'] ?? []) as $kid => $pub) {
            $raw = is_string($pub) ? Envelope::publicKey($pub) : null;
            if ($raw !== null) {
                $pinned[(string) $kid] = $raw;
            }
        }
        $min = (int) ($st['min_issued_seq'] ?? 0);
        try {
            $policy = $this->policyFor($envText, $pinned, $min, (string) ($st['group'] ?? ''), $nowMs);
            $text = $c->hmacKey;
            if ($text === null && $c->hmacKeyFile !== null) {
                $t = @file_get_contents($c->hmacKeyFile);
                $text = $t === false ? null : $t;
            }
            $key = KeyRing::parse($text)->select($policy);
        } catch (Refused $e) {
            $this->reason = $e->reason;
            return null;
        } catch (\Throwable) {
            $this->reason = 'policy_rejected';
            return null;
        }
        $over = $st['override_bp'] ?? null;
        $over = is_int($over) && $over >= 0 && $over <= 10000 ? $over : null;
        $cur = $this->lastSan;
        if ($cur === null || $cur->policy !== $policy || $cur->key !== $key || $cur->rateOverrideBp !== $over) {
            $cur = new Sanitizer($policy, $key, $over);
            $this->lastSan = $cur;
        }
        $names = ['baggage' => true, 'cookie' => true];
        if ($policy->subject !== null && $policy->subject['from'] === 'header') {
            $names[Utf8::lower($policy->subject['name'])] = true;
        }
        $this->decisionNames = $names;
        $this->validUntilMs = min($policy->notAfter ?? 0, $lastMs + $maxAgeMs);
        $this->reason = 'capturing';
        return $cur;
    }

    /**
     * @param array<string, string> $pinned
     * @throws Refused
     */
    private function policyFor(string $envText, array $pinned, int $min, string $group, int $nowMs): Policy
    {
        $memoKey = hash('sha256', $envText . "\0" . json_encode($pinned) . "\0" . $group);
        $policy = $this->policyMemo[$memoKey][0] ?? null;
        if ($policy === null) {
            try {
                $env = Json::toPlain(Json::parse($envText, 16), true);
            } catch (JsonError) {
                throw new Refused('policy_rejected', 'envelope json');
            }
            $v = Envelope::verify($env, $pinned, true);
            $policy = new Policy($v['body']);
            $policy->hash = $v['hash'];
            $this->policyMemo = [$memoKey => [$policy, $pinned]];
        }
        // Group, expiry and min_issued_seq are re-checked on every evaluation. The strict
        // replay check (issued_seq > last accepted) belongs to the shipper, which owns the history.
        Envelope::checkAcceptance($policy, $group, $nowMs, 0, $min, true);
        return $policy;
    }

    /** Assigned service name (the `service` of inbound events). */
    public function serviceName(): string
    {
        $this->sanitizer();
        return (string) ($this->status['service_name'] ?? '');
    }

    public function sourceId(): string
    {
        $this->sanitizer();
        return (string) ($this->status['source_id'] ?? '');
    }

    /** @return array<string, true> header names (lowercase) needed for the inbound sampling decision */
    public function decisionHeaders(): array
    {
        return $this->decisionNames;
    }

    /** Whether tt.s may be added to the baggage of a call to this url base (sanitizer.md 12, D-M8). */
    public function mayPropagate(string $urlBase): bool
    {
        $san = $this->sanitizer();
        if ($san === null || $san->policy->propagateTo === []) {
            return false;
        }
        $u = \TrafficTwin\Sanitizer\Run::normalizeUrlBase($urlBase);
        if ($u['invalid'] || $u['ip6'] !== null) {
            return false;
        }
        $host = preg_replace('/:[0-9]+$/', '', $u['hostport']) ?? $u['hostport'];
        $p = $san->policy;
        if (isset($p->baseHosts[$u['hostport']]) || isset($p->baseHosts[$host])) {
            return false;
        }
        return isset($p->propagateTo[$u['hostport']]) || isset($p->propagateTo[$host]);
    }

    // --- queue ---------------------------------------------------------------------------

    public function enqueue(Pending $p): void
    {
        if ($this->san === null || count($this->pending) >= self::PENDING_MAX || $this->pendingBytes + $p->heldBytes > self::PENDING_MAX_BYTES) {
            $this->counters->dropped();
            return;
        }
        $this->pending[] = $p;
        $this->pendingBytes += $p->heldBytes;
        if ($this->deferMode === 'now') {
            $this->processPending();
            return;
        }
        if ($this->deferMode === 'manual') {
            return; // the integrator calls processPending() after sending the response
        }
        if (!$this->shutdownRegistered) {
            $this->shutdownRegistered = true;
            register_shutdown_function([$this, 'onShutdown']);
        }
    }

    /** Shutdown hook: finish the HTTP response first when the SAPI can, then sanitize and spool. */
    public function onShutdown(): void
    {
        $this->shutdownRegistered = false;
        if ($this->finishRequest && function_exists('fastcgi_finish_request')) {
            @fastcgi_finish_request();
        }
        $this->processPending();
        $this->counters->flush(true);
    }

    /** Sanitizes and spools what is pending. Never throws. */
    public function processPending(): void
    {
        if ($this->pending !== [] && $this->sanitizer() === null) {
            // The gate closed (kill switch, revocation, expiry) while exchanges were waiting: drop them.
            $this->counters->dropped(count($this->pending));
            $this->pending = [];
        }
        while ($this->pending !== []) {
            $p = array_shift($this->pending);
            $this->pendingBytes -= $p->heldBytes;
            $this->process($p);
        }
        $this->pendingBytes = 0;
        $this->counters->flush();
    }

    private function process(Pending $p): void
    {
        try {
            $r = $p->san->run(($p->build)(), (int) (microtime(true) * 1000), $p->decision);
            if ($r->outcome === 'not_sampled') {
                return;
            }
            if ($r->outcome === 'too_large') {
                $this->counters->sanitizerError();
                $this->counters->error('event_too_large');
                return;
            }
            $policy = $p->san->policy;
            $json = EventBuilder::build($r->parts, $policy, $this->sourceId(), $p->dir, $p->tsMs, $p->latencyMs, $p->status, $p->netError, $p->traceId, $p->spanId, $p->parentSpanId);
            if ($json === null) {
                $this->counters->sanitizerError();
                $this->counters->error('event_invalid_or_too_large');
                return;
            }
            if ($this->spool === null || !$this->spool->append(EventBuilder::spoolLine($json, $p->tsMs, $p->traceId, $p->spanId, $policy->hash))) {
                $this->counters->dropped();
                $this->counters->error('spool_write_failed');
            }
        } catch (\Throwable) {
            // sanitizer.md 0: an internal error never produces an event.
            $this->counters->sanitizerError();
            $this->counters->error('sanitizer_error');
        }
    }

    /** Drops what is pending without sanitizing it (benchmarks measure the request path alone). */
    public function discardPending(): void
    {
        $this->pending = [];
        $this->pendingBytes = 0;
    }

    /** Test hook: forget the memoized gate decision. */
    public function reset(): void
    {
        $this->checkedNs = 0;
        $this->san = null;
        $this->lastSan = null;
        $this->policyMemo = [];
    }
}
