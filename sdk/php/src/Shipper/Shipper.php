<?php

declare(strict_types=1);

namespace TrafficTwin\Shipper;

use TrafficTwin\Capture\Counters;
use TrafficTwin\Capture\EventBuilder;
use TrafficTwin\Capture\Spool;
use TrafficTwin\Config;
use TrafficTwin\Sanitizer\Envelope;
use TrafficTwin\Sanitizer\Json;
use TrafficTwin\Sanitizer\JsonError;
use TrafficTwin\Sanitizer\KeyRing;
use TrafficTwin\Sanitizer\Policy;
use TrafficTwin\Sanitizer\Refused;
use TrafficTwin\Sanitizer\Utf8;
use TrafficTwin\State\Store;
use TrafficTwin\Version;

/**
 * The long-running side of the SDK (`vendor/bin/tt-shipper`). PHP workers are short-lived and
 * share nothing, so everything that needs a clock, a socket or a history lives here:
 *
 *  - enrollment (token + CA pin, CSR), certificate renewal;
 *  - the heartbeat (kill switch, `min_issued_seq`, sampling override, key rotation/revocation);
 *  - the policy download, with the full acceptance checks of policy.md 4, cached as the signed
 *    envelope exactly as received;
 *  - `status.json`, the small file workers read to decide whether they may capture;
 *  - shipping the spool to the intake as OTLP/HTTP JSON over mTLS, with the retry rules of
 *    event.md 4.4.
 *
 * It never sees raw payloads: the spool only holds sanitized events. It reads the HMAC key
 * only to report `key_missing` / `key_mismatch` and the key ids at enrollment; the key never
 * leaves the host. Fail closed: with no valid policy, or no heartbeat since start, `status.json`
 * tells workers not to capture.
 */
final class Shipper
{
    private const BATCH_EVENTS = 512;
    private const BATCH_BYTES = 3_500_000;
    private const MAX_RETRIES = 5;

    public Store $store;
    private Spool $spool;
    /** @var array<string, mixed>|null */
    private ?array $enrollment = null;
    private string $keyPem = '';
    private ?Fleet $fleet = null;
    /** @var array<string, mixed> */
    private array $persisted = [];
    private ?Policy $policy = null;
    private string $policyKid = '';
    private ?string $rejected = null;
    /** A heartbeat said a newer policy is current (a normal policy change): only a failed fetch is an error. */
    private bool $switching = false;
    private bool $heartbeatOk = false;
    private int $lastContact = 0;
    private ?int $overrideBp = null;
    private ?string $etag = null;
    private ?KeyRing $ring = null;
    private string $state = 'starting';
    private bool $stopping = false;
    /** @var resource|null */
    private $lock = null;

    /** @var array<string, int> shipper-side counters */
    private array $c = ['events_sent' => 0, 'events_dropped_queue' => 0, 'events_rejected' => 0, 'send_errors' => 0];
    /** @var list<array{code: string, at: string}> */
    private array $errors = [];

    private float $nextHeartbeat = 0.0;
    private float $nextPolicy = 0.0;
    private float $nextShip = 0.0;
    private float $nextEnroll = 0.0;
    private int $enrollDelay = 2;
    private int $enrollAttempts = 0;
    private string $lastStatusJson = '';
    private float $lastStatusWrite = 0.0;

    /** @var array{file: string, fh: resource}|null segment being sent */
    private ?array $cursor = null;
    /** @var list<array{ts: int, trace: ?string, span: ?string, hash: string, json: string}> */
    private array $batch = [];
    private int $batchBytes = 0;
    private int $attempt = 0;
    private float $retryAt = 0.0;
    private bool $includeCurrent = false;
    private bool $carryOver = false;

    /** @var callable(string): void */
    private $log;

    /** @param (callable(string): void)|null $log receives short status lines (codes only) */
    public function __construct(private Config $config, ?callable $log = null)
    {
        if ($config->stateDir === null) {
            throw new \InvalidArgumentException('TT_STATE_DIR is required');
        }
        $this->store = new Store($config->stateDir);
        $this->spool = new Spool($config->spoolPath() ?? $config->stateDir . '/spool', $config->spoolSegmentSeconds);
        $this->log = $log ?? static function (string $m): void {
        };
    }

    // --- lifecycle -----------------------------------------------------------------------

    /**
     * Makes the state and spool directories private (0700; a pre-existing wider directory is
     * narrowed, or refused when this user cannot narrow it). False: do not run.
     */
    public function secureDirs(): bool
    {
        return $this->store->ensure() && Store::secureDir($this->spool->dir());
    }

    /** Takes the single-instance lock. Returns false if another shipper already runs on this state directory. */
    public function lock(): bool
    {
        if (!$this->store->ensure()) {
            return false;
        }
        $old = umask(0077);
        $fh = @fopen($this->store->path('shipper.lock'), 'cb');
        umask($old);
        if ($fh === false || !flock($fh, LOCK_EX | LOCK_NB)) {
            return false;
        }
        $this->lock = $fh;
        return true;
    }

    public function stop(): void
    {
        $this->stopping = true;
    }

    public function stopping(): bool
    {
        return $this->stopping;
    }

    /** Loads persisted state and the cached policy, and writes the first status.json (not capturing yet). */
    public function init(): void
    {
        $this->store->ensure();
        $this->persisted = $this->store->readJson('state.json') ?? [];
        $this->loadKeys();
        $this->loadEnrollment();
        if ($this->carryOver && $this->enrollment !== null) {
            // Cron-style runs (--once) are not "starts" of the source: what the last heartbeat taught
            // us (it is persisted: kill switch, min_issued_seq) still holds, and it expires with
            // policy_max_age. Otherwise capture would stop for the length of every run.
            $prev = $this->store->readJson('status.json');
            if ($prev !== null && ($prev['heartbeat_ok'] ?? false) === true && (int) ($prev['last_contact'] ?? 0) > 0) {
                $this->heartbeatOk = true;
                $this->lastContact = (int) $prev['last_contact'];
                $o = $prev['override_bp'] ?? null;
                $this->overrideBp = is_int($o) ? $o : null;
            }
        }
        // Re-verify the cached policy (its issued_seq may equal the last accepted one).
        $cached = $this->store->readText('policy.envelope.json');
        if ($cached !== null && $this->enrollment !== null) {
            $this->tryAccept($cached, true);
        }
        $this->recompute();
        $this->writeStatus(true);
    }

    /** Long-running loop. Returns when stop() was called. */
    public function run(): void
    {
        $this->init();
        while (!$this->stopping) {
            $this->tick();
            usleep(200_000);
        }
        // Last effort: send what is queued, once.
        $this->retryAt = 0.0;
        $this->ship(microtime(true) + 3.0, true);
        $this->writeStatus(true);
    }

    /** One pass: enroll if needed, heartbeat, policy, ship. For cron-style use (`--once`) and tests. */
    public function runOnce(): void
    {
        $this->carryOver = true;
        $this->init();
        $this->nextEnroll = 0.0;
        $this->nextHeartbeat = $this->nextPolicy = $this->nextShip = 0.0;
        $this->tick();
        // Events produced while the policy was being fetched, and a retry window left by tick().
        $this->nextShip = 0.0;
        $this->retryAt = 0.0;
        $this->ship(microtime(true) + 5.0, true);
        $this->recompute();
        $this->writeStatus(true);
    }

    public function tick(): void
    {
        $now = microtime(true);
        if ($this->enrollment === null) {
            if ($now >= $this->nextEnroll) {
                $this->enroll();
            }
            if ($this->enrollment === null) {
                $this->recompute();
                $this->writeStatus();
                return;
            }
            $now = microtime(true);
        }
        if ($now >= $this->nextHeartbeat) {
            $this->heartbeat();
            $this->nextHeartbeat = microtime(true) + $this->interval('heartbeat_interval_s', $this->config->heartbeatIntervalMs, 30);
        }
        if ($now >= $this->nextPolicy) {
            $this->pollPolicy();
            $this->nextPolicy = microtime(true) + $this->interval('policy_poll_interval_s', $this->config->policyPollIntervalMs, 60);
        }
        $this->recompute();
        if ($now >= $this->nextShip) {
            $this->ship($now + 0.5);
            $this->nextShip = microtime(true) + ($this->config->exportFlushMs ?? 1000) / 1000;
        }
        $this->writeStatus();
    }

    private function interval(string $key, ?int $overrideMs, int $default): float
    {
        if ($overrideMs !== null) {
            return $overrideMs / 1000;
        }
        return (float) max(5, (int) ($this->enrollment[$key] ?? $default));
    }

    // --- keys, enrollment ------------------------------------------------------------------

    private function loadKeys(): void
    {
        $text = $this->config->hmacKey;
        if ($text === null && $this->config->hmacKeyFile !== null) {
            $t = @file_get_contents($this->config->hmacKeyFile);
            $text = $t === false ? null : $t;
        }
        try {
            $this->ring = KeyRing::parse($text);
        } catch (Refused) {
            $this->ring = null;
        }
    }

    private function loadEnrollment(): void
    {
        $saved = $this->store->readJson('enrollment.json');
        $key = $this->store->readText('client.key');
        if ($saved !== null && $key !== null && ($saved['enroll_url'] ?? null) === $this->config->enrollUrl) {
            $this->enrollment = $saved;
            $this->keyPem = $key;
            $this->connect();
        }
    }

    private function enroll(): void
    {
        $c = $this->config;
        if ($c->enrollUrl === null || $c->enrollToken === null || $c->serviceName === null) {
            $this->noteError($c->enrollToken === null ? 'enroll_token_missing' : 'not_configured');
            $this->nextEnroll = microtime(true) + 30;
            return;
        }
        try {
            $r = Fleet::enroll($c->enrollUrl, $c->enrollToken, [
                'kind' => Version::SOURCE_KIND,
                'version' => Version::SDK,
                'service_name' => $c->serviceName,
                'instance' => substr($c->instance ?? (gethostname() ?: 'unknown'), 0, 128),
                'runtime' => ['lang' => 'php', 'lang_version' => PHP_VERSION, 'os' => PHP_OS_FAMILY, 'arch' => php_uname('m')],
                'hmac_kids' => $this->ring !== null ? array_slice($this->ring->order, 0, 8) : [],
            ], $c->useCsr, $this->store);
            $this->enrollment = $r['enrollment'];
            $this->keyPem = $r['keyPem'];
            $this->store->writeText('client.key', $this->keyPem);
            $this->store->writeJson('enrollment.json', $this->enrollment);
            $this->connect();
            $this->enrollAttempts = 0;
            $this->enrollDelay = 2;
            $this->nextHeartbeat = $this->nextPolicy = 0.0;
        } catch (FleetError $e) {
            $this->noteError($e->errorCode);
            // Token or identity errors will not fix themselves; retry rarely.
            $permanent = ($e->httpStatus !== null && $e->httpStatus < 500) || preg_match('/pin|root|token|chain|bad_/', $e->errorCode) === 1;
            $this->enrollAttempts++;
            $this->enrollDelay = $permanent ? 300 : min($this->enrollDelay * 2, 300);
            $this->nextEnroll = microtime(true) + $this->enrollDelay;
        } catch (\Throwable) {
            $this->noteError('enroll_failed');
            $this->nextEnroll = microtime(true) + 60;
        }
    }

    /** Writes the TLS material for streams and builds the Fleet client. */
    private function connect(): void
    {
        $e = $this->enrollment;
        if ($e === null) {
            return;
        }
        $this->store->writeText('ca.pem', (string) $e['ca_chain']);
        $this->store->writeText('client.pem', rtrim((string) $e['client_cert']) . "\n" . $this->keyPem);
        $this->fleet = new Fleet($e, $this->store->path('ca.pem'), $this->store->path('client.pem'));
    }

    /** @return array<string, string> kid => public key (base64url) of the pinned, non-revoked policy signing keys */
    private function signingKeys(): array
    {
        $revoked = array_flip((array) ($this->persisted['revoked_kids'] ?? []));
        $out = [];
        $all = array_merge((array) ($this->enrollment['policy_signing_keys'] ?? []), (array) ($this->persisted['added_keys'] ?? []));
        foreach ($all as $k) {
            if (!is_array($k) || !isset($k['kid'], $k['public_key']) || isset($revoked[$k['kid']]) || isset($out[$k['kid']])) {
                continue;
            }
            if (Envelope::publicKey((string) $k['public_key']) !== null) {
                $out[(string) $k['kid']] = (string) $k['public_key'];
            }
        }
        return $out;
    }

    // --- policy (policy.md 4) ----------------------------------------------------------------

    private function tryAccept(string $envText, bool $fromCache): void
    {
        try {
            try {
                $env = Json::toPlain(Json::parse($envText, 16), true);
            } catch (JsonError) {
                throw new Refused('policy_rejected', 'json');
            }
            $keys = [];
            foreach ($this->signingKeys() as $kid => $pub) {
                $keys[$kid] = (string) Envelope::publicKey($pub);
            }
            $v = Envelope::verify($env, $keys, true);
            $p = new Policy($v['body']);
            $p->hash = $v['hash'];
            if ($this->policy !== null && $this->policy->hash === $p->hash && !$fromCache) {
                return;
            }
            Envelope::checkAcceptance(
                $p,
                (string) ($this->enrollment['group'] ?? ''),
                (int) (microtime(true) * 1000),
                (int) ($this->persisted['last_issued_seq'] ?? 0),
                (int) ($this->persisted['min_issued_seq'] ?? 0),
                $fromCache,
            );
            if ($this->switching) {
                ($this->log)('info policy_changed: now issued_seq ' . $p->issuedSeq);
            }
            $this->switching = false;
            $this->policy = $p;
            $sig = $env instanceof \TrafficTwin\Sanitizer\PObj ? ($env->m['signature'] ?? null) : null;
            $this->policyKid = $sig instanceof \TrafficTwin\Sanitizer\PObj ? (string) ($sig->m['kid'] ?? '') : '';
            $this->rejected = null;
            $this->persisted['last_issued_seq'] = $p->issuedSeq;
            $this->persist();
            if (!$fromCache) {
                // The cache holds the signed envelope exactly as received; workers re-verify it.
                $this->store->writeText('policy.envelope.json', $envText);
            }
        } catch (Refused $e) {
            // hardening.md 2.2: a policy refused for the safety subset is reported as policy_unsafe.
            $this->noteError($e->isUnsafe() ? 'policy_unsafe' : $e->reason);
            if ($this->policy === null) {
                $this->rejected = $e->reason === 'expired_policy' ? 'expired_policy' : 'policy_rejected';
            }
        } catch (\Throwable) {
            $this->noteError('policy_rejected');
            if ($this->policy === null) {
                $this->rejected = 'policy_rejected';
            }
        }
    }

    private function dropPolicy(string $reason): void
    {
        $this->policy = null;
        $this->rejected = $reason;
        $this->etag = null;
        $this->store->remove('policy.envelope.json');
    }

    private function pollPolicy(): void
    {
        if ($this->fleet === null) {
            return;
        }
        try {
            $r = $this->fleet->getPolicy($this->policy !== null ? $this->etag : null);
            if ($r['status'] === 304) {
                $this->lastContact = time();
            } elseif ($r['status'] === 200 && $r['body'] !== null) {
                $this->lastContact = time();
                $this->tryAccept($r['body'], false);
                if ($this->policy !== null && $r['etag'] !== null) {
                    $this->etag = $r['etag'];
                }
            } elseif ($r['status'] === 404) {
                $this->lastContact = time();
                $this->dropPolicy('no_policy');
            } elseif ($r['status'] === 403) {
                $this->revoke();
            } else {
                $this->noteError('policy_http_' . $r['status']);
            }
        } catch (FleetError $e) {
            $this->noteError('policy_' . $e->errorCode);
        } catch (\Throwable) {
            $this->noteError('policy_network');
        }
        if ($this->switching && $this->policy === null) {
            // The newer policy announced by the heartbeat could not be fetched or accepted.
            $this->switching = false;
            if ($this->rejected === 'starting') {
                $this->rejected = 'policy_rejected';
                $this->noteError('policy_below_min_issued_seq');
            }
        }
    }

    // --- heartbeat ---------------------------------------------------------------------------

    private function heartbeat(): void
    {
        if ($this->fleet === null || $this->enrollment === null) {
            return;
        }
        $this->loadKeys();
        $this->recompute();
        $agg = Counters::aggregate($this->store);
        $ov = $agg['ov'];
        sort($ov);
        $n = count($ov);
        $q = static fn (float $f): int => $n === 0 ? 0 : $ov[min($n - 1, (int) floor($f * $n))];
        $sampled = $agg['sampled'];
        $body = [
            'source_id' => $this->enrollment['source_id'],
            'state' => $this->state,
            'counters' => [
                'exchanges_seen' => $agg['seen'],
                'exchanges_sampled' => $sampled,
                'events_sent' => $this->c['events_sent'],
                'events_dropped_queue' => $this->c['events_dropped_queue'] + $agg['dropped'],
                'events_rejected' => $this->c['events_rejected'],
                'send_errors' => $this->c['send_errors'],
                'sanitizer_errors' => $agg['sanitizer_errors'],
            ],
            'overhead_us' => ['p50' => $q(0.5), 'p99' => $q(0.99)],
            'queue' => ['events' => 0, 'bytes' => $this->spool->size()],
            'last_errors' => array_slice(array_merge($agg['errors'], $this->errors), -20),
            'runtime' => ['lang' => 'php', 'lang_version' => PHP_VERSION],
            // The kids of the policy signing keys trusted now: tt-core waits for them before it allows
            // revoking an old key. array_values keeps it a JSON array, also when empty.
            'signing_kids' => self::sortedKids($this->signingKeys()),
        ];
        if ($this->policy !== null) {
            $body['policy'] = ['id' => $this->policy->policyId, 'version' => $this->policy->version, 'issued_seq' => $this->policy->issuedSeq, 'hash' => $this->policy->hash];
        }
        try {
            $r = $this->fleet->heartbeat($body);
            if ($r['status'] === 403) {
                $this->revoke();
            } elseif ($r['status'] === 200 && $r['json'] !== null) {
                $this->applyHeartbeat($r['json']);
            } else {
                $this->noteError('heartbeat_http_' . $r['status']);
            }
        } catch (FleetError $e) {
            $this->noteError('heartbeat_' . $e->errorCode);
        } catch (\Throwable) {
            $this->noteError('heartbeat_network');
        }
    }

    /** @param array<string, mixed> $j */
    private function applyHeartbeat(array $j): void
    {
        $this->heartbeatOk = true;
        $this->lastContact = time();
        $kill = ($j['kill'] ?? false) === true;
        if ($kill !== (($this->persisted['kill'] ?? false) === true)) {
            $this->persisted['kill'] = $kill;
            $this->persist();
        }
        if ($kill) {
            $this->dropQueues();
        }
        $min = $j['min_issued_seq'] ?? null;
        if (is_int($min) && $min >= 0) {
            if ($min !== ($this->persisted['min_issued_seq'] ?? null)) {
                $this->persisted['min_issued_seq'] = $min;
                $this->persist();
            }
            if ($this->policy !== null && $this->policy->issuedSeq < $min) {
                $pc = $j['policy_current'] ?? null;
                $newer = is_array($pc) && is_string($pc['hash'] ?? null) && $pc['hash'] !== $this->policy->hash
                    && is_int($pc['issued_seq'] ?? null) && $pc['issued_seq'] >= $min;
                // The policy in use is superseded for good: capture stops at once (fail-closed).
                if ($newer) {
                    // A normal policy change: the newer policy is fetched right away (policy_current below).
                    $this->dropPolicy('starting');
                    $this->switching = true;
                    ($this->log)('info policy_superseded: fetching issued_seq ' . $pc['issued_seq']);
                } else {
                    $this->dropPolicy('policy_rejected');
                    $this->noteError('policy_below_min_issued_seq');
                }
            }
        }
        $o = $j['sampling_override_bp'] ?? null;
        $this->overrideBp = is_int($o) && $o >= 0 && $o <= 10000 ? $o : null;
        // Revocations first (fleet-api, RT3-KEY-3): a key endorsed by a kid revoked in this very response is never pinned.
        if (is_array($j['revoke_signing_keys'] ?? null)) {
            $this->revokeSigningKeys($j['revoke_signing_keys']);
        }
        if (is_array($j['add_signing_keys'] ?? null)) {
            $this->addSigningKeys($j['add_signing_keys']);
        }
        $cur = $j['policy_current'] ?? null;
        if (is_array($cur) && is_string($cur['hash'] ?? null) && $cur['hash'] !== $this->policy?->hash) {
            $this->nextPolicy = 0.0;
        }
        if (is_string($j['renew_before'] ?? null) && ($t = strtotime($j['renew_before'])) !== false && time() >= $t) {
            $this->renew();
        }
    }

    /**
     * @param array<string, string> $keys kid => public key
     * @return list<string>
     */
    private static function sortedKids(array $keys): array
    {
        $kids = array_map('strval', array_keys($keys));
        sort($kids, SORT_STRING);
        return array_values($kids);
    }

    /** @param list<mixed> $list */
    private function revokeSigningKeys(array $list): void
    {
        $rk = array_flip(array_map('strval', (array) ($this->persisted['revoked_kids'] ?? [])));
        $changed = false;
        foreach ($list as $k) {
            if (is_string($k) && !isset($rk[$k])) {
                $rk[$k] = true;
                $changed = true;
            }
        }
        if ($changed) {
            $this->persisted['revoked_kids'] = array_map('strval', array_keys($rk));
            $this->persisted['added_keys'] = array_values(array_filter(
                (array) ($this->persisted['added_keys'] ?? []),
                static fn ($k): bool => !is_array($k) || !isset($rk[(string) ($k['kid'] ?? '')]),
            ));
            $this->persist();
        }
        if ($this->policy !== null && isset($rk[$this->policyKid])) {
            $this->dropPolicy('policy_rejected');
            $this->noteError('policy_key_revoked');
        }
    }

    /**
     * Pins the keys of add_signing_keys endorsed by a pinned, non-revoked key, in list order (an endorser
     * comes before the key it endorses). tt-core repeats the whole list at every heartbeat: a kid already
     * pinned with the same key is skipped silently; a revoked kid is never pinned again.
     *
     * @param list<mixed> $list
     */
    private function addSigningKeys(array $list): void
    {
        $known = $this->signingKeys();
        $revoked = array_flip(array_map('strval', (array) ($this->persisted['revoked_kids'] ?? [])));
        $added = (array) ($this->persisted['added_keys'] ?? []);
        $changed = false;
        foreach ($list as $k) {
            // Canonical codes (docs/spec/policy.md §3.1): malformed -> rejected; a kid pinned to other bytes ->
            // conflict; unknown/revoked endorser -> endorser_unknown; bad signature -> endorsement_invalid.
            if (!is_array($k) || !is_string($k['kid'] ?? null) || preg_match('/^[A-Za-z0-9._-]{1,64}$/D', $k['kid']) !== 1) {
                $this->noteError('signing_key_rejected');
                continue;
            }
            $kid = $k['kid'];
            if (isset($revoked[$kid])) {
                continue;
            }
            $raw = is_string($k['public_key'] ?? null) ? Envelope::publicKey($k['public_key']) : null;
            $sig = is_string($k['endorsement'] ?? null) ? Utf8::b64urlDecode($k['endorsement']) : null;
            if (($k['alg'] ?? null) !== 'Ed25519' || !is_string($k['endorsed_by'] ?? null) || $raw === null || $sig === null || strlen($sig) !== 64) {
                $this->noteError('signing_key_rejected');
                continue;
            }
            if (isset($known[$kid])) {
                if (!hash_equals((string) Envelope::publicKey($known[$kid]), $raw)) {
                    $this->noteError('signing_key_conflict');
                }
                continue;
            }
            $by = $k['endorsed_by'];
            $endorser = !isset($revoked[$by]) && isset($known[$by]) ? Envelope::publicKey($known[$by]) : null;
            if ($endorser === null) {
                $this->noteError('signing_key_endorser_unknown');
                continue;
            }
            if (!Envelope::sodiumAvailable()) {
                continue;
            }
            $msg = "tt-fleet-key/v1\0" . $kid . "\0" . $raw;
            if (!sodium_crypto_sign_verify_detached($sig, $msg, $endorser)) {
                $this->noteError('signing_key_endorsement_invalid');
                continue;
            }
            $added[] = ['kid' => $kid, 'alg' => 'Ed25519', 'public_key' => $k['public_key']];
            $known[$kid] = $k['public_key'];
            $changed = true;
        }
        if ($changed) {
            $this->persisted['added_keys'] = array_values($added);
            $this->persist();
        }
    }

    private function renew(): void
    {
        if ($this->fleet === null || $this->enrollment === null) {
            return;
        }
        try {
            $r = $this->fleet->renew($this->config->useCsr, (string) $this->enrollment['service_name'], $this->store);
            if ($r === null) {
                $this->noteError('renew_failed');
                return;
            }
            $this->enrollment['client_cert'] = $r['cert'];
            if ($r['notAfter'] !== null) {
                $this->enrollment['not_after'] = $r['notAfter'];
            }
            $this->keyPem = $r['keyPem'];
            $this->store->writeText('client.key', $this->keyPem);
            $this->store->writeJson('enrollment.json', $this->enrollment);
            $this->connect();
        } catch (\Throwable) {
            $this->noteError('renew_network');
        }
    }

    private function revoke(): void
    {
        $this->persisted['revoked'] = true;
        $this->persist();
        $this->dropQueues();
        $this->noteError('source_revoked');
    }

    private function dropQueues(): void
    {
        $this->c['events_dropped_queue'] += count($this->batch) + $this->spool->clear();
        $this->batch = [];
        $this->batchBytes = 0;
        if ($this->cursor !== null) {
            fclose($this->cursor['fh']);
            $this->cursor = null;
        }
    }

    private function persist(): void
    {
        if (!$this->store->writeJson('state.json', $this->persisted)) {
            $this->noteError('state_write_failed');
        }
    }

    private function noteError(string $code): void
    {
        $this->errors[] = ['code' => substr($code, 0, 64), 'at' => gmdate('Y-m-d\TH:i:s\Z')];
        if (count($this->errors) > 20) {
            array_shift($this->errors);
        }
        ($this->log)('error ' . $code);
    }

    // --- state and status.json ---------------------------------------------------------------

    private function recompute(): void
    {
        $now = time();
        $p = $this->policy;
        $maxAge = (int) ($this->enrollment['policy_max_age_s'] ?? 86400);
        if (($this->persisted['kill'] ?? false) === true || ($this->persisted['revoked'] ?? false) === true) {
            $st = 'killed';
        } elseif ($p === null) {
            $st = $this->rejected ?? 'no_policy';
        } elseif ($p->notAfter === null || $now * 1000 >= $p->notAfter || ($this->lastContact > 0 && $now - $this->lastContact > $maxAge)) {
            $st = 'expired_policy';
        } elseif ($this->ring === null) {
            $st = 'key_missing';
        } else {
            try {
                $this->ring->select($p);
                $st = $this->heartbeatOk ? 'capturing' : 'starting';
            } catch (Refused) {
                $st = 'key_mismatch';
            }
        }
        if ($this->enrollment === null) {
            $st = 'starting';
        }
        if ($st !== $this->state) {
            ($this->log)('state ' . $st);
        }
        $this->state = $st;
    }

    private function writeStatus(bool $force = false): void
    {
        $e = $this->enrollment;
        $keys = $e !== null ? $this->signingKeys() : [];
        $doc = [
            'v' => 1,
            'state' => $this->state,
            'kill' => ($this->persisted['kill'] ?? false) === true,
            'revoked' => ($this->persisted['revoked'] ?? false) === true,
            'heartbeat_ok' => $this->heartbeatOk,
            'last_contact' => $this->lastContact,
            'policy_max_age_s' => (int) ($e['policy_max_age_s'] ?? 86400),
            'min_issued_seq' => (int) ($this->persisted['min_issued_seq'] ?? 0),
            'override_bp' => $this->overrideBp,
            'service_name' => $e['service_name'] ?? null,
            'source_id' => $e['source_id'] ?? null,
            'group' => $e['group'] ?? null,
            'signing_keys' => (object) $keys,
            'policy_hash' => $this->policy?->hash,
            'pid' => getmypid(),
        ];
        $json = (string) json_encode($doc, JSON_UNESCAPED_SLASHES);
        $now = microtime(true);
        // Rewrite when something changed, and at least every 5 seconds so last_contact stays visible.
        if (!$force && $json === $this->lastStatusJson && $now - $this->lastStatusWrite < 5.0) {
            return;
        }
        if ($this->store->writeText('status.json', $json)) {
            $this->lastStatusJson = $json;
            $this->lastStatusWrite = $now;
        } else {
            $this->noteError('status_write_failed');
        }
    }

    /** Current state for the CLI and tests. */
    public function state(): string
    {
        return $this->state;
    }

    /** @return array<string, int> */
    public function counters(): array
    {
        return $this->c;
    }

    // --- export (event.md 4) -----------------------------------------------------------------

    /**
     * Sends spooled events until the spool is empty, a retry is pending or $deadline passes.
     */
    public function ship(float $deadline, bool $includeCurrent = false): void
    {
        $this->includeCurrent = $includeCurrent;
        if ($this->fleet === null || $this->enrollment === null) {
            return;
        }
        if (($this->persisted['kill'] ?? false) === true || ($this->persisted['revoked'] ?? false) === true) {
            $this->dropQueues();
            return;
        }
        $this->trimSpool();
        while (microtime(true) < $deadline && !$this->stopping) {
            if (microtime(true) < $this->retryAt) {
                return;
            }
            if ($this->batch === [] && !$this->fillBatch()) {
                return;
            }
            if (!$this->sendBatch()) {
                return;
            }
        }
    }

    /** Drop-oldest when the spool exceeds its cap. */
    private function trimSpool(): void
    {
        $max = $this->config->spoolMaxBytes;
        if ($this->spool->size() <= $max) {
            return;
        }
        $victims = array_merge($this->spool->claimedSegments(), $this->spool->closedSegments());
        foreach ($victims as $f) {
            if ($this->spool->size() <= $max) {
                break;
            }
            if ($this->cursor !== null && $this->cursor['file'] === $f) {
                continue;
            }
            $this->c['events_dropped_queue'] += Spool::countLines($f);
            @unlink($f);
        }
    }

    /** Reads the next events into the batch. Returns false when there is nothing to send. */
    private function fillBatch(): bool
    {
        while (count($this->batch) < self::BATCH_EVENTS && $this->batchBytes < self::BATCH_BYTES) {
            if ($this->cursor === null) {
                $next = $this->spool->claimedSegments()[0] ?? null;
                if ($next === null) {
                    $closed = $this->spool->closedSegments($this->includeCurrent)[0] ?? null;
                    $next = $closed !== null ? $this->spool->claim($closed) : null;
                }
                if ($next === null) {
                    break;
                }
                $fh = @fopen($next, 'rb');
                if ($fh === false) {
                    @unlink($next);
                    continue;
                }
                $this->cursor = ['file' => $next, 'fh' => $fh];
            }
            $line = fgets($this->cursor['fh']);
            if ($line === false) {
                fclose($this->cursor['fh']);
                @unlink($this->cursor['file']);
                $this->cursor = null;
                continue;
            }
            $rec = self::parseRecord(rtrim($line, "\n"));
            if ($rec === null) {
                $this->c['events_rejected']++;
                continue;
            }
            $this->batch[] = $rec;
            $this->batchBytes += strlen($rec['json']);
        }
        return $this->batch !== [];
    }

    /** @return array{ts: int, trace: ?string, span: ?string, hash: string, json: string}|null */
    public static function parseRecord(string $line): ?array
    {
        $f = explode("\t", $line, 5);
        if (count($f) !== 5 || !ctype_digit($f[0]) || !str_starts_with($f[3], 'sha256:') || ($f[4] === '' || $f[4][0] !== '{')) {
            return null;
        }
        return ['ts' => (int) $f[0], 'trace' => $f[1] === '-' ? null : $f[1], 'span' => $f[2] === '-' ? null : $f[2], 'hash' => $f[3], 'json' => $f[4]];
    }

    /** Sends the current batch. Returns true when the loop may continue, false to stop for now. */
    private function sendBatch(): bool
    {
        $n = count($this->batch);
        $body = EventBuilder::otlpBody($this->batch, (string) $this->enrollment['service_name'], (string) $this->enrollment['source_id'], (int) (microtime(true) * 1000));
        $res = null;
        $netErr = false;
        try {
            $res = $this->fleet->sendLogs((string) $this->enrollment['intake_url'], $body);
        } catch (\Throwable) {
            $netErr = true;
        }
        if ($res !== null && $res['status'] >= 200 && $res['status'] < 300) {
            $rejected = 0;
            $j = json_decode($res['body'] === '' ? '{}' : $res['body'], true);
            if (is_array($j) && isset($j['partialSuccess']['rejectedLogRecords'])) {
                $rejected = (int) $j['partialSuccess']['rejectedLogRecords'];
            }
            $rejected = min(max(0, $rejected), $n);
            $this->c['events_sent'] += $n - $rejected;
            $this->c['events_rejected'] += $rejected;
            if ($rejected > 0) {
                $this->noteError('intake_partial_reject');
            }
            $this->clearBatch();
            return true;
        }
        $status = $res['status'] ?? 0;
        $retryable = $netErr || in_array($status, [429, 502, 503, 504], true);
        if (!$retryable || $this->attempt >= self::MAX_RETRIES || $this->stopping) {
            if (in_array($status, [400, 401, 403, 413], true)) {
                $this->c['events_rejected'] += $n;
            } else {
                $this->c['events_dropped_queue'] += $n;
            }
            $this->c['send_errors']++;
            $this->noteError($res !== null ? 'intake_http_' . $status : 'intake_network');
            $this->clearBatch();
            return true;
        }
        $this->c['send_errors']++;
        $delay = min(30.0, 1.0 * (2 ** $this->attempt));
        $delay = $delay / 2 + (mt_rand() / mt_getrandmax()) * ($delay / 2);
        $ra = $res['headers']['retry-after'] ?? null;
        if ($ra !== null) {
            $secs = ctype_digit(trim($ra)) ? (float) $ra : (strtotime($ra) !== false ? strtotime($ra) - time() : 0);
            if ($secs > 0) {
                $delay = min(max($delay, $secs), 300.0);
            }
        }
        $this->attempt++;
        $this->retryAt = microtime(true) + $delay;
        return false;
    }

    private function clearBatch(): void
    {
        $this->batch = [];
        $this->batchBytes = 0;
        $this->attempt = 0;
        $this->retryAt = 0.0;
    }
}
