<?php

declare(strict_types=1);

namespace TrafficTwin\Tests\Support;

use TrafficTwin\Config;
use TrafficTwin\Runtime;
use TrafficTwin\Sanitizer\Json;
use TrafficTwin\Sanitizer\Utf8;

/**
 * A state directory as the shipper would leave it, built locally with a throw-away Ed25519 key:
 * status.json + the signed policy envelope. Lets tests exercise the worker side without a network.
 */
final class Fixture
{
    public const HMAC_KEY = 'k1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
    public const KID = 'policy-test-1';

    public string $dir;
    public string $secret;
    public string $public;
    /** @var array<string, mixed> */
    public array $status;

    public function __construct(?string $dir = null)
    {
        $this->dir = $dir ?? sys_get_temp_dir() . '/tt-fixture-' . bin2hex(random_bytes(4));
        @mkdir($this->dir, 0700, true);
        $kp = sodium_crypto_sign_keypair();
        $this->secret = sodium_crypto_sign_secretkey($kp);
        $this->public = Utf8::b64url(sodium_crypto_sign_publickey($kp));
        $this->status = [
            'v' => 1, 'state' => 'capturing', 'kill' => false, 'revoked' => false, 'heartbeat_ok' => true,
            'last_contact' => time(), 'policy_max_age_s' => 86400, 'min_issued_seq' => 0, 'override_bp' => null,
            'service_name' => 'shop-api', 'source_id' => 'src-test0001', 'group' => 'shop',
            'signing_keys' => [self::KID => $this->public], 'policy_hash' => null, 'pid' => 1,
        ];
    }

    public function __destruct()
    {
        if (getenv('TT_KEEP_FIXTURES') === false) {
            self::rmrf($this->dir);
        }
    }

    public static function rmrf(string $d): void
    {
        if (!is_dir($d)) {
            return;
        }
        foreach (scandir($d) ?: [] as $f) {
            if ($f === '.' || $f === '..') {
                continue;
            }
            $p = $d . '/' . $f;
            is_dir($p) && !is_link($p) ? self::rmrf($p) : @unlink($p);
        }
        @rmdir($d);
    }

    /** @param array<string, mixed> $over merged (shallow) into the default policy body */
    public static function policy(array $over = []): array
    {
        $now = time();
        return $over + [
            'format' => 'tt.policy.body/v1',
            'policy_id' => 'p-shop',
            'version' => 1,
            'issued_seq' => 1,
            'created_at' => gmdate('Y-m-d\TH:i:s\Z', $now - 60),
            'not_after' => gmdate('Y-m-d\TH:i:s\Z', $now + 30 * 86400),
            'targets' => ['groups' => ['shop']],
            'hmac' => ['kid' => 'k1', 'accept_kids' => [], 'epoch' => '2026-10'],
            'sampling' => ['rate_bp' => 10000, 'trust_baggage' => false, 'propagate_to' => []],
            'segments' => ['auto_words' => false, 'allow' => ['v1', 'api'], 'hosts_allow' => []],
            'limits' => ['max_body_bytes' => 1048576, 'max_depth' => 32, 'max_array' => 32, 'max_keys' => 256, 'keep_max_bytes' => 64],
            'global' => [
                'request' => ['headers' => ['content-type' => ['action' => 'keep']]],
                'response' => ['headers' => ['content-type' => ['action' => 'keep']]],
            ],
            'services' => [],
        ];
    }

    /** @param array<string, mixed> $body @return array<string, mixed> */
    public function envelope(array $body, ?string $secret = null, string $kid = self::KID): array
    {
        $bytes = Json::write(Json::toOut(Json::parse(json_encode($body, JSON_UNESCAPED_SLASHES))));
        $sig = sodium_crypto_sign_detached("tt.policy.body/v1\0" . $bytes, $secret ?? $this->secret);
        return [
            'format' => 'tt.policy.compiled/v1',
            'policy_id' => $body['policy_id'],
            'version' => $body['version'],
            'issued_seq' => $body['issued_seq'],
            'hash' => 'sha256:' . hash('sha256', $bytes),
            'body_b64' => Utf8::b64url($bytes),
            'signature' => ['alg' => 'Ed25519', 'kid' => $kid, 'sig' => Utf8::b64url($sig)],
        ];
    }

    /** @param array<string, mixed>|null $body */
    public function write(?array $body = null): self
    {
        $body ??= self::policy();
        $env = $this->envelope($body);
        file_put_contents($this->dir . '/policy.envelope.json', json_encode($env, JSON_UNESCAPED_SLASHES));
        $this->status['policy_hash'] = $env['hash'];
        $this->writeStatus();
        return $this;
    }

    public function writeStatus(): void
    {
        file_put_contents($this->dir . '/status.json', json_encode($this->status, JSON_UNESCAPED_SLASHES));
    }

    public function config(?string $key = self::HMAC_KEY): Config
    {
        $c = new Config();
        $c->stateDir = $this->dir;
        $c->hmacKey = $key;
        return $c;
    }

    public function runtime(?string $key = self::HMAC_KEY): Runtime
    {
        $rt = new Runtime($this->config($key));
        // Tests call processPending() themselves, after "emitting" the response.
        $rt->deferMode = 'shutdown';
        $rt->finishRequest = false;
        return $rt;
    }

    /** @return list<array<string, mixed>> events spooled so far, decoded (for assertions only) */
    public function events(): array
    {
        $out = [];
        foreach (glob($this->dir . '/spool/seg-*') ?: [] as $f) {
            foreach (file($f, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
                $parts = explode("\t", $line, 5);
                $out[] = json_decode($parts[4], true);
            }
        }
        return $out;
    }

    /** @return list<string> raw spool lines */
    public function spoolText(): string
    {
        $t = '';
        foreach (glob($this->dir . '/spool/seg-*') ?: [] as $f) {
            $t .= (string) file_get_contents($f);
        }
        return $t;
    }
}
