<?php

declare(strict_types=1);

namespace TrafficTwin\Shipper;

use TrafficTwin\State\Store;

/**
 * Fleet API client (api/fleet-api.v1.openapi.yaml): enrollment with a `tte_` token and CA pin,
 * then mTLS calls for heartbeat, policy, certificate renewal and the OTLP intake.
 */
final class Fleet
{
    /**
     * @param array<string, mixed> $e enrollment record
     * @param string $caFile PEM bundle received at enrollment
     * @param string $clientPem file with the client certificate and its key (0600)
     */
    public function __construct(private array $e, private string $caFile, private string $clientPem)
    {
    }

    /**
     * Enrolls with a token. Returns the enrollment record (with local bookkeeping) and the
     * private key PEM (generated locally when $useCsr).
     *
     * @param array<string, mixed> $source SourceInfo
     * @return array{enrollment: array<string, mixed>, keyPem: string}
     */
    public static function enroll(string $enrollUrl, string $token, array $source, bool $useCsr, Store $store, int $timeoutS = 15): array
    {
        $pin = Pki::tokenPin($token);
        if ($pin === null) {
            throw new FleetError('enroll_token_malformed');
        }
        $u = parse_url($enrollUrl);
        if ($u === false || ($u['scheme'] ?? '') !== 'https' || !isset($u['host'])) {
            throw new FleetError('enroll_url_not_https');
        }
        $host = trim($u['host'], '[]');
        $port = (int) ($u['port'] ?? 443);
        // The probe only locates the pinned root; trust comes from the next connection, verified
        // against that root as the only anchor (no self-signed leaf, host name checked).
        $rootPem = Pki::fetchPinnedRoot($host, $port, $pin, $timeoutS);
        if (!$store->ensure()) {
            throw new FleetError('state_dir_insecure');
        }
        $rootFile = $store->path('enroll-root.pem');
        $store->writeText('enroll-root.pem', $rootPem);
        $keyPem = '';
        $body = ['token' => $token, 'source' => $source];
        if ($useCsr) {
            $g = Pki::generateCsr((string) $source['service_name'], $store->dir);
            $keyPem = $g['keyPem'];
            $body['csr'] = $g['csrPem'];
        }
        try {
            $res = Http::request('POST', rtrim($enrollUrl, '/') . '/fleet/v1/enroll', ['Content-Type' => 'application/json'], json_encode($body, JSON_UNESCAPED_SLASHES), ['cafile' => $rootFile], $timeoutS);
        } finally {
            $store->remove('enroll-root.pem');
        }
        if ($res['status'] !== 201 && $res['status'] !== 200) {
            throw new FleetError('enroll_http_' . $res['status'], $res['status']);
        }
        $j = json_decode($res['body'], true);
        if (!is_array($j)) {
            throw new FleetError('enroll_bad_response');
        }
        if (!$useCsr) {
            if (!is_string($j['client_key'] ?? null)) {
                throw new FleetError('enroll_no_key');
            }
            $keyPem = $j['client_key'];
        }
        $keys = [];
        foreach ((array) ($j['policy_signing_keys'] ?? []) as $k) {
            if (is_array($k) && is_string($k['kid'] ?? null) && preg_match('/^[A-Za-z0-9._-]{1,64}$/D', $k['kid']) === 1
                && ($k['alg'] ?? null) === 'Ed25519' && is_string($k['public_key'] ?? null) && preg_match('/^[A-Za-z0-9_-]{43}$/D', $k['public_key']) === 1) {
                $keys[] = ['kid' => $k['kid'], 'alg' => 'Ed25519', 'public_key' => $k['public_key']];
            }
        }
        $en = [
            'source_id' => (string) ($j['source_id'] ?? ''),
            'group' => (string) ($j['group'] ?? ''),
            'service_name' => (string) ($j['service_name'] ?? ''),
            'client_cert' => (string) ($j['client_cert'] ?? ''),
            'ca_chain' => (string) ($j['ca_chain'] ?? ''),
            'not_after' => is_string($j['not_after'] ?? null) ? $j['not_after'] : null,
            'policy_signing_keys' => $keys,
            'intake_url' => (string) ($j['intake_url'] ?? ''),
            'fleet_url' => (string) ($j['fleet_url'] ?? ''),
            'policy_max_age_s' => is_int($j['policy_max_age_s'] ?? null) ? $j['policy_max_age_s'] : 86400,
            'heartbeat_interval_s' => is_int($j['heartbeat_interval_s'] ?? null) ? $j['heartbeat_interval_s'] : 30,
            'policy_poll_interval_s' => is_int($j['policy_poll_interval_s'] ?? null) ? $j['policy_poll_interval_s'] : 60,
            'enroll_url' => $enrollUrl,
            'pin' => $pin,
        ];
        if (preg_match('/^src-[0-9A-Za-z]{1,32}$/D', $en['source_id']) !== 1) {
            throw new FleetError('enroll_bad_source_id');
        }
        if (preg_match('/^[a-z0-9][a-z0-9-]{0,62}$/D', $en['group']) !== 1) {
            throw new FleetError('enroll_bad_group');
        }
        if (preg_match('/^[a-z0-9][a-z0-9._-]{0,62}$/D', $en['service_name']) !== 1) {
            throw new FleetError('enroll_bad_service_name');
        }
        if (Pki::derBlocks($en['client_cert']) === []) {
            throw new FleetError('enroll_bad_cert');
        }
        $pinned = false;
        foreach (Pki::derBlocks($en['ca_chain']) as $der) {
            $pinned = $pinned || hash_equals($pin, Pki::pinOf($der));
        }
        if (!$pinned) {
            throw new FleetError('enroll_chain_without_pinned_root');
        }
        // The CA chain becomes the mTLS trust anchor of every later call: each certificate in it,
        // and the client certificate, must chain to the pinned root (nothing else is trusted).
        $untrusted = $en['ca_chain'] . "\n" . $en['client_cert'];
        foreach (Pki::derBlocks($en['ca_chain']) as $der) {
            if (!hash_equals($pin, Pki::pinOf($der)) && !Pki::verifiesAgainst($rootPem, Pki::pemOfDer($der), $untrusted, $store->dir)) {
                throw new FleetError('enroll_chain_untrusted');
            }
        }
        if (!Pki::verifiesAgainst($rootPem, Pki::pemOfDer(Pki::derBlocks($en['client_cert'])[0]), $untrusted, $store->dir)) {
            throw new FleetError('enroll_cert_untrusted');
        }
        if ($en['policy_signing_keys'] === []) {
            throw new FleetError('enroll_no_signing_keys');
        }
        foreach (['intake_url', 'fleet_url'] as $f) {
            if (!str_starts_with($en[$f], 'https://')) {
                throw new FleetError('enroll_bad_urls');
            }
        }
        return ['enrollment' => $en, 'keyPem' => $keyPem];
    }

    /** @return array{cafile: string, local_cert: string} */
    private function tls(): array
    {
        return ['cafile' => $this->caFile, 'local_cert' => $this->clientPem];
    }

    private function url(string $path): string
    {
        return rtrim((string) $this->e['fleet_url'], '/') . $path;
    }

    /**
     * @param array<string, mixed> $body
     * @return array{status: int, json: ?array<string, mixed>}
     */
    public function heartbeat(array $body): array
    {
        $r = Http::request('POST', $this->url('/fleet/v1/heartbeat'), ['Content-Type' => 'application/json'], json_encode($body, JSON_UNESCAPED_SLASHES), $this->tls());
        $j = $r['status'] === 200 ? json_decode($r['body'], true) : null;
        return ['status' => $r['status'], 'json' => is_array($j) ? $j : null];
    }

    /** @return array{status: int, body: ?string, etag: ?string} */
    public function getPolicy(?string $etag): array
    {
        $h = $etag !== null ? ['If-None-Match' => $etag] : [];
        $r = Http::request('GET', $this->url('/fleet/v1/policy'), $h, null, $this->tls());
        return ['status' => $r['status'], 'body' => $r['status'] === 200 ? $r['body'] : null, 'etag' => $r['headers']['etag'] ?? null];
    }

    /** @return array{cert: string, keyPem: string, notAfter: ?string}|null */
    public function renew(bool $useCsr, string $commonName, Store $store): ?array
    {
        $keyPem = null;
        $body = [];
        if ($useCsr) {
            $g = Pki::generateCsr($commonName, $store->dir);
            $keyPem = $g['keyPem'];
            $body['csr'] = $g['csrPem'];
        }
        $r = Http::request('POST', $this->url('/fleet/v1/renew'), ['Content-Type' => 'application/json'], json_encode((object) $body), $this->tls());
        if ($r['status'] !== 200) {
            return null;
        }
        $j = json_decode($r['body'], true);
        if (!is_array($j) || !is_string($j['client_cert'] ?? null)) {
            return null;
        }
        if (!$useCsr) {
            $keyPem = is_string($j['client_key'] ?? null) ? $j['client_key'] : null;
        }
        return $keyPem === null ? null : ['cert' => $j['client_cert'], 'keyPem' => $keyPem, 'notAfter' => is_string($j['not_after'] ?? null) ? $j['not_after'] : null];
    }

    /**
     * Sends a prepared OTLP/HTTP JSON body to the intake.
     *
     * @return array{status: int, headers: array<string, string>, body: string}
     */
    public function sendLogs(string $url, string $json): array
    {
        $headers = ['Content-Type' => 'application/json'];
        if (strlen($json) > 1024 && function_exists('gzencode')) {
            $z = gzencode($json, 3);
            if ($z !== false) {
                $json = $z;
                $headers['Content-Encoding'] = 'gzip';
            }
        }
        return Http::request('POST', $url, $headers, $json, $this->tls(), 15, 65536);
    }
}
