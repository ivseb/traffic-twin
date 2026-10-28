<?php

declare(strict_types=1);

/**
 * A fake tt-core for tests: the Fleet source endpoints (enroll, heartbeat, policy, renew) and the
 * OTLP/HTTP JSON intake, over TLS with the root CA in the chain it presents, mTLS required on
 * the second listener. Invented data only.
 *
 *   php fake-core.php <work dir>
 *
 * Writes <work dir>/info.json when ready (ports, token, signing key). Test behaviour is driven by
 * <work dir>/control.json, re-read at every request:
 *   policy            policy body (assoc array) to serve, or null for 404
 *   kill, min_issued_seq, sampling_override_bp
 *   logs_status       fixed HTTP status for POST /v1/logs (e.g. 503), `logs_fail_n` limits how many times
 *   retry_after       Retry-After header for those failures
 *   revoked           heartbeat/policy/renew answer 403
 *   policy_current    explicit policy_current object for the heartbeat
 *   add_signing_keys, revoke_signing_keys
 * Output: <work dir>/events.ndjson (one received event per line), <work dir>/log.ndjson
 * (one line per request: path, status, client SAN, headers of interest).
 */

require __DIR__ . '/../../src/autoload.php';

use TrafficTwin\Sanitizer\Json;
use TrafficTwin\Sanitizer\Utf8;

$dir = $argv[1] ?? sys_get_temp_dir() . '/tt-fake-core';
@mkdir($dir, 0700, true);
@mkdir($dir . '/pki', 0700, true);

// --- PKI ---------------------------------------------------------------------------------------
$cnf = $dir . '/pki/openssl.cnf';
file_put_contents($cnf, <<<'CNF'
[req]
default_bits = 2048
distinguished_name = dn
prompt = no
[dn]
CN = tt-test
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[v3_server]
basicConstraints = CA:FALSE
subjectAltName = DNS:localhost,IP:127.0.0.1
keyUsage = digitalSignature
extendedKeyUsage = serverAuth
CNF);

function newKey(string $cnf)
{
    return openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1', 'config' => $cnf]);
}

$rootKey = newKey($cnf);
$rootCsr = openssl_csr_new(['commonName' => 'tt-test-root'], $rootKey, ['digest_alg' => 'sha256', 'config' => $cnf]);
$rootCert = openssl_csr_sign($rootCsr, null, $rootKey, 3650, ['digest_alg' => 'sha256', 'config' => $cnf, 'x509_extensions' => 'v3_ca'], 1);
openssl_x509_export($rootCert, $rootPem);
$srvKey = newKey($cnf);
$srvCsr = openssl_csr_new(['commonName' => 'localhost'], $srvKey, ['digest_alg' => 'sha256', 'config' => $cnf]);
$srvCert = openssl_csr_sign($srvCsr, $rootCert, $rootKey, 365, ['digest_alg' => 'sha256', 'config' => $cnf, 'x509_extensions' => 'v3_server'], 2);
openssl_x509_export($srvCert, $srvPem);
openssl_pkey_export($srvKey, $srvKeyPem, null, ['config' => $cnf]);
file_put_contents($dir . '/pki/ca.pem', $rootPem);
file_put_contents($dir . '/pki/server-chain.pem', $srvPem . $rootPem);
file_put_contents($dir . '/pki/server.key', $srvKeyPem);
$rootDer = base64_decode(preg_replace('/\s+/', '', (string) preg_replace('/-----[A-Z ]+-----/', '', $rootPem)));
$pin = Utf8::b64url(hash('sha256', $rootDer, true));

function issueClient(string $cnf, string $csrPem, string $sourceId, $rootCert, $rootKey, string $dir): string
{
    $ext = $dir . '/pki/client-' . $sourceId . '.cnf';
    file_put_contents($ext, "[req]\ndefault_bits = 2048\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = x\n[v3_client]\nbasicConstraints = CA:FALSE\nsubjectAltName = DNS:$sourceId\nkeyUsage = digitalSignature\nextendedKeyUsage = clientAuth\n");
    $cert = openssl_csr_sign($csrPem, $rootCert, $rootKey, 30, ['digest_alg' => 'sha256', 'config' => $ext, 'x509_extensions' => 'v3_client'], random_int(100, PHP_INT_MAX >> 8));
    openssl_x509_export($cert, $pem);
    return $pem;
}

// --- policy signing key -----------------------------------------------------------------------------
$kp = sodium_crypto_sign_keypair();
$signSecret = sodium_crypto_sign_secretkey($kp);
$signPublic = Utf8::b64url(sodium_crypto_sign_publickey($kp));
const SIGNING_KID = 'policy-test-1';

function canonicalBytes(array $doc): string
{
    return Json::write(Json::toOut(Json::parse(json_encode($doc, JSON_UNESCAPED_SLASHES))));
}

function envelopeFor(array $body, string $secret, string $kid = SIGNING_KID): array
{
    $bytes = canonicalBytes($body);
    $sig = sodium_crypto_sign_detached("tt.policy.body/v1\0" . $bytes, $secret);
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

// --- listeners -------------------------------------------------------------------------------------------
$token = 'tte_' . Utf8::b64url(random_bytes(24)) . '.' . $pin;
$mk = static function (bool $mtls) use ($dir): array {
    $ssl = [
        'local_cert' => $dir . '/pki/server-chain.pem',
        'local_pk' => $dir . '/pki/server.key',
        'verify_peer' => $mtls,
        'verify_peer_name' => false,
        'allow_self_signed' => true,
        'cafile' => $dir . '/pki/ca.pem',
        'capture_peer_cert' => true,
        'disable_compression' => true,
    ];
    $s = stream_socket_server('ssl://127.0.0.1:0', $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, stream_context_create(['ssl' => $ssl]));
    if ($s === false) {
        fwrite(STDERR, "listen failed: $errstr\n");
        exit(1);
    }
    $port = (int) substr((string) strrchr((string) stream_socket_get_name($s, false), ':'), 1);
    return [$s, $port];
};
[$srvEnroll, $portEnroll] = $mk(false);
[$srvMtls, $portMtls] = $mk(true);
file_put_contents($dir . '/info.json.tmp', json_encode([
    'ready' => true, 'pid' => getmypid(), 'enroll_port' => $portEnroll, 'mtls_port' => $portMtls,
    'token' => $token, 'pin' => $pin, 'signing_kid' => SIGNING_KID, 'signing_public_key' => $signPublic,
    'ca_file' => $dir . '/pki/ca.pem',
    'signing_secret' => Utf8::b64url($signSecret), // test-only: lets tests endorse rotated keys
]));
rename($dir . '/info.json.tmp', $dir . '/info.json');

// --- request handling -----------------------------------------------------------------------------------------
$sources = []; // source id => true
$logsFailed = 0;
$running = true;
if (function_exists('pcntl_async_signals')) {
    pcntl_async_signals(true);
    pcntl_signal(SIGTERM, static function () use (&$running): void {
        $running = false;
    });
}

function control(string $dir): array
{
    $j = @json_decode((string) @file_get_contents($dir . '/control.json'), true);
    return is_array($j) ? $j : [];
}

function respond($conn, int $status, string $body = '', array $headers = []): void
{
    $reason = [200 => 'OK', 201 => 'Created', 304 => 'Not Modified', 400 => 'Bad Request', 401 => 'Unauthorized', 403 => 'Forbidden', 404 => 'Not Found', 429 => 'Too Many Requests', 503 => 'Service Unavailable'][$status] ?? 'Status';
    $h = "HTTP/1.1 $status $reason\r\nConnection: close\r\nContent-Length: " . strlen($body) . "\r\n";
    foreach ($headers + ['Content-Type' => 'application/json'] as $k => $v) {
        $h .= "$k: $v\r\n";
    }
    @fwrite($conn, $h . "\r\n" . $body);
}

function readRequest($conn): ?array
{
    $buf = '';
    $t0 = microtime(true);
    while (!str_contains($buf, "\r\n\r\n")) {
        $c = @fread($conn, 8192);
        if ($c === false || ($c === '' && (feof($conn) || microtime(true) - $t0 > 5))) {
            return null;
        }
        $buf .= $c;
    }
    [$head, $rest] = explode("\r\n\r\n", $buf, 2);
    $lines = explode("\r\n", $head);
    [$method, $target] = explode(' ', array_shift($lines), 3);
    $h = [];
    foreach ($lines as $l) {
        $p = strpos($l, ':');
        if ($p > 0) {
            $h[strtolower(substr($l, 0, $p))] = trim(substr($l, $p + 1));
        }
    }
    $len = (int) ($h['content-length'] ?? 0);
    while (strlen($rest) < $len) {
        $c = @fread($conn, 65536);
        if ($c === false || ($c === '' && (feof($conn) || microtime(true) - $t0 > 10))) {
            return null;
        }
        $rest .= $c;
    }
    $body = substr($rest, 0, $len);
    if (($h['content-encoding'] ?? '') === 'gzip') {
        $d = @gzdecode($body);
        $body = $d === false ? '' : $d;
    }
    return ['method' => $method, 'path' => explode('?', $target)[0], 'headers' => $h, 'body' => $body];
}

function clientSan($conn): ?string
{
    $cert = stream_context_get_params($conn)['options']['ssl']['peer_certificate'] ?? null;
    if ($cert === null) {
        return null;
    }
    $info = openssl_x509_parse($cert);
    $san = (string) ($info['extensions']['subjectAltName'] ?? '');
    return preg_match('/DNS:(src-[0-9A-Za-z]+)/', $san, $m) === 1 ? $m[1] : null;
}

while ($running) {
    $r = [$srvEnroll, $srvMtls];
    $w = $e = null;
    if (@stream_select($r, $w, $e, 0, 200000) < 1) {
        continue;
    }
    foreach ($r as $srv) {
        $conn = @stream_socket_accept($srv, 5);
        if ($conn === false) {
            continue;
        }
        $isMtls = $srv === $srvMtls;
        stream_set_timeout($conn, 5);
        $req = readRequest($conn);
        if ($req === null) {
            fclose($conn);
            continue;
        }
        $ctl = control($dir);
        $san = $isMtls ? clientSan($conn) : null;
        $status = 404;
        $path = $req['path'];
        $log = ['path' => $path, 'method' => $req['method'], 'san' => $san, 'mtls' => $isMtls];

        if ($path === '/fleet/v1/enroll' && $req['method'] === 'POST') {
            $j = json_decode($req['body'], true);
            if (!is_array($j) || ($j['token'] ?? null) !== $token) {
                respond($conn, 401, json_encode(['code' => 'token', 'message' => 'unknown token']));
                $status = 401;
            } else {
                $sid = 'src-' . bin2hex(random_bytes(4));
                $sources[$sid] = true;
                if (isset($j['csr'])) {
                    $csr = openssl_csr_get_subject($j['csr']) !== false ? $j['csr'] : null;
                    $clientCert = $csr !== null ? issueClient($cnf, $csr, $sid, $rootCert, $rootKey, $dir) : null;
                    $clientKey = null;
                } else {
                    $k = newKey($cnf);
                    $c = openssl_csr_new(['commonName' => $sid], $k, ['digest_alg' => 'sha256', 'config' => $cnf]);
                    openssl_csr_export($c, $csrPem);
                    $clientCert = issueClient($cnf, $csrPem, $sid, $rootCert, $rootKey, $dir);
                    openssl_pkey_export($k, $clientKey, null, ['config' => $cnf]);
                }
                if ($clientCert === null) {
                    respond($conn, 422, json_encode(['code' => 'csr', 'message' => 'bad csr']));
                    $status = 422;
                } else {
                    $resp = [
                        'source_id' => $sid,
                        'group' => $ctl['group'] ?? 'shop',
                        'service_name' => $j['source']['service_name'] ?? 'unknown',
                        'client_cert' => $clientCert,
                        'ca_chain' => $rootPem,
                        'not_after' => gmdate('Y-m-d\TH:i:s\Z', time() + 30 * 86400),
                        'policy_signing_keys' => [['kid' => SIGNING_KID, 'alg' => 'Ed25519', 'public_key' => $signPublic]],
                        'intake_url' => "https://localhost:$portMtls/v1/logs",
                        'fleet_url' => "https://localhost:$portMtls",
                        'policy_max_age_s' => $ctl['policy_max_age_s'] ?? 86400,
                        'heartbeat_interval_s' => 30,
                        'policy_poll_interval_s' => 60,
                    ];
                    if ($clientKey !== null) {
                        $resp['client_key'] = $clientKey;
                    }
                    respond($conn, 201, json_encode($resp));
                    $status = 201;
                    $log['enroll'] = ['csr' => isset($j['csr']), 'source' => $j['source'] ?? null];
                }
            }
        } elseif (!$isMtls) {
            respond($conn, 403, json_encode(['code' => 'mtls', 'message' => 'client certificate required']));
            $status = 403;
        } elseif (($ctl['revoked'] ?? false) === true) {
            respond($conn, 403, json_encode(['code' => 'revoked', 'message' => 'revoked']));
            $status = 403;
        } elseif ($path === '/fleet/v1/heartbeat' && $req['method'] === 'POST') {
            $hb = json_decode($req['body'], true);
            $log['heartbeat'] = $hb;
            // signing_kids as sent (an empty PHP array must go out as [], not {}).
            $raw = json_decode($req['body']);
            $log['signing_kids_json'] = is_object($raw) && property_exists($raw, 'signing_kids') ? json_encode($raw->signing_kids) : null;
            $env = isset($ctl['policy']) ? envelopeFor($ctl['policy'], $signSecret) : null;
            $resp = [
                'next_heartbeat_s' => 30,
                'kill' => ($ctl['kill'] ?? false) === true,
                'min_issued_seq' => $ctl['min_issued_seq'] ?? 0,
                'policy_current' => $ctl['policy_current'] ?? ($env === null ? null : ['policy_id' => $env['policy_id'], 'version' => $env['version'], 'issued_seq' => $env['issued_seq'], 'hash' => $env['hash']]),
                'sampling_override_bp' => $ctl['sampling_override_bp'] ?? null,
                'renew_before' => $ctl['renew_before'] ?? null,
                'add_signing_keys' => $ctl['add_signing_keys'] ?? [],
                'revoke_signing_keys' => $ctl['revoke_signing_keys'] ?? [],
            ];
            respond($conn, 200, json_encode($resp));
            $status = 200;
        } elseif ($path === '/fleet/v1/policy' && $req['method'] === 'GET') {
            if (!isset($ctl['policy'])) {
                respond($conn, 404, json_encode(['code' => 'no_policy', 'message' => 'none']));
                $status = 404;
            } else {
                $secret = isset($ctl['policy_sign_secret']) ? (string) Utf8::b64urlDecode($ctl['policy_sign_secret']) : $signSecret;
                $env = envelopeFor($ctl['policy'], $secret, $ctl['policy_signing_kid'] ?? SIGNING_KID);
                if (isset($ctl['policy_tamper'])) {
                    $env['hash'] = 'sha256:' . str_repeat('0', 64);
                }
                if (($req['headers']['if-none-match'] ?? '') === '"' . $env['hash'] . '"') {
                    respond($conn, 304, '');
                    $status = 304;
                } else {
                    respond($conn, 200, json_encode($env, JSON_UNESCAPED_SLASHES), ['ETag' => '"' . $env['hash'] . '"']);
                    $status = 200;
                }
            }
        } elseif ($path === '/fleet/v1/renew' && $req['method'] === 'POST') {
            $j = json_decode($req['body'], true);
            $sid = $san ?? 'src-unknown';
            if (isset($j['csr'])) {
                respond($conn, 200, json_encode(['client_cert' => issueClient($cnf, $j['csr'], $sid, $rootCert, $rootKey, $dir), 'not_after' => gmdate('Y-m-d\TH:i:s\Z', time() + 30 * 86400)]));
            } else {
                respond($conn, 422, '{}');
            }
            $status = 200;
        } elseif ($path === '/v1/logs' && $req['method'] === 'POST') {
            $fixed = $ctl['logs_status'] ?? null;
            if (is_int($fixed) && $logsFailed < ($ctl['logs_fail_n'] ?? PHP_INT_MAX)) {
                $logsFailed++;
                $extra = isset($ctl['retry_after']) ? ['Retry-After' => (string) $ctl['retry_after']] : [];
                respond($conn, $fixed, '{}', $extra);
                $status = $fixed;
            } else {
                $doc = json_decode($req['body'], true);
                $n = 0;
                $mismatch = false;
                foreach ((array) ($doc['resourceLogs'] ?? []) as $rl) {
                    $sid = null;
                    foreach ((array) ($rl['resource']['attributes'] ?? []) as $a) {
                        if (($a['key'] ?? '') === 'tt.source.id') {
                            $sid = $a['value']['stringValue'] ?? null;
                        }
                    }
                    $mismatch = $mismatch || $sid !== $san;
                    foreach ((array) ($rl['scopeLogs'] ?? []) as $sl) {
                        foreach ((array) ($sl['logRecords'] ?? []) as $rec) {
                            $ev = $rec['body']['stringValue'] ?? null;
                            if (is_string($ev)) {
                                file_put_contents($dir . '/events.ndjson', $ev . "\n", FILE_APPEND | LOCK_EX);
                                $n++;
                            }
                        }
                    }
                }
                $log['events'] = $n;
                $log['san_mismatch'] = $mismatch;
                respond($conn, 200, '{}');
                $status = 200;
            }
        } else {
            respond($conn, 404, '{}');
        }
        $log['status'] = $status;
        file_put_contents($dir . '/log.ndjson', json_encode($log, JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND | LOCK_EX);
        fclose($conn);
    }
}
