<?php

declare(strict_types=1);

/**
 * RT-PHP-2 (medium): the response size cap of the PHP shipper is applied BEFORE decompression.
 *
 * sdk/php/src/Shipper/Http.php reads at most $maxBytes (8 MiB for policy/heartbeat, 64 KiB for the
 * intake), then, if the server says `Content-Encoding: gzip`, calls gzdecode() with no length
 * limit. The shipper never asks for gzip, yet any tt-core answer (or a MITM, see RT-PHP-1) can
 * send it: a ~40 KiB response inflates to 40 MiB (policy cap bypassed 5x); a few MiB inflate past
 * memory_limit and kill the shipper with a fatal error (crash loop; capture stops only after
 * policy_max_age because workers keep the last status.json).
 *
 * Here the server certificate is properly issued by the trusted root (no MITM needed).
 *
 * Run (exit 1 = vulnerable, 0 = fixed):
 *   docker run --rm -v "$PWD":/repo:ro -w /repo php:8.3-cli php test/redteam/php/gzip_cap_test.php
 */

require __DIR__ . '/../../../sdk/php/src/autoload.php';

use TrafficTwin\Shipper\FleetError;
use TrafficTwin\Shipper\Http;

$dir = sys_get_temp_dir() . '/tt-rt-gzip-' . bin2hex(random_bytes(4));
mkdir($dir, 0700, true);
$cnf = $dir . '/openssl.cnf';
file_put_contents($cnf, "[req]\ndefault_bits = 2048\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = x\n"
    . "[v3_ca]\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign,cRLSign\n"
    . "[v3_leaf]\nbasicConstraints = CA:FALSE\nsubjectAltName = DNS:localhost,IP:127.0.0.1\nkeyUsage = digitalSignature\nextendedKeyUsage = serverAuth\n");
$key = static fn () => openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1', 'config' => $cnf]);
$rootKey = $key();
$root = openssl_csr_sign(openssl_csr_new(['commonName' => 'tt-fleet-root'], $rootKey, ['config' => $cnf]), null, $rootKey, 30,
    ['digest_alg' => 'sha256', 'config' => $cnf, 'x509_extensions' => 'v3_ca'], 1);
openssl_x509_export($root, $rootPem);
$leafKey = $key();
$leaf = openssl_csr_sign(openssl_csr_new(['commonName' => 'localhost'], $leafKey, ['config' => $cnf]), $root, $rootKey, 30,
    ['digest_alg' => 'sha256', 'config' => $cnf, 'x509_extensions' => 'v3_leaf'], 2);
openssl_x509_export($leaf, $leafPem);
openssl_pkey_export($leafKey, $leafKeyPem, null, ['config' => $cnf]);
file_put_contents($dir . '/root.pem', $rootPem);
file_put_contents($dir . '/chain.pem', $leafPem . $rootPem);
file_put_contents($dir . '/leaf.key', $leafKeyPem);
file_put_contents($dir . '/answer.json', '{}');
// 40 MiB of JSON whitespace around an empty object: ~40 KiB on the wire.
file_put_contents($dir . '/answer.gz', gzencode('{' . str_repeat(' ', 40 << 20) . '}', 9));
$wire = filesize($dir . '/answer.gz');

$proc = proc_open([PHP_BINARY, __DIR__ . '/mitm_server.php', $dir], [0 => ['file', '/dev/null', 'r'], 1 => ['file', $dir . '/srv.out', 'w'], 2 => ['file', $dir . '/srv.out', 'a']], $pipes);
for ($i = 0; $i < 100 && !is_file($dir . '/port'); $i++) {
    usleep(50000);
}
$port = (int) @file_get_contents($dir . '/port');
$fail = 0;
try {
    $r = Http::request('GET', 'https://localhost:' . $port . '/fleet/v1/policy', [], null, ['cafile' => $dir . '/root.pem'], 5);
    $n = strlen($r['body']);
    if ($n > (8 << 20)) {
        echo "VULNERABLE: $wire bytes on the wire became a $n-byte policy body (cap 8388608)\n";
        $fail = 1;
    } else {
        echo "ok: body capped at $n bytes\n";
    }
} catch (FleetError $e) {
    echo "ok: refused ({$e->getMessage()})\n";
}
proc_terminate($proc, 9);
exec('rm -rf ' . escapeshellarg($dir));
exit($fail);
