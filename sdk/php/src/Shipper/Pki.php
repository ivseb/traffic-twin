<?php

declare(strict_types=1);

namespace TrafficTwin\Shipper;

use TrafficTwin\Sanitizer\Utf8;

/** Certificate helpers for enrollment (fleet-api.v1.openapi.yaml): CA pin, CSR, PEM handling. Needs ext-openssl. */
final class Pki
{
    public const TOKEN_RE = '/^tte_[A-Za-z0-9_-]{32,128}\.([A-Za-z0-9_-]{43})$/D';

    /** The CA pin embedded in an enrollment token, or null if the token is malformed. */
    public static function tokenPin(string $token): ?string
    {
        return preg_match(self::TOKEN_RE, $token, $m) === 1 ? $m[1] : null;
    }

    /** DER bytes of the first certificate of a PEM block list, or null. */
    public static function derOfPem(string $pem): ?string
    {
        if (preg_match('/-----BEGIN CERTIFICATE-----([A-Za-z0-9+\/=\s]+)-----END CERTIFICATE-----/', $pem, $m) !== 1) {
            return null;
        }
        $der = base64_decode(preg_replace('/\s+/', '', $m[1]) ?? '', true);
        return $der === false ? null : $der;
    }

    /** @return list<string> DER of every certificate in a PEM bundle */
    public static function derBlocks(string $bundle): array
    {
        $out = [];
        if (preg_match_all('/-----BEGIN CERTIFICATE-----([A-Za-z0-9+\/=\s]+)-----END CERTIFICATE-----/', $bundle, $all) > 0) {
            foreach ($all[1] as $b) {
                $der = base64_decode(preg_replace('/\s+/', '', $b) ?? '', true);
                if ($der !== false) {
                    $out[] = $der;
                }
            }
        }
        return $out;
    }

    /** base64url(SHA-256(DER)) */
    public static function pinOf(string $der): string
    {
        return Utf8::b64url(hash('sha256', $der, true));
    }

    public static function pemOfDer(string $der): string
    {
        return "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE-----\n";
    }

    /**
     * True when $certPem verifies against $rootPem as the ONLY trust anchor (no system store),
     * with the certificates of $untrustedBundle as possible intermediates.
     */
    public static function verifiesAgainst(string $rootPem, string $certPem, string $untrustedBundle, string $tmpDir): bool
    {
        $tag = bin2hex(random_bytes(4));
        $rootFile = $tmpDir . '/.verify-root-' . $tag . '.pem';
        $interFile = $tmpDir . '/.verify-inter-' . $tag . '.pem';
        $old = umask(0077);
        try {
            if (@file_put_contents($rootFile, $rootPem) === false || @file_put_contents($interFile, $untrustedBundle) === false) {
                return false;
            }
            return @openssl_x509_checkpurpose($certPem, X509_PURPOSE_ANY, [$rootFile], $interFile) === true;
        } finally {
            umask($old);
            @unlink($rootFile);
            @unlink($interFile);
        }
    }

    /**
     * Opens a TLS connection without trusting anything, takes the self-signed root from the
     * chain the server presents and checks it against the pin. Returns the root as PEM, to be
     * used as the only trust anchor for the real request. This probe proves nothing about the
     * server (anyone can replay the public root in its chain): the caller must then verify the
     * server against the returned root, never accept a self-signed leaf (see Http).
     */
    public static function fetchPinnedRoot(string $host, int $port, string $pin, int $timeoutS = 10): string
    {
        $ctx = stream_context_create(['ssl' => [
            'capture_peer_cert' => true,
            'capture_peer_cert_chain' => true,
            'verify_peer' => false,
            'verify_peer_name' => false,
            'SNI_enabled' => !filter_var($host, FILTER_VALIDATE_IP),
            'peer_name' => $host,
        ]]);
        $fp = @stream_socket_client('ssl://' . (str_contains($host, ':') ? '[' . $host . ']' : $host) . ':' . $port, $errno, $errstr, $timeoutS, STREAM_CLIENT_CONNECT, $ctx);
        if ($fp === false) {
            throw new FleetError('enroll_tls_error');
        }
        try {
            $opts = stream_context_get_params($fp)['options']['ssl'] ?? [];
            $chain = $opts['peer_certificate_chain'] ?? [];
            if (!is_array($chain) || $chain === []) {
                throw new FleetError('enroll_no_peer_cert');
            }
            $root = null;
            foreach ($chain as $cert) {
                if (!openssl_x509_export($cert, $pem)) {
                    continue;
                }
                $info = openssl_x509_parse($pem);
                if (!is_array($info) || ($info['subject'] ?? null) !== ($info['issuer'] ?? 0)) {
                    continue;
                }
                if (!str_contains((string) ($info['extensions']['basicConstraints'] ?? ''), 'CA:TRUE')) {
                    continue;
                }
                $der = self::derOfPem($pem);
                if ($der !== null && hash_equals($pin, self::pinOf($der))) {
                    $root = $pem;
                    break;
                }
            }
            if ($root === null) {
                // Either the server did not include the root, or its root does not match the pin.
                throw new FleetError('enroll_pin_mismatch');
            }
            return $root;
        } finally {
            fclose($fp);
        }
    }

    /**
     * A new ECDSA P-256 key and a PKCS#10 request for it (the private key never leaves the host).
     *
     * @return array{keyPem: string, csrPem: string}
     */
    public static function generateCsr(string $commonName, string $tmpDir): array
    {
        $cnf = $tmpDir . '/.openssl-' . bin2hex(random_bytes(4)) . '.cnf';
        $old = umask(0077);
        file_put_contents($cnf, "[req]\ndefault_bits = 2048\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = x\n");
        umask($old);
        try {
            $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1', 'config' => $cnf]);
            if ($key === false) {
                throw new FleetError('csr_key_failed');
            }
            $csr = openssl_csr_new(['commonName' => $commonName], $key, ['digest_alg' => 'sha256', 'config' => $cnf]);
            if ($csr === false || !openssl_csr_export($csr, $csrPem) || !openssl_pkey_export($key, $keyPem, null, ['config' => $cnf])) {
                throw new FleetError('csr_failed');
            }
            return ['keyPem' => $keyPem, 'csrPem' => $csrPem];
        } finally {
            @unlink($cnf);
        }
    }
}
