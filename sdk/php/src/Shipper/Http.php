<?php

declare(strict_types=1);

namespace TrafficTwin\Shipper;

/**
 * Minimal HTTPS client on PHP stream contexts (no ext-curl needed): one request per connection,
 * optional client certificate (mTLS). Response bodies are capped, after decompression too.
 * Errors are reported as codes, never with payload.
 *
 * TLS: the server chain must verify against the given CA file as the ONLY trust anchor (the
 * pinned root at enrollment, the Fleet CA chain afterwards; the system store is never loaded
 * when a CA file is set), and the certificate must match the host name. Self-signed leaves are
 * never accepted: `allow_self_signed` turns "self-signed leaf" into success whatever the CA
 * file says (RT-PHP-1), so it is explicitly off.
 */
final class Http
{
    /** Input slice fed to the inflater per step: bounds the memory of one step (~1 MiB out). */
    private const INFLATE_STEP = 1024;

    /**
     * @param array<string, string> $headers
     * @param array{cafile: string, local_cert?: string} $tls
     * @return array{status: int, headers: array<string, string>, body: string}
     * @throws FleetError network failures
     */
    public static function request(string $method, string $url, array $headers, ?string $body, array $tls, int $timeoutS = 15, int $maxBytes = 8 << 20): array
    {
        $parts = parse_url($url);
        if ($parts === false || ($parts['scheme'] ?? '') !== 'https' || !isset($parts['host'])) {
            throw new FleetError('url_not_https');
        }
        $cafile = $tls['cafile'] ?? '';
        if ($cafile === '' || !is_file($cafile)) {
            throw new FleetError('tls_no_trust_anchor');
        }
        $host = trim($parts['host'], '[]');
        $h = '';
        foreach ($headers as $k => $v) {
            $h .= $k . ': ' . $v . "\r\n";
        }
        if (!isset(array_change_key_case($headers)['accept-encoding'])) {
            $h .= "Accept-Encoding: identity\r\n";
        }
        if ($body !== null) {
            $h .= 'Content-Length: ' . strlen($body) . "\r\n";
        }
        $ssl = [
            'verify_peer' => true,
            'verify_peer_name' => true,
            'allow_self_signed' => false,
            'cafile' => $cafile,
            'peer_name' => $host,
            'SNI_enabled' => filter_var($host, FILTER_VALIDATE_IP) === false,
            'disable_compression' => true,
        ];
        if (isset($tls['local_cert'])) {
            $ssl['local_cert'] = $tls['local_cert'];
        }
        $ctx = stream_context_create([
            'http' => [
                'method' => $method,
                'header' => $h,
                'content' => $body ?? '',
                'ignore_errors' => true,
                'timeout' => $timeoutS,
                'follow_location' => 0,
                'protocol_version' => 1.1,
            ],
            'ssl' => $ssl,
        ]);
        // Collect the diagnostics of the open (several: "SSL operation failed ... certificate verify
        // failed", then "Failed to open stream"); only a code derived from them leaves this method.
        $diag = '';
        set_error_handler(static function (int $no, string $msg) use (&$diag): bool {
            $diag .= $msg . "\n";
            return true;
        });
        try {
            $fp = fopen($url, 'rb', false, $ctx);
        } finally {
            restore_error_handler();
        }
        if ($fp === false) {
            throw new FleetError(self::codeOf($diag));
        }
        try {
            stream_set_timeout($fp, $timeoutS);
            $data = stream_get_contents($fp, $maxBytes + 1);
            $meta = stream_get_meta_data($fp);
            if ($data === false || strlen($data) > $maxBytes) {
                throw new FleetError('response_too_large');
            }
            $status = 0;
            $rh = [];
            foreach ((array) ($meta['wrapper_data'] ?? []) as $line) {
                if (!is_string($line)) {
                    continue;
                }
                if (preg_match('#^HTTP/\d(?:\.\d)? (\d{3})#', $line, $m) === 1) {
                    $status = (int) $m[1];
                    $rh = [];
                    continue;
                }
                $c = strpos($line, ':');
                if ($c > 0) {
                    $rh[strtolower(substr($line, 0, $c))] = trim(substr($line, $c + 1));
                }
            }
            if ($status === 0) {
                throw new FleetError('bad_response');
            }
            $enc = strtolower($rh['content-encoding'] ?? '');
            if ($enc !== '' && $enc !== 'identity') {
                if ($enc !== 'gzip' || !function_exists('inflate_init')) {
                    throw new FleetError('unsupported_content_encoding');
                }
                $data = self::gunzip($data, $maxBytes);
                unset($rh['content-encoding']);
            }
            return ['status' => $status, 'headers' => $rh, 'body' => $data];
        } finally {
            fclose($fp);
        }
    }

    /**
     * Inflates a gzip body a slice at a time and refuses it as soon as the output passes
     * $maxBytes (a few KiB on the wire can inflate to gigabytes).
     *
     * @throws FleetError response_too_large | bad_content_encoding
     */
    public static function gunzip(string $data, int $maxBytes): string
    {
        $z = @inflate_init(ZLIB_ENCODING_GZIP);
        if ($z === false) {
            throw new FleetError('bad_content_encoding');
        }
        $out = '';
        $n = strlen($data);
        for ($i = 0; $i < $n; $i += self::INFLATE_STEP) {
            $last = $i + self::INFLATE_STEP >= $n;
            $part = @inflate_add($z, substr($data, $i, self::INFLATE_STEP), $last ? ZLIB_FINISH : ZLIB_SYNC_FLUSH);
            if ($part === false) {
                throw new FleetError('bad_content_encoding');
            }
            if (strlen($out) + strlen($part) > $maxBytes) {
                throw new FleetError('response_too_large');
            }
            $out .= $part;
        }
        if (inflate_get_status($z) !== ZLIB_STREAM_END) {
            throw new FleetError('bad_content_encoding');
        }
        return $out;
    }

    private static function codeOf(string $msg): string
    {
        $m = strtolower($msg);
        return match (true) {
            str_contains($m, 'certificate') || str_contains($m, 'ssl') || str_contains($m, 'tls') => 'tls_error',
            str_contains($m, 'timed out') => 'timeout',
            str_contains($m, 'refused') => 'refused',
            str_contains($m, 'resolve') || str_contains($m, 'getaddrinfo') => 'dns',
            default => 'network',
        };
    }
}
