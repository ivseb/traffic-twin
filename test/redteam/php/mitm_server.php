<?php

declare(strict_types=1);

/**
 * Red team helper: a TLS server that impersonates tt-core WITHOUT holding any key of the real
 * Fleet CA. It presents [self-signed attacker leaf for localhost/127.0.0.1, real root (public)]
 * and answers every request with an attacker-chosen enrollment / heartbeat. Invented data only.
 *
 *   php mitm_server.php <work dir>
 *
 * Reads <dir>/chain.pem, <dir>/leaf.key, <dir>/answer.json (or <dir>/answer.gz, sent with
 * Content-Encoding: gzip); writes <dir>/port when listening and
 * appends every request (request line + body) to <dir>/requests.log.
 */

$dir = $argv[1];
$ctx = stream_context_create(['ssl' => [
    'local_cert' => $dir . '/chain.pem',
    'local_pk' => $dir . '/leaf.key',
    'verify_peer' => false,
    'disable_compression' => true,
]]);
$srv = stream_socket_server('tls://127.0.0.1:0', $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx);
if ($srv === false) {
    fwrite(STDERR, "listen: $errstr\n");
    exit(1);
}
$name = stream_socket_get_name($srv, false);
file_put_contents($dir . '/port', substr($name, strrpos($name, ':') + 1));
while (true) {
    $c = @stream_socket_accept($srv, 30);
    if ($c === false) {
        continue;
    }
    stream_set_timeout($c, 5);
    $head = '';
    while (!str_contains($head, "\r\n\r\n")) {
        $chunk = fread($c, 8192);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $head .= $chunk;
    }
    if ($head === '') {
        fclose($c); // the pin probe: handshake only
        continue;
    }
    [$h, $body] = explode("\r\n\r\n", $head, 2) + [1 => ''];
    if (preg_match('/content-length:\s*(\d+)/i', $h, $m) === 1) {
        while (strlen($body) < (int) $m[1]) {
            $chunk = fread($c, 8192);
            if ($chunk === false || $chunk === '') {
                break;
            }
            $body .= $chunk;
        }
    }
    $answer = (string) file_get_contents($dir . '/answer.json');
    file_put_contents($dir . '/requests.log', strtok($h, "\r\n") . "\t" . $body . "\n", FILE_APPEND);
    $enc = '';
    if (is_file($dir . '/answer.gz')) {
        $answer = (string) file_get_contents($dir . '/answer.gz');
        $enc = "Content-Encoding: gzip\r\n";
    }
    fwrite($c, "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n" . $enc . "Content-Length: " . strlen($answer) . "\r\nConnection: close\r\n\r\n" . $answer);
    fclose($c);
}
