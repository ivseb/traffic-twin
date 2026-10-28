<?php

declare(strict_types=1);

/**
 * Guard (passes today): the PHP sanitizer emits no PHP diagnostic (warning, notice, deprecation)
 * and no output while sanitizing every conformance vector, plus mutated copies that carry a
 * unique canary in the path, query, headers, cookies and bodies. A diagnostic such as
 * `Undefined array key "<value>"` would land in the application's error log or response with
 * display_errors on. The canary must also never appear in a refusal code.
 *
 * Run (exit 1 = leak or diagnostic):
 *   docker run --rm -v "$PWD":/repo:ro -w /repo php:8.3-cli php -d error_reporting=-1 test/redteam/php/diagnostics_leak_test.php
 */

require __DIR__ . '/../../../sdk/php/src/autoload.php';

use TrafficTwin\Sanitizer\PObj;
use TrafficTwin\Sanitizer\VectorRunner;

$root = realpath(__DIR__ . '/../../../conformance');
$canary = 'Cnry' . bin2hex(random_bytes(6));
$diag = [];
set_error_handler(static function (int $no, string $msg, string $file, int $line) use (&$diag): bool {
    if ((error_reporting() & $no) === 0) {
        return true; // silenced with @ (frameworks' handlers skip these too)
    }
    $diag[] = "$no $msg at " . basename($file) . ":$line";
    return true;
});

$mutate = static function (PObj $vec) use ($canary): PObj {
    $in = $vec->m['input'] ?? null;
    if (!$in instanceof PObj) {
        return $vec;
    }
    $i = $in->m;
    $i['raw_path'] = '/' . $canary . (is_string($i['raw_path'] ?? null) ? $i['raw_path'] : '/x');
    $i['raw_query'] = $canary . '=' . $canary . '&a=' . $canary;
    $h = is_array($i['req_headers'] ?? null) ? $i['req_headers'] : [];
    $h[] = ['X-' . $canary, $canary];
    $h[] = ['Cookie', $canary . '=' . $canary];
    $h[] = ['Authorization', 'Bearer ' . $canary];
    $i['req_headers'] = $h;
    $i['req_body'] = '{"' . $canary . '":"' . $canary . '","n":[' . str_repeat('{"' . $canary . '":1},', 5) . '0]}';
    $rh = is_array($i['resp_headers'] ?? null) ? $i['resp_headers'] : [];
    $rh[] = ['Set-Cookie', $canary . '=' . $canary];
    $i['resp_headers'] = $rh;
    $i['resp_body'] = '<html>' . $canary . '</html>';
    $in->m = $i;
    return $vec;
};

$runs = 0;
$leaks = [];
foreach (glob($root . '/vectors/*.json') as $f) {
    foreach ([false, true] as $mut) {
        $vec = VectorRunner::parse((string) file_get_contents($f));
        if ($mut) {
            $vec = $mutate($vec);
        }
        ob_start();
        try {
            $got = VectorRunner::run($vec, $root);
        } catch (\Throwable $e) {
            $got = ['outcome' => 'error', 'code' => $e->getMessage()];
        }
        $out = (string) ob_get_clean();
        $runs++;
        if ($out !== '') {
            $leaks[] = basename($f) . ': output ' . substr($out, 0, 200);
        }
        if (str_contains((string) ($got['code'] ?? ''), $canary)) {
            $leaks[] = basename($f) . ': canary in refusal code/message';
        }
    }
}
restore_error_handler();
foreach ($diag as $d) {
    if (str_contains($d, $canary)) {
        $leaks[] = 'diagnostic with canary: ' . $d;
    }
}
printf("%d runs, %d diagnostics, %d leaks\n", $runs, count($diag), count($leaks));
foreach (array_slice(array_unique($diag), 0, 10) as $d) {
    echo "  diag: $d\n";
}
foreach (array_slice($leaks, 0, 10) as $l) {
    echo "  LEAK: $l\n";
}
exit($leaks === [] && $diag === [] ? 0 : 1);
