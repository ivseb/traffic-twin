<?php

declare(strict_types=1);

// Runs every conformance vector against the PHP sanitizer and compares byte for byte.
//
//   php scripts/run-vectors.php [--dir <conformance dir>] [--verbose] [id-prefix ...]
//
// Exit code 0 only if every selected vector passes. Mismatches print the vector id and both
// byte strings (conformance/README.md, "Writing a runner").

use TrafficTwin\Sanitizer\VectorRunner;

require __DIR__ . '/../src/autoload.php';

$args = array_slice($argv, 1);
$dir = realpath(__DIR__ . '/../../../conformance') ?: __DIR__ . '/../../../conformance';
$verbose = false;
$prefixes = [];
for ($i = 0; $i < count($args); $i++) {
    if ($args[$i] === '--dir') {
        $dir = realpath($args[++$i]);
    } elseif ($args[$i] === '--verbose' || $args[$i] === '-v') {
        $verbose = true;
    } else {
        $prefixes[] = $args[$i];
    }
}

$files = glob($dir . '/vectors/*.json');
sort($files);
$pass = 0;
$fail = 0;
$failed = [];
foreach ($files as $f) {
    $id = basename($f, '.json');
    if ($prefixes && !array_filter($prefixes, static fn (string $p): bool => str_starts_with($id, $p))) {
        continue;
    }
    $vec = VectorRunner::parse((string) file_get_contents($f));
    $exp = $vec->m['expected']->m;
    try {
        $got = VectorRunner::run($vec, $dir);
    } catch (Throwable $e) {
        $got = ['outcome' => 'error', 'error' => $e->getMessage() . ' at ' . $e->getFile() . ':' . $e->getLine()];
    }
    $ok = $got['outcome'] === $exp['outcome'];
    if ($ok && $exp['outcome'] === 'event') {
        $ok = $got['canonical'] === $exp['canonical'];
    }
    if ($ok && $exp['outcome'] === 'not_sampled') {
        $ok = ($got['sampled_by'] ?? null) === $exp['sampled_by'];
    }
    if ($ok && $exp['outcome'] === 'refused') {
        $ok = ($got['code'] ?? null) === $exp['code'];
    }
    if ($ok) {
        $pass++;
        if ($verbose) {
            echo "PASS $id\n";
        }
        continue;
    }
    $fail++;
    $failed[] = $id;
    echo "FAIL $id\n";
    $e = $exp['outcome'] === 'event' ? $exp['canonical'] : json_encode($exp);
    $g = $got['outcome'] === 'event' ? $got['canonical'] : json_encode($got);
    if ($verbose || (strlen($e) <= 2000 && strlen($g) <= 2000)) {
        echo "  expected: $e\n  got:      $g\n";
    } else {
        $d = 0;
        while ($d < strlen($e) && $d < strlen($g) && $e[$d] === $g[$d]) {
            $d++;
        }
        $from = max(0, $d - 150);
        printf("  first difference at byte %d (expected %d bytes, got %d bytes)\n", $d, strlen($e), strlen($g));
        echo '  expected: ...' . substr($e, $from, 400) . "\n";
        echo '  got:      ...' . substr($g, $from, 400) . "\n";
    }
}
printf("\nvectors: %d passed, %d failed, %d total (PHP %s)\n", $pass, $fail, $pass + $fail, PHP_VERSION);
if ($fail) {
    echo 'failed: ' . implode(' ', $failed) . "\n";
}
exit($fail ? 1 : 0);
