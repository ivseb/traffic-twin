<?php

declare(strict_types=1);

/**
 * RT-PHP-3 (low): a pre-existing TT_STATE_DIR (or spool dir) keeps its permissions.
 *
 * sdk/php/src/State/Store.php ensure() and Capture/Spool.php ensureDir() only mkdir(0700) when the
 * directory is missing. A directory created by the deployment with 0755/0777 is used as is: files
 * are 0600, but in a writable directory another local user can rename files over status.json,
 * whose `signing_keys` workers pin without any endorsement check (Runtime::evaluate) and whose
 * `kill`/`min_issued_seq` they trust.
 *
 * Run (exit 1 = vulnerable, 0 = fixed):
 *   docker run --rm -v "$PWD":/repo:ro -w /repo php:8.3-cli php test/redteam/php/state_dir_perms_test.php
 */

require __DIR__ . '/../../../sdk/php/src/autoload.php';

use TrafficTwin\Capture\Spool;
use TrafficTwin\State\Store;

$dir = sys_get_temp_dir() . '/tt-rt-perm-' . bin2hex(random_bytes(4));
mkdir($dir, 0777);
chmod($dir, 0777);
mkdir($dir . '/spool', 0777);
chmod($dir . '/spool', 0777);
$s = new Store($dir);
$s->writeJson('status.json', ['kill' => false]);
(new Spool($dir . '/spool'))->append("0\t-\t-\tsha256:x\t{}");
clearstatcache();
$fail = 0;
foreach ([$dir => 0700, $dir . '/spool' => 0700, $dir . '/status.json' => 0600] as $p => $want) {
    $got = fileperms($p) & 0777;
    printf("%s %o (want %o)\n", basename($p), $got, $want);
    if ($got !== $want) {
        $fail = 1;
    }
}
foreach (glob($dir . '/spool/seg-*') as $seg) {
    printf("%s %o (want 600)\n", basename($seg), fileperms($seg) & 0777);
    $fail = $fail || (fileperms($seg) & 0777) !== 0600 ? 1 : $fail;
}
echo $fail ? "VULNERABLE: pre-existing state/spool directories keep loose permissions\n" : "ok\n";
exec('rm -rf ' . escapeshellarg($dir));
exit($fail);
