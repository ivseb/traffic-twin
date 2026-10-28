#!/bin/sh
# Red team round 2, PHP SDK. Each script exits 1 when its finding is present. Repository mounted read-only.
#   test/redteam/php/run.sh            (from anywhere)
repo=$(cd "$(dirname "$0")/../../.." && pwd)
rc=0
for t in tls_mitm_test gzip_cap_test state_dir_perms_test diagnostics_leak_test; do
  echo "== $t"
  docker run --rm -v "$repo":/repo:ro -w /repo php:8.3-cli php -d error_reporting=-1 -d memory_limit=1G test/redteam/php/$t.php || rc=1
done
exit $rc
