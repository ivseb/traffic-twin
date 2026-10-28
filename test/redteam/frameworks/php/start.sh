#!/bin/sh
# Red team round 3, PHP: the shipper (long-running process, as documented)
# next to the web server. The PHP built-in server (cli-server SAPI) prints an
# access log line per request on stderr: those lines are the server's own
# log, not the SDK's, and fw_test.go filters them (stackInfo.logFilter).
set -eu
if [ "${TT_DISABLED:-}" != "1" ]; then
  php /app/vendor/bin/tt-shipper &
fi
exec php -d variables_order=EGPCS -S 0.0.0.0:8080 -t /app/public /app/public/index.php
