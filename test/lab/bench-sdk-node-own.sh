#!/usr/bin/env bash
# The SDK author's own benchmark (sdk/node/bench/overhead.mjs: app + fake tt-core in one container, no
# external load tool) run on the demo host, which measures CPU of the request thread and of all threads per request.
# Copies sdk/node (built: dist/) to the demo host and runs it in node:24-alpine for several endpoint/sampling pairs.
#   test/lab/bench-sdk-node-own.sh [rounds] [seconds]
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
ROUNDS="${1:-3}"; SECS="${2:-8}"
(cd "$REPO_DIR/sdk/node" && [[ -d dist ]] || npm run build >/dev/null)
(cd "$REPO_DIR/sdk/node" && COPYFILE_DISABLE=1 tar -czf "$STATE_DIR/sdknode.tgz" --exclude=node_modules . 2>/dev/null)
put "$DEMO" "$STATE_DIR/sdknode.tgz" /opt/tt-lab/sdknode.tgz
ct "$DEMO" "rm -rf /opt/tt-lab/sdknode && mkdir /opt/tt-lab/sdknode && tar -xzf /opt/tt-lab/sdknode.tgz -C /opt/tt-lab/sdknode 2>/dev/null"
for cfg in "health 10000" "health 500" "health 0" "orders 10000" "orders 500" "orders 0"; do
  ep="${cfg% *}"; bp="${cfg#* }"
  echo "== endpoint=$ep (io 2 ms) sampling=$((bp/100))%"
  ct "$DEMO" "docker run --rm -v /opt/tt-lab/sdknode:/sdk -w /sdk node:24-alpine node bench/overhead.mjs --endpoint $ep --io-ms 2 --seconds $SECS --rounds $ROUNDS --rate-bp $bp 2>&1 | grep -E 'p50 added|app CPU per request \(request|CPU per request under|saturation \(|throughput delta'"
done
