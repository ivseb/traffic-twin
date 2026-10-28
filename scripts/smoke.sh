#!/bin/sh
# Smoke test of a built tt binary: it starts the single-host trial (`tt dev up`)
# and checks that the embedded UI and the readiness probe answer.
#
#   scripts/smoke.sh [path/to/tt]        (default: bin/tt)
#
# TT_SMOKE_ADMIN / TT_SMOKE_INTAKE change the loopback addresses.
set -eu

bin=${1:-bin/tt}
admin=${TT_SMOKE_ADMIN:-127.0.0.1:17070}
intake=${TT_SMOKE_INTAKE:-127.0.0.1:14318}
dir=$(mktemp -d)
log="$dir/tt.log"
pid=

cleanup() {
  if [ -n "$pid" ]; then kill -INT "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  rm -rf "$dir"
}
trap cleanup EXIT

"$bin" version

"$bin" dev up -dir "$dir/data" -admin "$admin" -intake "$intake" >"$log" 2>&1 &
pid=$!

# The trial uses a self-signed loopback certificate: -k is expected here.
ready=
for _ in $(seq 1 100); do
  if curl -fsSk "https://$admin/readyz" >/dev/null 2>&1; then ready=1; break; fi
  if ! kill -0 "$pid" 2>/dev/null; then break; fi
  sleep 0.2
done
if [ -z "$ready" ]; then
  echo "tt dev up did not become ready; its output:" >&2
  cat "$log" >&2
  exit 1
fi
curl -fsSk "https://$admin/" | grep -q '<title>traffic-twin</title>'
echo "ok: tt dev up serves the UI and /readyz"
