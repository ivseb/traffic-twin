#!/usr/bin/env bash
# Smoke test of the demo: bring the stack up with an accelerated clock, let
# the fake customers run, check the produced counts against the ground truth
# through /__truth, tear everything down. Exit code 0 only if all checks pass.
#
#   ./smoke.sh                     # defaults below
#   DURATION=120s ./smoke.sh       # longer run
set -euo pipefail

cd "$(dirname "$0")"

export TIME_SCALE="${TIME_SCALE:-2880}"   # 1 real second = 48 simulated minutes; 30 s = 1 day
export DURATION="${DURATION:-90s}"        # loadgen run time (real)
export CUSTOMERS="${CUSTOMERS:-2000}"
export SEED="${SEED:-42}"
export SHOP_PORT="${SHOP_PORT:-0}"        # 0 = random free host port, avoids clashes
export CARRIER_PORT="${CARRIER_PORT:-0}"
PROJECT="tt-demo-smoke-$$"
compose() { docker compose -p "$PROJECT" "$@"; }

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "--- last logs ---"
    compose logs --tail=20 carrier shop loadgen || true
  fi
  echo "--- teardown ---"
  compose --profile tools down -v --remove-orphans >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

echo "--- build & start (TIME_SCALE=$TIME_SCALE, DURATION=$DURATION, CUSTOMERS=$CUSTOMERS, SEED=$SEED) ---"
compose build --quiet
# Same simulated clock for every container, starting now (after the build).
export CLOCK_ANCHOR="${CLOCK_ANCHOR:-$(date +%s)}"
compose up -d --wait carrier shop
compose up -d loadgen

echo "--- loadgen running for $DURATION ---"
compose wait loadgen >/dev/null || true
code="$(docker inspect -f '{{.State.ExitCode}}' "$(compose ps -a -q loadgen)")"
compose logs --no-log-prefix loadgen | sed -n '/loadgen summary/,$p'
if [ "$code" != "0" ]; then
  echo "loadgen exited with code $code"
  exit 1
fi

echo "--- checking ground truth ---"
compose --profile tools run --rm --no-deps truthcheck
