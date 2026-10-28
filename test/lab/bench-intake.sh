#!/usr/bin/env bash
# Events/s accepted by the intake of tt-core, and core CPU/RSS under that load.
#
# A throwaway second tt-core + keyguard (bench-core-lib.sh) runs on the core and keyguard hosts so that the
# lab's live data is not touched; it is deleted at the end. intakebench (test/lab/intakebench)
# runs on the demo host with N enrolled sources and steps through target rates.
#
#   test/lab/bench-intake.sh [rates]      e.g. "1000,2000,4000,8000,16000"
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
source "$REPO_DIR/test/e2e/lab-lib.sh"
source "$LAB_DIR/bench-core-lib.sh"
RATES="${1:-1000,2000,4000,8000,12000}"
SOURCES="${SOURCES:-6}"; STEP="${STEP:-20s}"
OUT="$STATE_DIR/bench"; mkdir -p "$OUT"
if [[ -z "${KEEP:-}" ]]; then trap bench_core_down EXIT; fi

log "building intakebench (linux/amd64)"
(cd "$REPO_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$STATE_DIR/bin/intakebench" ./test/lab/intakebench)
put "$DEMO" "$STATE_DIR/bin/intakebench" /opt/tt-lab/bin/intakebench 0755

bench_core_up
PID="$(ct "$CORE" "systemctl show -p MainPID --value $BENCH_UNIT")"
ct "$CORE" "grep -E 'VmRSS|VmHWM' /proc/$PID/status; systemctl show -p CPUUsageNSec --value $BENCH_UNIT" >"$OUT/core-before.txt"
# sample RSS and CPU of the bench core every second while the load runs
ct "$CORE" "nohup sh -c 'while kill -0 $PID 2>/dev/null; do echo \$(date +%s) \$(awk \"/VmRSS/{print \\\$2}\" /proc/$PID/status) \$(systemctl show -p CPUUsageNSec --value $BENCH_UNIT); sleep 1; done' > /tmp/bench-core.samples 2>&1 &"

log "load: $SOURCES sources, rates $RATES, $STEP per step"
printf '%s\n' "$TOKEN_GO" | ct "$DEMO" "read -r TT_ENROLL_TOKEN; export TT_ENROLL_TOKEN; /opt/tt-lab/bin/intakebench -enroll-url https://$CORE_HOST:4319 -hmac-key-file /opt/tt-lab/secrets/hmac.shop.keys -sources $SOURCES -rates $RATES -duration $STEP" | tee "$OUT/intake.txt"

ct "$CORE" "cat /tmp/bench-core.samples; rm -f /tmp/bench-core.samples" >"$OUT/core-samples.txt" || true
ct "$CORE" "grep -E 'VmRSS|VmHWM' /proc/$PID/status; ls -la /var/lib/tt-core-bench/ | head -8" | tee -a "$OUT/core-before.txt"
awk 'NR>1 && $2>max {max=$2} END {printf "peak RSS of the bench core: %.0f MiB\n", max/1024}' "$OUT/core-samples.txt" | tee -a "$OUT/intake.txt"
awk 'NR==1{t0=$1;c0=$3} {t1=$1;c1=$3} END {printf "mean CPU of the bench core over the run: %.0f%% of one core (%d s)\n", (c1-c0)/1e9/(t1-t0)*100, t1-t0}' "$OUT/core-samples.txt" | tee -a "$OUT/intake.txt"
