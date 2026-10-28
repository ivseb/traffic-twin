#!/usr/bin/env bash
# Overhead of the Node SDK (the build in sdk/node, installed from `npm pack` into the demo shop image):
# saturation throughput, latency and CPU of the application thread at several sampling rates,
# with the sanitizer threads at their default and at 0 (everything on the main thread).
#
# A separate shop ("ttb-shop", port 3100 on the demo host) with a carrier of its own and an SDK enrolled to a
# throwaway bench core (bench-core-lib.sh) is driven with oha (closed loop, 16 connections) on
# GET /customers/{id}/orders (the shop answers from memory: the cost of the SDK is not hidden by the
# carrier's latency). The live lab keeps running next to it: note the load average in the output.
#
#   test/lab/bench-sdk-node.sh [runs] [seconds]      (default 5 runs of 20 s per configuration)
#
# Per run it records req/s, p50/p99 latency and the CPU of the main thread (the application thread,
# /proc/<pid>/task/<pid>/stat) and of the whole process (main thread + sanitizer workers).
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
source "$REPO_DIR/test/e2e/lab-lib.sh"
source "$LAB_DIR/bench-core-lib.sh"
RUNS="${1:-5}"; SECS="${2:-20}"
OUT="$STATE_DIR/bench"; mkdir -p "$OUT"
R=/opt/tt-lab
CUST=CUS-000777
# ENDPOINT=list: GET /customers/{id}/orders (in memory, ~70 us); ENDPOINT=ship: GET /orders/{id}/shipment
# (an outbound call to the carrier, ~80 ms of I/O: the realistic case). CFGSET=full|short.
ENDPOINT="${ENDPOINT:-list}"; CFGSET="${CFGSET:-full}"; TAG="${ENDPOINT}"
RUNLOG="$OUT/sdk-node-runs-$TAG.jsonl"; : >"$RUNLOG"

cleanup() {
  ct "$DEMO" "docker rm -f ttb-shop ttb-carrier >/dev/null 2>&1; docker network rm ttbench >/dev/null 2>&1; rm -rf $R/state/bench-shop $R/bench.env" || true
  bench_core_down
}
if [[ -z "${KEEP:-}" ]]; then trap cleanup EXIT; fi

jwt() { printf '%s.%s.' "$(printf '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=\n' | tr '+/' '-_')" "$(printf '{"sub":"%s"}' "$1" | base64 | tr -d '=\n' | tr '+/' '-_')"; }
TOK="$(jwt $CUST)"

bench_core_up
CORE_URL_BENCH="$CORE_URL"
ct "$DEMO" "docker rm -f ttb-shop ttb-carrier >/dev/null 2>&1; docker network rm ttbench >/dev/null 2>&1; docker network create ttbench >/dev/null
rm -rf $R/state/bench-shop; install -d -m 0700 -o 1000 -g 1000 $R/state/bench-shop
docker run -d --name ttb-carrier --network ttbench -e PORT=8080 -e TIME_SCALE=240 tt-demo-go:local carrier >/dev/null"
printf 'TT_ENROLL_TOKEN=%s\n' "$TOKEN_NODE" | ct "$DEMO" "umask 077; cat > $R/bench.env"

start_shop() { # disabled threads(optional)
  local thr=""; [[ -n "${2:-}" ]] && thr="-e TT_SANITIZER_THREADS=$2"
  ct "$DEMO" "docker rm -f ttb-shop >/dev/null 2>&1; docker run -d --name ttb-shop --network ttbench -p 127.0.0.1:3100:3000 \
    -e PORT=3000 -e TIME_SCALE=240 -e CARRIER_BASE_URL=http://ttb-carrier:8080 -e TT_DISABLED=$1 $thr \
    --env-file $R/bench.env -e TT_ENROLL_URL=https://$CORE_HOST:4319 -e TT_SERVICE_NAME=shop-api \
    -e TT_HMAC_KEY_FILE=/run/secrets/hmac.keys -e TT_STATE_DIR=/state \
    -v $R/secrets/hmac.shop.keys:/run/secrets/hmac.keys:ro -v $R/state/bench-shop:/state \
    tt-lab-shop:local node --import @traffic-twin/sdk/register server.js >/dev/null"
  local i; for i in $(seq 1 40); do ct "$DEMO" "curl -fsS localhost:3100/__health >/dev/null" 2>/dev/null && return 0; sleep 1; done
  die "ttb-shop not healthy"
}

wait_capturing() {
  local i
  for i in $(seq 1 60); do
    req benchop GET "/api/v1/fleet/sources?group=demo"
    [[ "$(jqb 'map(select(.state=="capturing")) | length')" -ge 1 ]] && return 0
    sleep 3
  done
  die "SDK of ttb-shop not capturing"
}

set_sampling() { # bp | null
  req benchop GET "/api/v1/fleet/sources?group=demo"
  local src; src="$(jqb '.[0].source_id')"
  req benchop PUT "/api/v1/fleet/sources/$src/sampling" "{\"sampling_override_bp\":$1}"
  [[ "$CODE" == 204 ]] || die "sampling override: HTTP $CODE $BODY"
}

# one measured run on the demo host; prints a JSON line
measure() { # cfg run
  ct "$DEMO" "CFG=$1 RUN=$2 SECS=$SECS ENDPOINT=$ENDPOINT TOK='$TOK' CUST=$CUST bash -s" <<'EOS'
set -e
PID=$(docker inspect -f '{{.State.Pid}}' ttb-shop)
tick() { sed 's/.*) //' "$1" | awk '{print $12+$13}'; }
m0=$(tick /proc/$PID/task/$PID/stat); p0=$(tick /proc/$PID/stat)
if [ "$ENDPOINT" = ship ]; then URL=http://localhost:3100/orders/$(cat /tmp/ttb-oid)/shipment; else URL=http://localhost:3100/customers/$CUST/orders; fi
J=$(oha -z ${SECS}s -c 16 --no-tui --output-format json -H "Authorization: Bearer $TOK" $URL)
m1=$(tick /proc/$PID/task/$PID/stat); p1=$(tick /proc/$PID/stat)
nthreads=$(ls /proc/$PID/task | wc -l); load=$(cut -d' ' -f1 /proc/loadavg)
echo "$J" | jq -c --arg cfg "$CFG" --argjson run "$RUN" --argjson secs "$SECS" --argjson m $((m1-m0)) --argjson p $((p1-p0)) --argjson th "$nthreads" --arg load "$load" \
  '{cfg:$cfg, run:$run, rps:.summary.requestsPerSec, p50_ms:(.latencyPercentiles.p50*1000), p99_ms:(.latencyPercentiles.p99*1000), ok:.summary.successRate,
    app_cpu_pct:($m/100/$secs*100), proc_cpu_pct:($p/100/$secs*100), threads:$th, load1:($load|tonumber)}'
EOS
}

run_cfg() { # name disabled threads sampling(bp|null|"")
  local name="$1" dis="$2" thr="$3" samp="$4" i
  log "configuration $name (TT_DISABLED=$dis threads=${thr:-default} sampling=${samp:-n/a})"
  start_shop "$dis" "$thr"
  if [[ "$dis" == 0 ]]; then
    wait_capturing
    set_sampling "$samp"
    sleep 45   # heartbeat (30 s) delivers the override
  fi
  ct "$DEMO" "for i in 1 2 3 4 5 6 7 8 9 10; do curl -s -o /tmp/ttb-order.json -X POST localhost:3100/orders -H 'Authorization: Bearer $TOK' -d '{\"items\":[{\"sku\":\"SKU-MUG-001\",\"qty\":2}],\"email\":\"bench@example.com\",\"shippingAddress\":{\"fullName\":\"Bench Test\",\"line1\":\"Via Prova 1\",\"city\":\"Roma\",\"postcode\":\"00100\",\"country\":\"IT\"}}'; jq -r .id /tmp/ttb-order.json > /tmp/ttb-oid; done; sleep 4"
  ct "$DEMO" "U=http://localhost:3100/customers/$CUST/orders; [ '$ENDPOINT' = ship ] && U=http://localhost:3100/orders/\$(cat /tmp/ttb-oid)/shipment; oha -z 8s -c 16 --no-tui -H 'Authorization: Bearer $TOK' \$U >/dev/null 2>&1; true"
  for i in $(seq 1 "$RUNS"); do
    measure "$name" "$i" | tee -a "$RUNLOG" >&2
  done
}

run_cfg off          1 ""  ""
run_cfg thr-def-0pc  0 ""  0
run_cfg thr-def-5pc  0 ""  500
run_cfg thr-def-100pc 0 "" null
if [[ "$CFGSET" == full ]]; then
  run_cfg thr-0-0pc    0 0   0
  run_cfg thr-0-5pc    0 0   500
  run_cfg thr-0-100pc  0 0   null
fi
run_cfg off-again    1 ""  ""

# summary: median [min..max] per configuration; deltas against "off" (median of the two off sets)
jq -s '
  def med: sort | if length==0 then null else .[(length-1)/2|floor] end;
  group_by(.cfg) | map({cfg: .[0].cfg, n: length,
    rps: (map(.rps)|med), rps_min: (map(.rps)|min), rps_max: (map(.rps)|max),
    p50_ms: (map(.p50_ms)|med), p99_ms: (map(.p99_ms)|med),
    app_cpu: (map(.app_cpu_pct)|med), app_cpu_min: (map(.app_cpu_pct)|min), app_cpu_max: (map(.app_cpu_pct)|max),
    proc_cpu: (map(.proc_cpu_pct)|med), threads: (map(.threads)|max), load1: (map(.load1)|med)})' "$RUNLOG" >"$OUT/sdk-node-summary-$TAG.json"
jq -r '(map(select(.cfg|startswith("off"))|.rps)|add/length) as $base
  | .[] | [.cfg, (.rps|floor), "\(.rps_min|floor)..\(.rps_max|floor)", ((.rps/$base-1)*100|.*10|round/10), (.p50_ms*100|round/100), (.p99_ms*100|round/100),
           (.app_cpu|floor), "\(.app_cpu_min|floor)..\(.app_cpu_max|floor)", (.proc_cpu|floor), .threads, (.load1*100|round/100)] | @tsv' "$OUT/sdk-node-summary-$TAG.json" \
  | (echo -e "config\trps(median)\trps(min..max)\tvs off %\tp50 ms\tp99 ms\tapp cpu %\tapp cpu min..max\tproc cpu %\tthreads\tload1"; cat) | column -t -s "$(printf '\t')" | tee "$OUT/sdk-node-summary-$TAG.txt"
