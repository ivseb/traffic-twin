#!/usr/bin/env bash
# Overhead of the Node SDK on the demo shop and latency added by tt-egress.
# Runs oha (https://github.com/hatoo/oha, static binary in /usr/local/bin on the demo host)
# against the real stack of /opt/tt-lab. The loadgen is stopped for the duration
# and restarted at the end. Results (oha JSON) go to test/lab/.state/bench/.
#
#   test/lab/bench-overhead.sh [sdk|egress|all]      (default all)
#
# Modes of the SDK: off (TT_DISABLED=1), 5% and 100% sampling. The sampling is
# set through the Fleet API (per-source override, delivered with the heartbeat),
# exactly as an operator would.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
source "$REPO_DIR/test/e2e/lab-lib.sh"
OUT="$STATE_DIR/bench"; mkdir -p "$OUT"
WORK="$STATE_DIR/e2e"; CA_CERT="$STATE_DIR/pki/lab-ca.crt"
R=/opt/tt-lab
DC="cd $R && docker compose -f compose.yml --env-file .env"
LAT_RATE="${LAT_RATE:-150}"; LAT_SECS="${LAT_SECS:-45}"; SAT_SECS="${SAT_SECS:-25}"

# the sampling override of a source is set with the operator's session
operator_sampling() { # bp|null
  local pw src
  pw="$(ct "$CORE" "grep '^PW_e2e_operator=' /etc/tt-lab/credentials.env | cut -d= -f2-")"
  login e2e_operator "$pw"
  req e2e_operator GET "/api/v1/fleet/sources?group=demo"
  src="$(jqb '.[] | select(.kind=="sdk-node") | .source_id')"
  req e2e_operator PUT "/api/v1/fleet/sources/$src/sampling" "{\"sampling_override_bp\":$1}"
  [[ "$CODE" == 204 ]] || die "sampling override: HTTP $CODE $BODY"
}

jwt() { printf '%s.%s.' "$(printf '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=\n' | tr '+/' '-_')" "$(printf '{"sub":"%s"}' "$1" | base64 | tr -d '=\n' | tr '+/' '-_')"; }

wait_shop() { local i; for i in $(seq 1 40); do ct "$DEMO" "curl -fsS localhost:3000/__health >/dev/null" 2>/dev/null && return 0; sleep 1; done; die "shop not healthy"; }

sdk_modes() {
  local cust=CUS-000777 tok
  tok="$(jwt $cust)"
  ct "$DEMO" "$DC stop loadgen" >&2
  local mode
  for mode in off pct5 pct100; do
    log "SDK mode: $mode"
    case "$mode" in
      off) "$LAB_DIR/deploy-demo.sh" restart-shop SHOP_TT_DISABLED=1 >&2 ;;
      pct5|pct100) "$LAB_DIR/deploy-demo.sh" restart-shop SHOP_TT_DISABLED=0 >&2 ;;
    esac
    wait_shop
    if [[ "$mode" != off ]]; then
      # wait for capture, then set the sampling and give the heartbeat (30 s) time to deliver it
      sleep 20
      operator_sampling "$([[ $mode == pct5 ]] && echo 500 || echo null)"
      sleep 40
    fi
    # five orders for the customer so that the list has a realistic body
    ct "$DEMO" "for i in 1 2 3 4 5; do curl -s -o /dev/null -X POST localhost:3000/orders -H 'Authorization: Bearer $tok' -H \"Idempotency-Key: bench-$mode-\$i-\$RANDOM\" -d '{\"items\":[{\"sku\":\"SKU-MUG-001\",\"qty\":2}],\"email\":\"bench@example.com\",\"shippingAddress\":{\"fullName\":\"Bench Test\",\"line1\":\"Via Prova 1\",\"city\":\"Roma\",\"postcode\":\"00100\",\"country\":\"IT\"}}'; done"
    local url="http://localhost:3000/customers/$cust/orders"
    ct "$DEMO" "oha -z 10s -q 100 -c 16 --no-tui -H 'Authorization: Bearer $tok' $url >/dev/null 2>&1"   # warm-up
    log "  latency run: ${LAT_RATE} req/s for ${LAT_SECS}s"
    ct "$DEMO" "oha -z ${LAT_SECS}s -q $LAT_RATE -c 64 --no-tui --output-format json -H 'Authorization: Bearer $tok' $url" >"$OUT/sdk-$mode-latency.json"
    log "  saturation run: 16 connections for ${SAT_SECS}s"
    ct "$DEMO" "oha -z ${SAT_SECS}s -c 16 --no-tui --output-format json -H 'Authorization: Bearer $tok' $url" >"$OUT/sdk-$mode-saturation.json"
    ct "$DEMO" "docker stats --no-stream --format '{{.Name}} {{.CPUPerc}} {{.MemUsage}}' tt-lab-shop-1" >"$OUT/sdk-$mode-shop-stats.txt"
  done
  # back to normal: SDK on, no override, loadgen running
  operator_sampling null
  "$LAB_DIR/deploy-demo.sh" restart-shop SHOP_TT_DISABLED=0 >&2
  ct "$DEMO" "$DC start loadgen" >&2
}

egress_latency() {
  ct "$DEMO" "$DC stop loadgen" >&2
  local net=tt-lab_default
  local what url
  for what in direct via-egress; do
    case "$what" in
      direct) url='http://carrier:8080/v1/shipments?orderId=ORD-BENCH' ;;
      via-egress) url='http://tt-egress:9090/carrier/v1/shipments?orderId=ORD-BENCH' ;;
    esac
    log "carrier $what"
    ct "$DEMO" "docker run --rm --network $net -v /usr/local/bin/oha:/oha:ro alpine:3.20 /oha -z 10s -q 100 -c 16 --no-tui $url >/dev/null 2>&1"
    ct "$DEMO" "docker run --rm --network $net -v /usr/local/bin/oha:/oha:ro alpine:3.20 /oha -z 60s -q 100 -c 16 --no-tui --output-format json $url" >"$OUT/egress-$what.json"
  done
  ct "$DEMO" "curl -s localhost:9090/_tt/health" >"$OUT/egress-health.json"
  ct "$DEMO" "$DC start loadgen" >&2
}

case "${1:-all}" in
  sdk) sdk_modes ;;
  egress) egress_latency ;;
  all) sdk_modes; egress_latency ;;
  *) die "usage: $0 [sdk|egress|all]" ;;
esac
log "results in $OUT"
for f in "$OUT"/*.json; do
  [[ "$(basename "$f")" == egress-health.json ]] && continue
  printf '%-34s ' "$(basename "$f")"
  jq -r '[.summary.requestsPerSec, (.latencyPercentiles.p50*1000), (.latencyPercentiles.p99*1000), .summary.successRate] | map(tostring) | join("  rps/p50ms/p99ms/ok: ")' "$f" 2>/dev/null || echo "?"
done
