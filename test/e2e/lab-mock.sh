#!/usr/bin/env bash
# Phases "mock" and "wiremock" of test/e2e/lab-e2e.sh (sourced by it).

# A valid order body for the pack's contract (invented data).
ORDER_BODY='{"items":[{"sku":"SKU-MUG-001","qty":2}],"email":"anna.rossi@example.com","shippingAddress":{"fullName":"Anna Rossi","line1":"Via Inventata 2","city":"Roma","postcode":"00100","country":"IT"}}'

phase_mock() {
  log "== mock: tt mock on the demo host serves the signed pack"
  local pack; pack="$(<"$WORK/pack.id")"
  [[ -s "$WORK/current.ttpack" ]] || die "no pack downloaded yet: run the world phase first"
  put "$DEMO" "$WORK/current.ttpack" "$DEMO_R/packs/current.ttpack.new" 0644
  ct "$DEMO" "mv -f $DEMO_R/packs/current.ttpack.new $DEMO_R/packs/current.ttpack && systemctl enable tt-mock >/dev/null 2>&1; systemctl restart tt-mock"
  MOCK_TOKEN="$(ct "$DEMO" "grep '^TT_CONTROL_TOKEN=' /etc/tt-mock/mock.env | cut -d= -f2-")"
  local i ok=0
  for i in $(seq 1 30); do mockc GET /__tt/health; [[ "$CODE" == 200 ]] && { ok=1; break; }; sleep 1; done
  check "tt-mock is up with the pack (signature verified at start)" test "$ok" = 1
  [[ "$ok" == 1 ]] || { ct "$DEMO" "journalctl -u tt-mock -n 20 --no-pager -o cat" >&2; die "tt-mock did not start"; }

  # A mock must refuse a pack whose signer it does not know.
  check "tt-mock refuses the pack under an unknown gate key" ct "$DEMO" \
    "! TT_GATE_PUBKEYS=fake-1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA timeout 10 /usr/local/bin/tt mock --pack $DEMO_R/packs/current.ttpack --addr 127.0.0.1:18480 --quiet"
  mockc GET /__tt/health; eq "health needs no token" "$CODE" 200
  mockc GET /__tt/pack ""; # with the token
  eq "control API with the token" "$CODE" 200
  eq "the served pack is the published one" "$(jqb '.pack_id')" "$pack"
  log "pack: $(jqb -c '{services,customers,rules:(.rules|map({id,outcomes})),scenarios}')"
  local save="$MOCK_TOKEN"; MOCK_TOKEN=wrong; mockc GET /__tt/pack; eq "control API with a wrong token is refused" "$CODE" 401; MOCK_TOKEN="$save"

  mock_lifecycle
  mock_scenarios
}

mock_session() { # args: json -> prints id
  mockc POST /__tt/sessions "$1"; [[ "$CODE" == 201 ]] || die "create session: HTTP $CODE $BODY"
  jqb '.id'
}

mock_lifecycle() {
  mockc GET "/__tt/customers?limit=3"; expect "customers" 200
  local cust sid; cust="$(jqb '.[0].id')"
  sid="$(mock_session "$(jq -nc --arg c "$cust" '{seed:7,customer:$c,faults:{mode:"off"}}')")"
  local orders=() id n
  for n in $(seq 1 20); do
    mockc POST /__svc/shop-api/orders "$ORDER_BODY" "$sid"
    if [[ "$CODE" != 201 ]]; then
      mockc GET "/__tt/sessions/$sid/journal"; warn "POST /orders: HTTP $CODE ${BODY:0:300}"; break
    fi
    orders+=("$(jqb '.id')")
  done
  eq "20 orders created in the mock" "${#orders[@]}" 20
  [[ ${#orders[@]} -gt 0 ]] || return 0
  mockc POST /__svc/shop-api/orders "$ORDER_BODY" "$sid"
  check "an order response links its shipment (shipmentId)" test "$(jqb '.shipmentId != null')" = true
  local hid=0 pend=0
  for id in "${orders[@]}"; do
    mockc GET "/__svc/shop-api/orders/$id/shipment" "" "$sid"
    if [[ "$CODE" == 404 ]]; then hid=$((hid+1)); elif [[ "$CODE" == 200 && "$(jqb '.status')" == PENDING ]]; then pend=$((pend+1)); fi
  done
  eq "right after the order every shipment is still PENDING or not visible" "$((hid+pend))" "${#orders[@]}"
  # demo ground truth R3: a PENDING shipment is invisible (404) in the shop; the mined pack exposes it as 200 PENDING
  gap "PENDING shipments are hidden from the shop API as in the observed traffic (hidden_when)" test "$pend" = 0
  # advance the virtual clock: delays mined from the captured traffic are real seconds
  # (the demo clock runs TIME_SCALE times faster than reality), so the steps start small
  local step total=0 states_seen="" created=0 delivered=0 cancelled=0
  for step in 1s 1s 1s 2s 3s 5s 10s 20s 30s 1m 5m 30m 6h 72h; do
    mockc POST "/__tt/sessions/$sid/clock/advance" "{\"by\":\"$step\"}"; expect "advance $step" 200
    created=0; delivered=0; cancelled=0; local transit=0 hidden=0
    for id in "${orders[@]}"; do
      mockc GET "/__svc/shop-api/orders/$id/shipment" "" "$sid"
      case "$CODE:$(jqb '.status // empty' 2>/dev/null)" in
        200:PENDING) hidden=$((hidden+1)) ;;
        200:CREATED) created=$((created+1)) ;;
        200:IN_TRANSIT) transit=$((transit+1)) ;;
        200:DELIVERED) delivered=$((delivered+1)) ;;
        200:CANCELLED) cancelled=$((cancelled+1)) ;;
        404:*) hidden=$((hidden+1)) ;;
        *) warn "GET shipment: HTTP $CODE ${BODY:0:200}" ;;
      esac
    done
    printf '    +%-4s CREATED=%s IN_TRANSIT=%s DELIVERED=%s CANCELLED=%s hidden=%s\n' "$step" "$created" "$transit" "$delivered" "$cancelled" "$hidden" >&2
    [[ $created -gt 0 ]] && states_seen="${states_seen}C"
    [[ $transit -gt 0 ]] && states_seen="${states_seen}T"
    [[ $delivered -gt 0 ]] && states_seen="${states_seen}D"
    true
  done
  check "shipments pass through an intermediate state (CREATED/IN_TRANSIT) before DELIVERED" bash -c 'grep -q "[CT]" <<<"$1" && grep -q "D" <<<"$1"' _ "$states_seen"
  ge "after the last advance most shipments are final (DELIVERED + CANCELLED)" "$((delivered + cancelled))" 12
  mockc GET "/__tt/sessions/$sid/journal"; ge "the journal recorded the calls" "$(jq -s length <<<"$BODY")" 20
  mockc DELETE "/__tt/sessions/$sid"
}

mock_scenarios() {
  # 1. a cancelled shipment, forced on the lifecycle rule
  # the rule triggered by the shop's POST /orders (the miner also finds the same lifecycle from the carrier's side)
  local rule
  rule="$(jq -r '[.[] | select(.cause.op=="POST /orders" and ([.outcomes[].name] | index("cancelled")))][0].id' "$WORK/rules.approved.json")"
  check "the pack has the POST /orders lifecycle rule with a 'cancelled' outcome ($rule)" test -n "$rule" -a "$rule" != null
  mockc GET /__tt/customers?limit=1; local cust; cust="$(jqb '.[0].id')"
  local sid; sid="$(mock_session "$(jq -nc --arg c "$cust" '{seed:11,customer:$c,faults:{mode:"off"}}')")"
  mockc POST "/__tt/sessions/$sid/scenario" "$(jq -nc --arg r "$rule" '{rule:$r,outcome:"cancelled"}')"; expect "force the cancelled outcome" 200
  mockc POST /__svc/shop-api/orders "$ORDER_BODY" "$sid"; expect "order" 201
  local oid; oid="$(jqb '.id')" st=""
  mockc POST "/__tt/sessions/$sid/clock/advance" '{"by":"72h"}'; expect "advance 72h" 200
  mockc GET "/__svc/shop-api/orders/$oid/shipment" "" "$sid"
  eq "forced scenario: the shipment ends CANCELLED" "$(jqb '.status')" CANCELLED
  gap "a cancelled shipment carries a cancelReason (ground truth R3)" test "$(jqb '.cancelReason != null')" = true
  # the same through the shipping-ext (carrier) API
  mockc GET "/__svc/shipping-ext/v1/shipments?orderId=$oid" "" "$sid"
  check "the carrier API agrees (CANCELLED)" test "$(jqb '.items[0].status')" = CANCELLED
  mockc DELETE "/__tt/sessions/$sid"

  # 2. a forced 503 (fault injection on the carrier's GET /v1/shipments)
  sid="$(mock_session "$(jq -nc --arg c "$cust" '{seed:12,customer:$c,faults:{mode:"off"}}')")"
  mockc POST /__svc/shop-api/orders "$ORDER_BODY" "$sid"; expect "order" 201; oid="$(jqb '.id')"
  mockc PUT "/__tt/sessions/$sid/faults" '{"mode":"custom","rules":[{"service":"shipping-ext","op":"GET /v1/shipments","status":503,"p":1,"times":1}]}'
  expect "set a 503 fault" 200
  mockc GET "/__svc/shipping-ext/v1/shipments?orderId=$oid" "" "$sid"
  eq "forced fault: the carrier answers 503" "$CODE" 503
  mockc GET "/__svc/shipping-ext/v1/shipments?orderId=$oid" "" "$sid"
  eq "the fault was injected once only (times: 1)" "$CODE" 200
  mockc GET "/__tt/sessions/$sid/journal"; check "the journal shows the injected fault" bash -c 'grep -qi "503" <<<"$1"' _ "$BODY"
  mockc DELETE "/__tt/sessions/$sid"
}

phase_wiremock() {
  log "== wiremock: export the pack and run the real WireMock container against it"
  local pack; pack="$(<"$WORK/pack.id")"
  sess "$PUBLISHER"
  req "$PUBLISHER" POST /api/v1/exports "$(jq -nc --arg p "$pack" '{pack_id:$p,target:"wiremock"}')"; expect "run export" 202; follow_job "$PUBLISHER"
  eq "export finished" "$(jqb '.status')" done
  local exp; exp="$(jqb '.result.export_id')"
  req "$PUBLISHER" GET "/api/v1/exports/$exp"; expect "export report" 200
  log "export report: $(jqb -c '.report | {lost: (.lost // .losses // null)}' 2>/dev/null | cut -c1-300)"
  curl -fsS --cacert "$CA_CERT" -b "$WORK/jar.$PUBLISHER" -H "X-CSRF-Token: $(<"$WORK/csrf.$PUBLISHER")" \
    -o "$WORK/export-$exp.zip" "$CORE_URL/api/v1/exports/$exp/download" || die "export download failed"
  put "$DEMO" "$WORK/export-$exp.zip" "$DEMO_R/exports/wiremock.zip" 0644
  ct "$DEMO" "set -e; cd $DEMO_R/exports; rm -rf wiremock; (command -v unzip >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unzip >/dev/null); unzip -q -o wiremock.zip; ls wiremock; docker rm -f tt-wiremock-shipping tt-wiremock-shop >/dev/null 2>&1 || true"
  local img=wiremock/wiremock:3.9.1
  ct "$DEMO" "docker run -d --name tt-wiremock-shipping -p 8089:8080 -v $DEMO_R/exports/wiremock/shipping-ext/mappings:/home/wiremock/mappings:ro $img --verbose >/dev/null && docker run -d --name tt-wiremock-shop -p 8090:8080 -v $DEMO_R/exports/wiremock/shop-api/mappings:/home/wiremock/mappings:ro $img --verbose >/dev/null"
  local wm="http://$DEMO_HOST:8089" i ok=0 total
  for i in $(seq 1 60); do curl -fsS "$wm/__admin/mappings" >/dev/null 2>&1 && { ok=1; break; }; sleep 1; done
  check "WireMock (shipping-ext) started and loaded the export" test "$ok" = 1
  total="$(curl -fsS "$wm/__admin/mappings" | jq '.meta.total')"
  ge "WireMock loaded stubs for shipping-ext" "$total" 3
  wiremock_assertions "$wm"
}

# wiremock_assertions <base url of the shipping-ext WireMock>
wiremock_assertions() {
  local wm="$1" code body
  # (1) the contract default: an unknown order has no visible shipment
  body="$(curl -sS -w '\n%{http_code}' "$wm/v1/shipments?orderId=ORD-NOPE")"; code="${body##*$'\n'}"; body="${body%$'\n'*}"
  eq "unknown order: 200" "$code" 200
  # the export answers an unmatched request with the contract's example response (not an empty list)
  check "unknown order: a well-formed list of shipments (contract default)" test "$(jq -r '.items | type' <<<"$body")" = array
  # (2) a fault selected by header
  code="$(curl -sS -o /dev/null -w '%{http_code}' -H 'X-TT-Fault: 503' "$wm/v1/shipments?orderId=ORD-NOPE")"
  eq "fault by header: 503" "$code" 503
  # (3) the lifecycle of an order of the pack's world: each GET advances the scenario one step
  local order
  order="$(jq -r '[.mappings[] | select(.scenarioName != null) | .request.queryParameters.orderId.equalTo // empty][0] // empty' < <(curl -fsS "$wm/__admin/mappings"))"
  if [[ -n "$order" ]]; then
    local seq="" s
    for s in 1 2 3 4 5; do
      body="$(curl -fsS "$wm/v1/shipments?orderId=$order")"
      seq="$seq $(jq -r '.items[0].status // "none"' <<<"$body")"
    done
    log "WireMock lifecycle of $order:$seq"
    check "WireMock walks the shipment through its states for a world order" bash -c 'set -- $1; [ "$1" = none ] && [ "$#" = 5 ] && grep -q "DELIVERED\|CANCELLED" <<<"$1 $2 $3 $4 $5"' _ "$seq"
  else
    warn "no scenario mapping with an orderId in the export: lifecycle assertion skipped"
  fi
}
