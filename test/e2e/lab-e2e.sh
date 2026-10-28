#!/usr/bin/env bash
# End-to-end proof of the traffic-twin lab (demo, keyguard and core hosts).
# Everything the product does is driven through the admin API with a bootstrap
# admin; nothing is called inside the processes.
#
#   test/e2e/lab-e2e.sh                          all phases
#   PHASES="events contracts" test/e2e/lab-e2e.sh   only some of them
#
# Phases, in order: bootstrap users fleet policy events hosts contracts rules world mock wiremock admin restart
#
# Re-runnable: users, group, enrolled sources and the active policy are reused;
# every run mines, builds and publishes a new pack and re-runs the mock and
# WireMock assertions against it. Exit code is 0 only if every assertion passed.
#
# Secrets: the bootstrap admin and user passwords are generated on the first run
# and kept ONLY in /etc/tt-lab/credentials.env (mode 0600) on the core host. They
# are never printed. The setup token is read from the 0600 file in the core's data directory.
set -euo pipefail

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$E2E_DIR/../.." && pwd)"
source "$REPO_DIR/test/lab/lib.sh"   # ct/put/get helpers and STATE_DIR
source "$E2E_DIR/lab-lib.sh"         # admin API helpers (redefines log/die)

WORK="$STATE_DIR/e2e"; mkdir -p "$WORK"; chmod 700 "$WORK"
CA_CERT="$STATE_DIR/pki/lab-ca.crt"
[[ -f "$CA_CERT" ]] || die "run test/lab/deploy-infra.sh first (no lab CA at $CA_CERT)"
CRED_FILE=/etc/tt-lab/credentials.env
PHASES="${PHASES:-bootstrap users fleet policy events hosts contracts rules world mock wiremock admin restart}"
# The miner decides an outcome only for causes older than its completion horizon (>= 1 h, see
# internal/miner/causal.go), so even with the accelerated demo clock the traffic must span > 1 h.
EVENTS_MIN_MINUTES="${EVENTS_MIN_MINUTES:-75}"   # minutes of traffic under the demo policy before mining
EVENTS_MIN_CALLS="${EVENTS_MIN_CALLS:-8000}"     # shop-api calls
EVENTS_TIMEOUT_MIN="${EVENTS_TIMEOUT_MIN:-150}"
ADMIN=e2e_admin
OPERATOR=e2e_operator; REVIEWER=e2e_reviewer; PUBLISHER=e2e_publisher; APPROVER=e2e_approver; AUDITOR=e2e_auditor
TEAM="$OPERATOR:operator $REVIEWER:rule-reviewer $PUBLISHER:publisher $APPROVER:policy-approver $AUDITOR:auditor"
DEMO_R=/opt/tt-lab

have() { local p; for p in $PHASES; do [[ "$p" == "$1" ]] && return 0; done; return 1; }
newpw() { openssl rand -base64 24 | tr -d '/+=\n' | cut -c1-24; }
pw_of() { local v="PW_$1"; printf '%s' "${!v:-}"; }
now_s() { date +%s; }
iso() { date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ; }

# ---------------------------------------------------------------------------
# credentials: kept only on the core host
load_creds() {
  local line k v
  while IFS= read -r line; do
    [[ "$line" == PW_*=* ]] || continue
    k="${line%%=*}"; v="${line#*=}"
    # Only the lab users of this script; other accounts in the file (people
    # added by hand, e.g. "first.last") are not shell identifiers.
    [[ "$k" =~ ^PW_[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    printf -v "$k" '%s' "$v"
  done < <(ct "$CORE" "cat $CRED_FILE 2>/dev/null || true")
}
save_cred() { # user password
  ct "$CORE" "install -d -m 0700 \"\$(dirname $CRED_FILE)\"; umask 077; touch $CRED_FILE; grep -v '^PW_$1=' $CRED_FILE > $CRED_FILE.new || true; echo 'PW_$1=$2' >> $CRED_FILE.new; mv -f $CRED_FILE.new $CRED_FILE; chmod 0600 $CRED_FILE"
  printf -v "PW_$1" '%s' "$2"
}

# sess <user>: a valid session for the user (login again when expired).
sess() {
  local u="$1"
  if [[ -f "$WORK/csrf.$u" ]]; then
    req "$u" GET /api/v1/auth/me
    [[ "$CODE" == 200 ]] && return 0
  fi
  login "$u" "$(pw_of "$u")" || die "cannot log in as $u"
}

# ---------------------------------------------------------------------------
phase_bootstrap() {
  log "== bootstrap: core reachable, first administrator"
  req anon GET /readyz
  eq "core /readyz" "$CODE" 200
  req anon GET /api/v1/version
  log "core version: $(jqb -c . 2>/dev/null || echo "$BODY")"
  load_creds
  if [[ -z "$(pw_of $ADMIN)" ]]; then
    local tok pw
    tok="$(ct "$CORE" "cat /var/lib/tt-core/setup-token 2>/dev/null | grep -o 'tts_[A-Za-z0-9_-]*' | tail -1" || true)"
    pw="$(newpw)"
    save_cred "$ADMIN" "$pw"
    if [[ -n "$tok" ]]; then
      req anon POST /api/v1/setup "$(jq -nc --arg t "$tok" --arg u "$ADMIN" --arg p "$pw" '{setup_token:$t,username:$u,password:$p}')"
      if [[ "$CODE" != 201 ]]; then
        warn "setup answered HTTP $CODE: $(jqb -c '.error // .' 2>/dev/null)"
      fi
    else
      warn "no setup token file in the data directory of tt-core (an administrator probably exists already)"
    fi
  fi
  login "$ADMIN" "$(pw_of $ADMIN)" || die "cannot log in as $ADMIN. If the administrator was created by hand, store its password as PW_$ADMIN in $CRED_FILE on the core host; to restart from scratch stop tt-core, delete /var/lib/tt-core/tt-core.db* and start it again"
  req "$ADMIN" GET /api/v1/auth/me
  check "bootstrap admin session has the admin role" test "$(jqb '.roles | index("admin") != null')" = true
}

phase_users() {
  log "== users: one account per role (separation of duties)"
  sess "$ADMIN"
  req "$ADMIN" GET /api/v1/users; expect "list users" 200
  local existing; existing="$(jqb '.[].username')"
  local kv u r pw id
  for kv in $TEAM; do
    u="${kv%%:*}"; r="${kv##*:}"
    if grep -qx "$u" <<<"$existing"; then
      if [[ -z "$(pw_of "$u")" ]]; then
        pw="$(newpw)"; id="$(jq -r --arg u "$u" '.[] | select(.username==$u) | .id' <<<"$BODY")"
        req "$ADMIN" PATCH "/api/v1/users/$id" "$(jq -nc --arg p "$pw" '{password:$p}')"; expect "reset password of $u" 200
        save_cred "$u" "$pw"
      fi
    else
      pw="$(newpw)"; save_cred "$u" "$pw"
      req "$ADMIN" POST /api/v1/users "$(jq -nc --arg u "$u" --arg p "$pw" --arg r "$r" '{username:$u,password:$p,roles:[$r]}')"
      expect "create user $u" 201
    fi
  done
  req "$ADMIN" GET /api/v1/users
  check "five role accounts plus the bootstrap admin exist" test "$(jqb 'length')" -ge 6
  sess "$OPERATOR"
  req "$OPERATOR" POST /api/v1/users '{"username":"mallory","password":"not-allowed-1234","roles":["admin"]}'
  eq "an operator cannot create users (RBAC)" "$CODE" 403
}

# approve_policy <policy_id> <version>: the admin approves alone, with a reason.
approve_policy() {
  sess "$ADMIN"
  req "$ADMIN" POST "/api/v1/fleet/policies/$1/versions/$2/approve" '{"reason":"lab: admin override"}'
  expect "approve $1 v$2" 200
  eq "policy $1 v$2 active after approval" "$(jqb '.status')" active
}

sources_json() { req "$OPERATOR" GET "/api/v1/fleet/sources?group=demo"; }

phase_fleet() {
  log "== fleet: group, starter policy, enrollment tokens, demo stack"
  sess "$OPERATOR"
  req "$OPERATOR" GET /api/v1/fleet/groups/demo
  if [[ "$CODE" == 404 ]]; then
    req "$OPERATOR" POST /api/v1/fleet/groups '{"name":"demo","allowed_service_names":["shop-api","egress-shop"],"policy_id":"p-demo"}'
    expect "create group demo" 201
  fi
  req "$OPERATOR" GET /api/v1/fleet/policies; expect "list policies" 200
  if [[ "$(jqb '[.[] | select(.policy_id=="p-demo")] | length')" == 0 ]]; then
    req "$OPERATOR" POST /api/v1/fleet/groups/demo/starter-policy '{"hmac_kid":"k1","epoch":"2026-10","sampling_rate":"1"}'
    expect "starter policy" 201
    approve_policy p-demo "$(jqb '.version')"
  fi
  sources_json; expect "list sources" 200
  local need
  need="$(jqb '[ (map(select(.kind=="sdk-node" and .revoked==false)) | length), (map(select(.kind=="egress" and .revoked==false)) | length) ] | map(select(. == 0)) | length')"
  if [[ "$need" -gt 0 || "${FORCE_ENROLL:-0}" == 1 ]]; then
    log "enrolling the demo sources (group tokens, valid 30 days)"
    req "$OPERATOR" POST /api/v1/fleet/enrollment-tokens '{"kind":"sdk-node","group":"demo","token_type":"group","expires_in_s":2592000}'
    expect "token for the Node SDK" 201; local t_shop; t_shop="$(jqb '.token')"
    req "$OPERATOR" POST /api/v1/fleet/enrollment-tokens '{"kind":"egress","group":"demo","token_type":"group","expires_in_s":2592000}'
    expect "token for tt-egress" 201; local t_egress; t_egress="$(jqb '.token')"
    "$REPO_DIR/test/lab/deploy-demo.sh" up "$t_shop" "$t_egress" >&2
  else
    ct "$DEMO" "cd $DEMO_R && docker compose -f compose.yml --env-file .env up -d 2>&1 | tail -3" >&2
  fi
  local i ok=0
  for i in $(seq 1 60); do
    sources_json
    if [[ "$(jqb 'map(select(.state=="capturing")) | map(.kind) | unique | length')" == 2 ]]; then ok=1; break; fi
    sleep 5
  done
  check "both sources enrolled and capturing (sdk-node, egress)" test "$ok" = 1
  [[ "$ok" == 1 ]] || { log "sources: $(jqb -c 'map({kind,state,problems})')"; die "sources not capturing"; }
}

phase_policy() {
  log "== policy: the demo policy, proposed by the operator, approved by the admin (override with reason)"
  sess "$OPERATOR"
  req "$OPERATOR" GET /api/v1/fleet/policies; expect "list policies" 200
  local have_full; have_full="$(jqb '[.[] | select(.policy_id=="p-demo" and .status=="active" and (.origin=="propose" or .origin=="rollback"))] | length')"
  if [[ "$have_full" == 0 || "${FORCE_POLICY:-0}" == 1 ]]; then
    req "$OPERATOR" POST /api/v1/fleet/policies "@$E2E_DIR/policy.lab.json"; expect "propose the demo policy" 201
    local v; v="$(jqb '.version')"
    eq "the demo policy opens data: it needs the opening approvals" "$(jqb '.classification')" opening
    approve_policy p-demo "$v"
    rm -f "$WORK/policy_active_at"
  fi
  req "$OPERATOR" GET /api/v1/fleet/policies
  local want; want="$(jqb '[.[] | select(.policy_id=="p-demo" and .status=="active")] | map(.version) | max')"
  local i ok=0
  for i in $(seq 1 90); do
    sources_json
    if [[ "$(jqb --argjson v "$want" 'map(select(.state=="capturing" and .policy.version==$v)) | length')" == 2 ]]; then ok=1; break; fi
    sleep 4
  done
  check "both sources capture under policy p-demo v$want" test "$ok" = 1
  [[ "$ok" == 1 ]] || die "sources did not pick up p-demo v$want: $(jqb -c 'map({kind,state,policy})')"
  [[ -f "$WORK/policy_active_at" ]] || now_s >"$WORK/policy_active_at"
}

phase_events() {
  log "== events: wait for traffic under the demo policy (>= ${EVENTS_MIN_MINUTES} min, >= ${EVENTS_MIN_CALLS} shop-api calls)"
  sess "$OPERATOR"
  [[ -f "$WORK/policy_active_at" ]] || now_s >"$WORK/policy_active_at"
  local t0 deadline calls mins
  t0="$(<"$WORK/policy_active_at")"; deadline=$(( $(now_s) + EVENTS_TIMEOUT_MIN * 60 ))
  while :; do
    sess "$OPERATOR"
    req "$OPERATOR" GET /api/v1/services; expect "list services" 200
    calls="$(jqb '[.[] | select(.service=="shop-api") | .calls] | add // 0')"
    mins=$(( ($(now_s) - t0) / 60 ))
    printf '    %s min under policy, shop-api calls %s, services: %s\n' "$mins" "$calls" "$(jqb -c 'map({(.service): .calls}) | add')" >&2
    if [[ "$mins" -ge "$EVENTS_MIN_MINUTES" && "$calls" -ge "$EVENTS_MIN_CALLS" ]]; then break; fi
    [[ $(now_s) -lt $deadline ]] || die "timeout waiting for events"
    sleep 30
  done
  ge "shop-api calls stored" "$calls" "$EVENTS_MIN_CALLS"
  check "shop-api and shipping-ext are both discovered" test "$(jqb '[.[] | select(.service=="shop-api" or .service=="shipping-ext")] | length')" = 2
  check "shipping-ext (captured by tt-egress) is a policy service" test "$(jqb '.[] | select(.service=="shipping-ext") | .in_policy')" = true
  sources_json
  eq "no sanitizer errors at the sources" "$(jqb '[.[].sanitizer_errors] | add')" 0
  log "sources: $(jqb -c 'map({kind,events_per_min,drop_ratio,overhead_us})')"
}

SERVICES="shop-api shipping-ext"
phase_contracts() {
  log "== contracts: snapshots and inferred OpenAPI"
  sess "$OPERATOR"
  local svc from to; to="$(iso "$(now_s)")"; from="$(iso $(( $(now_s) - 7*86400 )))"
  for svc in $SERVICES; do
    req "$OPERATOR" POST "/api/v1/contracts/$svc/snapshots" "$(jq -nc --arg f "$from" --arg t "$to" '{from:$f,to:$t}')"
    expect "snapshot $svc" 201 202; follow_job "$OPERATOR"
  done
  req "$OPERATOR" GET /api/v1/contracts/shop-api; expect "contract shop-api" 200
  check "shop-api contract has POST /orders" test "$(jqb '.paths | has("/orders")')" = true
  check "shop-api contract has GET /orders/{id}/shipment" test "$(jqb '.paths | has("/orders/{id}/shipment")')" = true
  check "shop-api contract has GET /customers/{id}/orders" test "$(jqb '.paths | has("/customers/{id}/orders")')" = true
  check "no HMAC token (tk1:) in the zone-B contract view" bash -c '! grep -q "tk1:" <<<"$1"' _ "$BODY"
  req "$OPERATOR" GET /api/v1/contracts/shipping-ext; expect "contract shipping-ext" 200
  check "shipping-ext contract has POST /v1/shipments and GET /v1/shipments" test "$(jqb '.paths | has("/v1/shipments")')" = true
  req "$OPERATOR" GET /api/v1/drift; log "drift alerts: $(jqb 'length' 2>/dev/null || echo '?')"
}

phase_rules() {
  log "== rules: mining run, review, approval"
  sess "$OPERATOR"
  req "$OPERATOR" POST /api/v1/rules/mine; expect "mine rules" 202 200; follow_job "$OPERATOR"
  eq "mining job finished" "$(jqb '.status')" done
  log "mining result: $(jqb -c '.result | {events,new,updated,stale,unchanged}')"
  check "the mining job carries diagnostics (entities, rule_diagnostics, status)" test "$(jqb '(.result.entities|length>0) and (.result.rule_diagnostics|length>0) and (.result.status.state != null)')" = true
  check "the miner's coverage status is ok" test "$(jqb '.result.status.state')" = ok
  req "$OPERATOR" GET /api/v1/rules/status; expect "rules status" 200
  log "miner status: $(jqb -c '{state, warnings}')"
  sess "$REVIEWER"
  req "$REVIEWER" GET "/api/v1/rules?status=draft"; expect "list draft rules" 200
  local ids kinds; ids="$(jqb '.[].id')"; kinds="$(jqb -c '[.[].kind] | group_by(.) | map({(.[0]): length}) | add')"
  log "draft rules: ${kinds:-none}"
  local id
  for id in $ids; do
    req "$REVIEWER" POST "/api/v1/rules/$id/approve"; [[ "$CODE" == 200 ]] || warn "approve $id: HTTP $CODE ${BODY:0:200}"
  done
  # A contract change (drift) marks the approved rules stale (reason contract-drift) and the miner does not propose them
  # again: the reviewer decides. The ones the last run still sees with high confidence are approved again.
  req "$REVIEWER" GET "/api/v1/rules/status"; expect "rules status" 200
  local st_ids; st_ids="$(jqb '[.rule_diagnostics[]? | select((.reason // "") | test("stale")) | select((.confidence // 0) >= 0.9) | .rule_id] | .[]')"
  for id in $st_ids; do
    req "$REVIEWER" POST "/api/v1/rules/$id/approve"; log "re-approved the stale rule $id after the contract drift: HTTP $CODE"
  done
  req "$REVIEWER" GET "/api/v1/rules?status=approved"; expect "list approved rules" 200
  echo "$BODY" >"$WORK/rules.approved.json"
  local ncausal nbatch
  ncausal="$(jqb '[.[] | select(.kind=="causal")] | length')"; nbatch="$(jqb '[.[] | select(.kind=="batch")] | length')"
  ge "approved causal rules (order -> shipment lifecycle)" "$ncausal" 1
  # The nightly batch of the demo is at 02:00 of the SIMULATED clock; the miner looks for a change concentrated at the same
  # real clock hour on several days, which an accelerated demo clock cannot show (needs days of real traffic).
  if [[ "$nbatch" -ge 1 ]]; then check "approved batch rules (nightly consolidation)" true
  else warn "no batch rule mined: expected with an accelerated clock (the miner needs the same real hour on several days)"; fi
}

phase_world() {
  log "== world: archetypes, synthetic customers, pack, gate, signature, publication"
  sess "$OPERATOR"
  req "$OPERATOR" POST /api/v1/archetypes/build '{"k_min":20,"group":"demo"}'; expect "build archetypes" 202; follow_job "$OPERATOR"
  log "archetypes: $(jqb -c '.result')"
  req "$OPERATOR" POST /api/v1/worlds '{"seed":42,"customers":30,"group":"demo"}'; expect "generate world" 202; follow_job "$OPERATOR"
  if [[ "$(jqb '.status')" == failed ]]; then warn "world generation failed: $(jqb -c '{error, details}')"; fi
  local world; world="$(jqb '.result.world_id')"; check "world generated" test -n "$world" -a "$world" != null
  # A world without the group's approved rules is empty: never accepted in silence (two teams in different groups each creating an "order").
  check "the demo world has entities" test "$(jqb '.result.entities // 0')" -gt 0
  check "the demo world applies approved rules" test "$(jqb '.result.rules // [] | length')" -gt 0
  if [[ "$(jqb '.result.excluded_rules // [] | length')" -gt 0 ]]; then warn "demo rules left out of the world: $(jqb -c '.result.excluded_rules')"; fi
  echo "$world" >"$WORK/world.id"
  req "$OPERATOR" POST /api/v1/packs "$(jq -nc --arg w "$world" '{world_id:$w,valid_days:30}')"; expect "build pack" 202; follow_job "$OPERATOR"
  local pack status; pack="$(jqb '.result.pack_id')"; status="$(jqb '.result.status')"
  echo "$BODY" >"$WORK/pack.build.json"
  eq "pack passes the publication gate and is signed" "$status" signed
  [[ "$status" == signed ]] || die "pack $pack: $status: $(jqb -c '.result.gate_report' | cut -c1-600)"
  sess "$PUBLISHER"
  req "$PUBLISHER" POST "/api/v1/packs/$pack/publish"; expect "publish pack" 200
  curl -fsS --cacert "$CA_CERT" -b "$WORK/jar.$PUBLISHER" -H "X-CSRF-Token: $(<"$WORK/csrf.$PUBLISHER")" \
    -o "$WORK/$pack.ttpack" "$CORE_URL/api/v1/packs/$pack/download" || die "download of pack $pack failed"
  check "pack archive downloaded ($(wc -c <"$WORK/$pack.ttpack") bytes)" test -s "$WORK/$pack.ttpack"
  echo "$pack" >"$WORK/pack.id"; cp "$WORK/$pack.ttpack" "$WORK/current.ttpack"
}

# ---------------------------------------------------------------------------
# the hosts registry, the admin-as-superuser and the restart phases are in lab-v15.sh;
# the mock and WireMock phases are in lab-mock.sh
source "$E2E_DIR/lab-v15.sh"
source "$E2E_DIR/lab-mock.sh"

main() {
  local p
  for p in bootstrap users fleet policy events hosts contracts rules world mock wiremock admin restart; do
    have "$p" || continue
    # every phase after bootstrap needs the credentials and a session
    if [[ "$p" != bootstrap && -z "$(pw_of $ADMIN)" ]]; then load_creds; fi
    "phase_$p"
  done
  echo >&2
  log "result: $PASS passed, $FAIL failed, ${#GAPS[@]} known product gaps"
  if [[ ${#GAPS[@]} -gt 0 ]]; then printf '  gap: %s\n' "${GAPS[@]}" >&2; fi
  if [[ $FAIL -gt 0 ]]; then printf '  failed: %s\n' "${FAILED[@]}" >&2; exit 1; fi
}
main "$@"
