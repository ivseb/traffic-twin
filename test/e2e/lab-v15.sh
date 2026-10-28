#!/usr/bin/env bash
# Phases "hosts", "admin" and "restart" of test/e2e/lab-e2e.sh (sourced by it): host autodiscovery
# (spec v1.5), the admin as superuser (audited), and the miner's robustness to an application restart.

# active_policy_version <policy_id>: the active version (sets BODY).
active_policy_version() {
  req "$OPERATOR" GET /api/v1/fleet/policies; expect "list policies" 200
  jqb --arg p "$1" '[.[] | select(.policy_id==$p and .status=="active")][0].version'
}

phase_hosts() {
  log "== hosts: registry of outbound hosts, 'twin this host', double capture"
  sess "$OPERATOR"
  req "$OPERATOR" GET /api/v1/hosts; expect "hosts registry" 200
  log "hosts: $(jqb -c '[.domains[] | {domain, calls, patterns: [.patterns[] | {pattern, declared, exact, callers: [.callers[].service]}]}]' | cut -c1-500)"
  check "the carrier seen through tt-egress is a declared host of its registrable domain (carrier.example)" \
    test "$(jqb '[.domains[] | select(.domain=="carrier.example") | .patterns[] | select(.pattern=="api.carrier.example" and .declared==true and ([.callers[].service] | index("egress-shop")))] | length')" = 1
  check "the shop's call to tt-egress is grouped by domain (tt-egress) and attributed to shop-api" \
    test "$(jqb '[.domains[] | select(.domain=="tt-egress") | .patterns[] | select(.pattern=="tt-egress:9090" and ([.callers[].service] | index("shop-api")))] | length')" = 1
  check "no value in the registry: patterns only" bash -c '! grep -Eq "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" <<<"$1"' _ "$(jqb '[.domains[].patterns[].pattern]')"
  # the double capture is detected on fresh traffic: right after a core restart it takes a few minutes
  local dc i
  for i in $(seq 1 30); do
    sources_json; expect "list sources" 200
    dc="$(jqb '[.[] | select(.problems | map(.code) | index("double_capture"))] | map(.kind) | sort | join(",")')"
    [[ "$dc" == "egress,sdk-node" ]] && break
    sleep 10
  done
  check "double_capture warning on the shop (SDK) and on tt-egress" \
    test "$(jqb '[.[] | select(.problems | map(.code) | index("double_capture"))] | map(.kind) | sort | join(",")')" = "egress,sdk-node"

  # "twin this host" adds the host as an external service. It only names calls
  # already seen, so since v1.6 it does not open values: it is applied at once
  # (observe-safe). A change that opens values would stay a draft.
  local before; before="$(active_policy_version p-demo)"
  req "$OPERATOR" POST "/api/v1/hosts/tt-egress%3A9090/twin" '{"service":"tt-egress-proxy","scheme":"http"}'; expect "twin the host" 201
  local v; v="$(jqb '.version')"
  eq "the twin comes from the host twin" "$(jqb '.origin')" host-twin
  eq "the twin does not open values" "$(jqb '.opens_values')" false
  eq "an observe-safe twin is applied at once" "$(jqb '.status')" active
  check "the twin adds an external service for the host" test "$(jqb '[.diff[]? | select(.where | test("tt-egress"))] | length')" -ge 1
  # clean up: roll back to the version before the twin (the admin approves it
  # alone, with a reason), so later runs find the demo policy unchanged
  req "$OPERATOR" POST "/api/v1/fleet/policies/p-demo/rollback" "$(jq -nc --argjson to "$before" '{to_version:$to}')"; expect "roll back the twin" 201 200
  local rv; rv="$(jqb '.version')"
  [[ "$(jqb '.status')" == active ]] || approve_policy p-demo "$rv"
}

# The admin is the superuser: it performs reviewer, operator and publisher actions alone, and every one is audited.
phase_admin() {
  log "== admin: reviewer, operator and publisher actions alone, audited as authz.admin_override"
  sess "$ADMIN"
  local world pack
  world="$(<"$WORK/world.id")"
  req "$ADMIN" POST /api/v1/rules/mine; expect "admin mines rules (operator action)" 202 200; follow_job "$ADMIN"
  local ids id
  # the demo group's drafts only: the console is shared with other teams
  req "$ADMIN" GET "/api/v1/rules?status=draft&group=demo"; expect "admin lists draft rules" 200
  ids="$(jqb '.[].id')"
  for id in $ids; do req "$ADMIN" POST "/api/v1/rules/$id/approve"; eq "admin approves rule $id (reviewer action)" "$CODE" 200; done
  req "$ADMIN" POST /api/v1/packs "$(jq -nc --arg w "$world" '{world_id:$w,valid_days:30}')"; expect "admin builds a pack (operator action)" 202; follow_job "$ADMIN"
  pack="$(jqb '.result.pack_id')"; eq "the admin's pack is signed" "$(jqb '.result.status')" signed
  req "$ADMIN" POST "/api/v1/packs/$pack/publish"
  check "publishing as admin without a reason is refused (4xx)" test "${CODE:0:1}" = 4
  req "$ADMIN" POST "/api/v1/packs/$pack/publish" '{"reason":"lab: admin override check"}'; eq "publishing as admin with a reason (publisher action)" "$CODE" 200
  req "$ADMIN" GET "/api/v1/packs/$pack"; eq "the pack is published" "$(jqb '.status')" published
  sess "$AUDITOR"
  req "$AUDITOR" GET "/api/v1/audit/export?last=400"; expect "audit tail" 200
  local au="$BODY"
  check "the audit log has authz.admin_override entries for the admin's actions" \
    test "$(jq -s '[.[] | select(.action=="authz.admin_override")] | length' <<<"$au")" -ge 3
  check "the pack publication by the admin is audited" test "$(jq -s '[.[] | select(.action|test("pack.publish")) | select(.actor.name=="'"$ADMIN"'" or .actor.id!=null)] | length' <<<"$au")" -ge 1
  req "$AUDITOR" GET /api/v1/audit/verify; expect "audit chain verification" 200
  log "audit chain: $(jqb -c .)"
}

# The demo shop keeps its state in memory: a restart leaves orders that the miner only knows from polls.
# The rules must survive it (not stale), and the run must say why it kept them (diagnostics).
phase_restart() {
  log "== restart: restart the shop once, keep running, mine again"
  sess "$REVIEWER"
  req "$REVIEWER" GET "/api/v1/rules?status=approved"; expect "approved rules" 200
  local before; before="$(jqb '[.[].id] | sort | join(",")')"
  check "there are approved rules before the restart" test -n "$before"
  log "restarting the shop container (in-memory orders are lost)"
  "$REPO_DIR/test/lab/deploy-demo.sh" restart-shop SHOP_TT_DISABLED=0 >&2
  local i
  for i in $(seq 1 ${RESTART_WAIT_MIN:-8}); do printf '    %s/%s min of traffic after the restart\n' "$i" "${RESTART_WAIT_MIN:-8}" >&2; sleep 60; done
  sess "$OPERATOR"
  req "$OPERATOR" POST /api/v1/rules/mine; expect "mine after the restart" 202 200; follow_job "$OPERATOR"
  log "mining after the restart: $(jqb -c '.result | {events,new,updated,stale,unchanged}')"
  eq "no rule went stale after the restart" "$(jqb '.result.stale | length')" 0
  check "the job explains the run (entities with birth shares)" test "$(jqb '[.result.entities[]? | select(.born != null or .birth_share_low != null)] | length')" -ge 1
  req "$OPERATOR" GET /api/v1/rules/status; expect "rules status" 200
  log "miner status: $(jqb -c '{state, warnings}')"
  check "the miner status is ok" test "$(jqb '.state')" = ok
  sess "$REVIEWER"
  req "$REVIEWER" GET "/api/v1/rules?status=approved"
  local after; after="$(jqb '[.[].id] | sort | join(",")')"
  check "the rules approved before the restart are still approved" bash -c '
    for r in ${1//,/ }; do case ",$2," in *",$r,"*) ;; *) exit 1;; esac; done' _ "$before" "$after"
}
