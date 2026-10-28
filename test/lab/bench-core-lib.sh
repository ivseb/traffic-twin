#!/usr/bin/env bash
# Throwaway "bench" keyguard + tt-core pair for the benchmarks (source this file after lib.sh and
# test/e2e/lab-lib.sh). They do not touch the live lab: own ports (keyguard 7445, core 7444/4319),
# own databases and Fleet CA; the key files and certificates are the lab's.
#
# keyguard refuses a second core that restarts the issued_seq of a policy (rollback protection),
# which is why the bench core needs its own keyguard instance.
#
# After bench_core_up: CORE_URL points at the bench core, benchop/benchadmin have sessions,
# TOKEN_GO and TOKEN_NODE are group enrollment tokens (sdk-go, sdk-node), and sources of
# group "demo" (service shop-api) run under policy p-bench (the lab policy, sampling 100%).
BENCH_UNIT=tt-core-bench
BENCH_CRED=/etc/tt-lab/bench-credentials.env
CA_CERT="$STATE_DIR/pki/lab-ca.crt"
BWORK="$STATE_DIR/bench/work"; mkdir -p "$BWORK"; chmod 700 "$BWORK"
WORK="$BWORK"

bench_core_down() {
  ct "$KG" "systemctl stop tt-keyguard-bench 2>/dev/null; systemctl disable tt-keyguard-bench >/dev/null 2>&1; rm -rf /var/lib/tt-keyguard-bench /etc/systemd/system/tt-keyguard-bench.service /etc/tt-keyguard/keyguard-bench.env; systemctl daemon-reload" || true
  ct "$CORE" "systemctl stop $BENCH_UNIT 2>/dev/null; systemctl disable $BENCH_UNIT >/dev/null 2>&1; rm -rf /var/lib/tt-core-bench /etc/systemd/system/$BENCH_UNIT.service /etc/tt/core-bench.yaml $BENCH_CRED; systemctl daemon-reload" || true
}

bench_core_up() {
  bench_core_down
  log "starting the bench keyguard on $KG_HOST:7445"
  ct "$KG" "set -e
sed -e 's|0.0.0.0:7443|0.0.0.0:7445|; s|/var/lib/tt-keyguard/|/var/lib/tt-keyguard-bench/|' /etc/tt-keyguard/keyguard.env > /etc/tt-keyguard/keyguard-bench.env
chown root:tt-keyguard /etc/tt-keyguard/keyguard-bench.env; chmod 0640 /etc/tt-keyguard/keyguard-bench.env
sed -e 's|StateDirectory=tt-keyguard|StateDirectory=tt-keyguard-bench|; s|keyguard.env|keyguard-bench.env|' /etc/systemd/system/tt-keyguard.service > /etc/systemd/system/tt-keyguard-bench.service
systemctl daemon-reload; systemctl start tt-keyguard-bench"
  log "starting the bench core on $CORE_HOST (7444 admin, 4319 intake)"
  ct "$CORE" "set -e
sed -e 's|https://$KG_HOST:7443|https://$KG_HOST:7445|; s|0.0.0.0:7443|0.0.0.0:7444|; s|0.0.0.0:4318|0.0.0.0:4319|; s|:4318|:4319|; s|/var/lib/tt-core/|/var/lib/tt-core-bench/|' /etc/tt/core.yaml > /etc/tt/core-bench.yaml
chown root:tt-core /etc/tt/core-bench.yaml; chmod 0640 /etc/tt/core-bench.yaml
sed -e 's|StateDirectory=tt-core|StateDirectory=tt-core-bench|; s|/etc/tt/core.yaml|/etc/tt/core-bench.yaml|; s|^Description=.*|Description=traffic-twin core (bench, throwaway)|' /etc/systemd/system/tt-core.service > /etc/systemd/system/$BENCH_UNIT.service
systemctl daemon-reload; systemctl start $BENCH_UNIT"
  CORE_URL="https://$CORE_HOST:7444"
  local i
  for i in $(seq 1 30); do curl -fsS --cacert "$CA_CERT" "$CORE_URL/readyz" >/dev/null 2>&1 && break; sleep 1; done

  log "bench core: admin, operator, group, policy, enrollment tokens"
  local admin_pw op_pw tok
  admin_pw="$(openssl rand -base64 24 | tr -d '/+=\n' | cut -c1-24)"; op_pw="$(openssl rand -base64 24 | tr -d '/+=\n' | cut -c1-24)"
  ct "$CORE" "install -d -m 0700 /etc/tt-lab; umask 077; printf 'ADMIN_PW=%s\nOP_PW=%s\n' '$admin_pw' '$op_pw' > $BENCH_CRED"
  tok="$(ct "$CORE" "cat /var/lib/tt-core-bench/setup-token 2>/dev/null | grep -o 'tts_[A-Za-z0-9_-]*' | tail -1")"
  req anon POST /api/v1/setup "$(jq -nc --arg t "$tok" --arg p "$admin_pw" '{setup_token:$t,username:"benchadmin",password:$p}')"; expect setup 201
  login benchadmin "$admin_pw"
  req benchadmin POST /api/v1/users "$(jq -nc --arg p "$op_pw" '{username:"benchop",password:$p,roles:["operator"]}')"; expect "create operator" 201
  login benchop "$op_pw"
  sed 's/"policy_id":"p-demo"/"policy_id":"p-bench"/' "$REPO_DIR/test/e2e/policy.lab.json" >"$BWORK/policy.bench.json"
  req benchop POST /api/v1/fleet/groups '{"name":"demo","allowed_service_names":["shop-api"],"policy_id":"p-bench"}'; expect group 201
  req benchop POST /api/v1/fleet/groups/demo/starter-policy '{"hmac_kid":"k1","epoch":"2026-10","sampling_rate":"1"}'; expect starter 201
  bench_approve "$(jqb .version)"
  req benchop POST /api/v1/fleet/policies "@$BWORK/policy.bench.json"; expect policy 201; bench_approve "$(jqb .version)"
  req benchop POST /api/v1/fleet/enrollment-tokens '{"kind":"sdk-go","group":"demo","token_type":"group","expires_in_s":7200}'; expect token 201
  TOKEN_GO="$(jqb .token)"
  req benchop POST /api/v1/fleet/enrollment-tokens '{"kind":"sdk-node","group":"demo","token_type":"group","expires_in_s":7200}'; expect token 201
  TOKEN_NODE="$(jqb .token)"
}

bench_approve() { req benchadmin POST "/api/v1/fleet/policies/p-bench/versions/$1/approve" '{"reason":"bench: throwaway core"}'; expect "approve v$1" 200; }
