#!/usr/bin/env bash
# Prepares and drives the demo stack on the demo host (directory /opt/tt-lab):
# demo shop + Node SDK, carrier behind tt-egress, loadgen, tt-mock (systemd).
#
#   test/lab/deploy-demo.sh prepare            copy sources, binaries, secrets; build images
#   test/lab/deploy-demo.sh up TOK_SHOP TOK_EGRESS   write .env and (re)start the stack
#   test/lab/deploy-demo.sh restart-shop [ENV=VAL...]  recreate only the shop (e.g. SHOP_TT_DISABLED=1)
#   test/lab/deploy-demo.sh down | status | logs <svc>
set -euo pipefail
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

BIN="$STATE_DIR/bin/tt-linux-amd64"
R=/opt/tt-lab
DC="cd $R && docker compose -f compose.yml --env-file .env"

prepare() {
  [[ -f "$BIN" ]] || "$LAB_DIR/deploy-infra.sh" build
  log "demo host: directories and sources"
  ct "$DEMO" "install -d -m 0755 $R $R/bin $R/packs $R/exports && install -d -m 0700 $R/secrets"
  ct "$DEMO" "[ -f $R/.env ] || install -m 0600 /dev/null $R/.env"
  ct "$DEMO" "install -d -m 0700 -o 1000 -g 1000 $R/state/shop; install -d -m 0700 -o 65532 -g 65532 $R/state/egress"
  (cd "$REPO_DIR" && COPYFILE_DISABLE=1 tar -czf "$STATE_DIR/demo.tgz" --exclude='*.test' demo)
  put "$DEMO" "$STATE_DIR/demo.tgz" "$R/demo.tgz"
  ct "$DEMO" "cd $R && rm -rf demo && tar -xzf demo.tgz && rm demo.tgz"
  log "demo host: Node SDK tarball (npm pack of sdk/node)"
  (cd "$REPO_DIR/sdk/node" && [[ -d dist ]] || npm ci --no-audit --no-fund >/dev/null && npm run build >/dev/null)
  local tgz
  tgz="$(cd "$REPO_DIR/sdk/node" && npm pack --silent --pack-destination "$STATE_DIR" | tail -1)"
  put "$DEMO" "$STATE_DIR/$tgz" "$R/sdk.tgz"
  put "$DEMO" "$BIN" "$R/bin/tt" 0755
  put "$DEMO" "$BIN" /usr/local/bin/tt.new 0755
  ct "$DEMO" "mv -f /usr/local/bin/tt.new /usr/local/bin/tt"
  put "$DEMO" "$LAB_DIR/demo/compose.yml" "$R/compose.yml" 0644
  put "$DEMO" "$LAB_DIR/demo/egress.Dockerfile" "$R/egress.Dockerfile" 0644
  put "$DEMO" "$LAB_DIR/demo/shop.Dockerfile" "$R/shop.Dockerfile" 0644

  log "demo host: HMAC key (a source needs it locally; it never travels to tt-core) and gate public key"
  # The key goes keyguard host -> this machine (memory only through ssh) -> demo host; never on disk here.
  ct "$KG" "cat /etc/tt-keyguard/secrets/hmac.keys" | ct "$DEMO" "set -e; umask 077; cat > $R/secrets/hmac.keys.new; \
    install -m 0400 -o 1000 -g 1000 $R/secrets/hmac.keys.new $R/secrets/hmac.shop.keys; \
    install -m 0400 -o 65532 -g 65532 $R/secrets/hmac.keys.new $R/secrets/hmac.egress.keys; rm -f $R/secrets/hmac.keys.new"
  local gate
  gate="$(ct "$KG" "cat /etc/tt-keyguard/pack.key.pub" | tr -d '\n')"
  [[ -n "$gate" ]] || die "no pack public key on keyguard"
  ct "$DEMO" "set -e
id tt-mock >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin tt-mock
install -d -m 0750 -o root -g tt-mock /etc/tt-mock
[ -f /etc/tt-mock/mock.env ] || { umask 027; printf 'TT_GATE_PUBKEYS=%s\nTT_CONTROL_TOKEN=%s\n' '$gate' \"\$(head -c 24 /dev/urandom | base64 | tr -d '/+=')\" > /etc/tt-mock/mock.env; }
sed -i \"s|^TT_GATE_PUBKEYS=.*|TT_GATE_PUBKEYS=$gate|\" /etc/tt-mock/mock.env
chown root:tt-mock /etc/tt-mock/mock.env; chmod 0640 /etc/tt-mock/mock.env
chmod 0755 $R/packs"
  put "$DEMO" "$LAB_DIR/units/tt-mock.service" /etc/systemd/system/tt-mock.service 0644
  ct "$DEMO" "systemctl daemon-reload && systemctl enable tt-mock >/dev/null 2>&1"
  log "demo host: building images (carrier, shop+SDK, tt-egress)"
  ct "$DEMO" "$DC build 2>&1 | tail -5"
}

# up <shop token> <egress token>: write .env (0600) and start the stack.
up() {
  local shop_tok="${1:?shop token}" egress_tok="${2:?egress token}" anchor
  # the simulated clock starts at the first deployment and is kept across restarts (FORCE_REANCHOR=1 restarts it)
  anchor="$(ct "$DEMO" "grep -s ^CLOCK_ANCHOR= $R/.env | cut -d= -f2")"
  if [[ -z "$anchor" || "${FORCE_REANCHOR:-0}" == 1 ]]; then anchor="$(date +%s)"; fi
  ct "$DEMO" "set -e; umask 077; cat > $R/.env.new; mv -f $R/.env.new $R/.env" <<EOF
TT_ENROLL_URL=https://$CORE_HOST:4318
TT_SHOP_TOKEN=$shop_tok
TT_EGRESS_TOKEN=$egress_tok
TIME_SCALE=${TIME_SCALE:-240}
CLOCK_ANCHOR=$anchor
EOF
  ct "$DEMO" "$DC up -d --remove-orphans 2>&1 | tail -8"
}

case "${1:-}" in
  prepare) prepare ;;
  up) shift; up "$@" ;;
  reanchor|set)   # reanchor [VAR=VAL..] | set VAR=VAL..: edit .env (CLOCK_ANCHOR, TIME_SCALE, CUSTOMERS, MAX_RPS) and recreate the stack
    cmd="$1"; shift
    if [[ "$cmd" == reanchor ]]; then set -- "CLOCK_ANCHOR=$(date +%s)" "$@"; fi
    for kv in "$@"; do
      ct "$DEMO" "sed -i '/^${kv%%=*}=/d' $R/.env; echo '$kv' >> $R/.env"
    done
    ct "$DEMO" "$DC up -d --remove-orphans 2>&1 | tail -6"
    ;;
  restart-shop)
    shift
    # extra VAR=VALUE pairs are appended to a transient env file for this recreate only
    envs=""; for kv in "$@"; do envs+="$kv "; done
    ct "$DEMO" "$DC stop shop >/dev/null; cd $R && $envs docker compose -f compose.yml --env-file .env up -d --force-recreate shop 2>&1 | tail -3"
    ;;
  down) ct "$DEMO" "$DC down" ;;
  stop) ct "$DEMO" "$DC stop 2>&1 | tail -3" ;;      # keeps the containers (and the in-memory shop state is lost only on recreate)
  start) ct "$DEMO" "$DC start 2>&1 | tail -3" ;;
  status) ct "$DEMO" "$DC ps; systemctl is-active tt-mock || true" ;;
  logs) shift; ct "$DEMO" "$DC logs --tail 40 $*" ;;
  *) die "usage: $0 prepare|up TOK_SHOP TOK_EGRESS|restart-shop [VAR=VAL..]|down|status|logs <svc>" ;;
esac
