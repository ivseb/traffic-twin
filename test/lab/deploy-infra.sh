#!/usr/bin/env bash
# Deploys keyguard (keyguard host) and tt-core (core host) as in production:
# separate hosts, mTLS between them, keys generated on the host that uses
# them (files 0400), lab CA kept only on the operator machine, systemd units
# with hardening. Idempotent: existing keys and certificates are kept; the
# binary, configuration and units are refreshed.
#
#   test/lab/deploy-infra.sh [build|pki|keyguard|core|all]   (default: all)
set -euo pipefail
# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

BIN="$STATE_DIR/bin/tt-linux-amd64"
PKI="$STATE_DIR/pki"

build() {
  mkdir -p "$STATE_DIR/bin"
  # Always rebuild the embedded UI: a stale dist would ship an old console
  # against a new API (make only rebuilds what changed).
  log "building the UI (make ui)"
  (cd "$REPO_DIR" && make ui >/dev/null)
  local sha ver
  sha="$(cd "$REPO_DIR" && git rev-parse --short HEAD)"
  ver="${LAB_VERSION:-0.1.0-lab.$sha}"   # semver: sources report it in every event
  log "building linux/amd64 tt ($ver)"
  (cd "$REPO_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
    -ldflags "-s -w -X main.version=$ver -X main.commit=$sha" -o "$BIN" ./cmd/tt)
  printf '%s\n' "$sha" >"$BIN.commit"
  ls -l "$BIN" >&2
}

pki() {
  mkdir -p "$PKI"; chmod 700 "$PKI"
  if [[ ! -f "$PKI/lab-ca.key" ]]; then
    # A deployed lab already trusts its CA (sources, browsers): a new one
    # would silently break every TLS client. Copy the old $PKI here instead,
    # or set LAB_NEW_CA=1 to replace it on purpose.
    if [[ "${LAB_NEW_CA:-}" != 1 ]] && ct "$KG" test -f /etc/tt-keyguard/keyguard.crt 2>/dev/null; then
      die "no lab CA in $PKI but the lab is already deployed: copy the existing pki/ here (or LAB_NEW_CA=1)"
    fi
    log "creating the lab CA (private key stays on this machine)"
    ( umask 077; openssl ecparam -name prime256v1 -genkey -noout -out "$PKI/lab-ca.key" )
    openssl req -x509 -new -key "$PKI/lab-ca.key" -sha256 -days 1825 -subj "/O=traffic-twin lab/CN=traffic-twin lab CA" \
      -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$PKI/lab-ca.crt"
  fi
}

# sign_csr <csr> <out.crt> <eku> <san>
sign_csr() {
  local csr="$1" out="$2" eku="$3" san="$4"
  printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\nsubjectAltName=%s\n' "$eku" "$san" >"$PKI/ext.cnf"
  openssl x509 -req -in "$csr" -CA "$PKI/lab-ca.crt" -CAkey "$PKI/lab-ca.key" -CAcreateserial -days 825 -sha256 -extfile "$PKI/ext.cnf" -out "$out" 2>/dev/null
}

push_bin() {
  # Rebuild when the binary is missing or was built from another commit:
  # "core" alone must never ship an old tt.
  local head
  head="$(cd "$REPO_DIR" && git rev-parse --short HEAD)"
  [[ -f "$BIN" && "$(cat "$BIN.commit" 2>/dev/null)" == "$head" ]] || build
  put "$1" "$BIN" /usr/local/bin/tt.new 0755
  ct "$1" 'mv -f /usr/local/bin/tt.new /usr/local/bin/tt && /usr/local/bin/tt version 2>&1 | head -1' >&2 || true
}

# gen_key_csr <role> <key path> <owner> <csr path> <CN>: the private key is
# generated on the host that will use it and never leaves it.
gen_key_csr() {
  local id="$1" key="$2" owner="$3" csr="$4" cn="$5"
  ct "$id" "set -e; if [ ! -f '$key' ]; then umask 077; openssl ecparam -name prime256v1 -genkey -noout -out '$key.tmp' && mv '$key.tmp' '$key'; fi; chown $owner:$owner '$key'; chmod 0400 '$key'; openssl req -new -key '$key' -subj '/O=traffic-twin lab/CN=$cn' -out '$csr'"
  get "$id" "$csr" "$PKI/$(basename "$csr")"
}

keyguard() {
  pki
  push_bin "$KG"
  log "keyguard: user, directories, keys"
  ct "$KG" 'set -e
id tt-keyguard >/dev/null 2>&1 || useradd --system --home-dir /var/lib/tt-keyguard --no-create-home --shell /usr/sbin/nologin tt-keyguard
install -d -m 0750 -o root -g tt-keyguard /etc/tt-keyguard
install -d -m 0500 -o tt-keyguard -g tt-keyguard /etc/tt-keyguard/secrets
cd /etc/tt-keyguard/secrets
gen() { # type kid file
  [ -f "$3" ] && return 0
  /usr/local/bin/tt keyguard genkey -type "$1" -kid "$2" -out "/tmp/$3" > "/tmp/$3.pub"
  mv "/tmp/$3" "$3"; chown tt-keyguard:tt-keyguard "$3"; chmod 0400 "$3"
  if [ "$1" = ed25519 ]; then install -m 0644 -o root -g root "/tmp/$3.pub" "/etc/tt-keyguard/$3.pub"; fi
  rm -f "/tmp/$3.pub"
}
chmod 0700 .
gen hmac k1 hmac.keys
gen ed25519 policy-1 policy.key
gen ed25519 pack-1 pack.key
chmod 0500 .'
  gen_key_csr "$KG" /etc/tt-keyguard/secrets/keyguard.key tt-keyguard /etc/tt-keyguard/keyguard.csr tt-keyguard
  # the key directory is 0500: gen_key_csr wrote nothing there as root before chmod? (root bypasses modes)
  sign_csr "$PKI/keyguard.csr" "$PKI/keyguard.crt" serverAuth "$(san_of "$KG_HOST"),DNS:tt-keyguard"
  put "$KG" "$PKI/keyguard.crt" /etc/tt-keyguard/keyguard.crt 0644
  # tt-core's client certificate must exist to compute the pin keyguard enforces.
  core_client_cert
  put "$KG" "$PKI/tt-core-client.crt" /etc/tt-keyguard/tt-core-client.crt 0644
  local pin
  pin="$(ct "$KG" /usr/local/bin/tt keyguard pin /etc/tt-keyguard/tt-core-client.crt)"
  log "keyguard: trusted client pin $pin"
  ct "$KG" "cat >/etc/tt-keyguard/keyguard.env && chown root:tt-keyguard /etc/tt-keyguard/keyguard.env && chmod 0640 /etc/tt-keyguard/keyguard.env" <<EOF
TT_KEYGUARD_LISTEN=0.0.0.0:7443
TT_KEYGUARD_TLS_CERT_FILE=/etc/tt-keyguard/keyguard.crt
TT_KEYGUARD_TLS_KEY_FILE=/etc/tt-keyguard/secrets/keyguard.key
TT_KEYGUARD_CLIENT_PINS=$pin
TT_KEYGUARD_DB=/var/lib/tt-keyguard/tt-keyguard.db
TT_KEYGUARD_HMAC_KEYS_FILE=/etc/tt-keyguard/secrets/hmac.keys
TT_KEYGUARD_POLICY_SIGNING_KEY_FILE=/etc/tt-keyguard/secrets/policy.key
TT_KEYGUARD_PACK_SIGNING_KEY_FILE=/etc/tt-keyguard/secrets/pack.key
TT_KEYGUARD_OPENING_APPROVALS=2
TT_KEYGUARD_ADMIN_OVERRIDE=true
TT_KEYGUARD_LOG_LEVEL=info
EOF
  sed "s|__CORE_ALLOW_IP__|$CORE_ALLOW_IP|" "$LAB_DIR/units/tt-keyguard.service" >"$STATE_DIR/tt-keyguard.service"
  put "$KG" "$STATE_DIR/tt-keyguard.service" /etc/systemd/system/tt-keyguard.service 0644
  ct "$KG" 'systemctl daemon-reload && systemctl enable tt-keyguard >/dev/null 2>&1 && systemctl restart tt-keyguard'
  sleep 2
  ct "$KG" 'systemctl is-active tt-keyguard; journalctl -u tt-keyguard -n 5 --no-pager -o cat' >&2
}

# core_client_cert: key on the core host (tt-core-client.key), certificate signed by the lab CA.
core_client_cert() {
  ct "$CORE" 'id tt-core >/dev/null 2>&1 || useradd --system --home-dir /var/lib/tt-core --no-create-home --shell /usr/sbin/nologin tt-core
install -d -m 0750 -o root -g tt-core /etc/tt; install -d -m 0500 -o tt-core -g tt-core /etc/tt/secrets'
  if [[ ! -f "$PKI/tt-core-client.crt" ]]; then
    gen_key_csr "$CORE" /etc/tt/secrets/tt-core-client.key tt-core /etc/tt/tt-core-client.csr tt-core-client
    sign_csr "$PKI/tt-core-client.csr" "$PKI/tt-core-client.crt" clientAuth "DNS:tt-core-client"
  fi
}

core() {
  pki
  push_bin "$CORE"
  core_client_cert
  log "core: certificates"
  gen_key_csr "$CORE" /etc/tt/secrets/admin.key tt-core /etc/tt/admin.csr tt-core
  if [[ ! -f "$PKI/admin.crt" ]]; then
    sign_csr "$PKI/admin.csr" "$PKI/admin.crt" serverAuth "$(san_of "$CORE_HOST"),DNS:tt-core"
  fi
  put "$CORE" "$PKI/admin.crt" /etc/tt/admin.crt 0644
  put "$CORE" "$PKI/tt-core-client.crt" /etc/tt/tt-core-client.crt 0644
  put "$CORE" "$PKI/lab-ca.crt" /etc/tt/lab-ca.pem 0644
  # keyguard's server pin: computed on the core host from the certificate it will see.
  put "$CORE" "$PKI/keyguard.crt" /etc/tt/keyguard.crt 0644
  local pin
  pin="$(ct "$CORE" /usr/local/bin/tt keyguard pin /etc/tt/keyguard.crt)"
  sed -e "s|__KG_PIN__|$pin|" -e "s|__KG_HOST__|$KG_HOST|" -e "s|__CORE_HOST__|$CORE_HOST|" "$LAB_DIR/core.lab.yaml" >"$STATE_DIR/core.yaml"
  put "$CORE" "$STATE_DIR/core.yaml" /etc/tt/core.yaml 0640
  ct "$CORE" 'chown root:tt-core /etc/tt/core.yaml'
  put "$CORE" "$LAB_DIR/units/tt-core.service" /etc/systemd/system/tt-core.service 0644
  ct "$CORE" 'systemctl daemon-reload && systemctl enable tt-core >/dev/null 2>&1 && systemctl restart tt-core'
  local i
  for i in $(seq 1 30); do
    if curl -fsS --cacert "$PKI/lab-ca.crt" "https://$CORE_HOST:7443/readyz" >/dev/null 2>&1; then log "core: ready"; return 0; fi
    sleep 1
  done
  ct "$CORE" 'systemctl status tt-core --no-pager | head -20; journalctl -u tt-core -n 20 --no-pager -o cat' >&2 || true
  die "tt-core not ready"
}

case "${1:-all}" in
  build) build ;;
  pki) pki ;;
  keyguard) keyguard ;;
  core) core ;;
  all) build; pki; keyguard; core ;;
  *) die "usage: $0 [build|pki|keyguard|core|all]" ;;
esac
