#!/usr/bin/env bash
# Kubernetes end-to-end test of the traffic-twin charts and of the injection webhook, on a throwaway
# kind cluster.
#
#   deploy/test/kind-e2e.sh
#
# What it does
#   1. builds the dev image of `tt` (deploy/test/Dockerfile.tt) and the SDK init images (deploy/images/sdk-*);
#   2. creates the kind cluster "tt-e2e" (or reuses it with TT_E2E_REUSE=1) with a kubeconfig of its own,
#      so the kubeconfig and the current context of the user are never touched;
#   3. installs tt-keyguard and the real tt-core with generated test certificates and keys, in namespaces that
#      enforce Pod Security "restricted" (keyguard: "baseline", for its key installer); creates the first
#      administrator, a group, enrollment tokens and the signed starter policy through the admin API;
#   4. installs tt-injector and checks node, python and (TT_E2E_JAVA=1 / TT_E2E_DOTNET=1) java and .NET injection, coexistence with
#      OpenTelemetry environment variables, refusal of unknown languages, idempotency, and that an
#      unavailable injector does not block pods (failurePolicy Ignore);
#   5. checks that the injected Node and Python pods enroll against the real tt-core (Fleet CA pinned by the
#      token, mTLS) and that tt-core accepts the sanitized events they send;
#   6. installs tt-mock with a signed package and tt-egress.
#
# Requirements: docker, kind, kubectl, helm, go. Everything the script creates is deleted at the end
# unless TT_E2E_KEEP=1.
#
# Variables
#   KIND                kind binary (default: kind)
#   TT_E2E_CLUSTER      cluster name, must start with "tt-e2e" (default tt-e2e)
#   TT_E2E_REUSE=1      reuse an existing cluster of that name and do not delete it
#   TT_E2E_KEEP=1       do not delete the cluster at the end
#   TT_E2E_JAVA=1       also build and test the Java SDK image (needs Maven Central, a few minutes)
#   TT_E2E_DOTNET=1     also build and test the .NET SDK init image (pulls the .NET SDK image, a few minutes)
#   TT_E2E_SKIP_BUILD=1 reuse the local images tt:e2e, tt-sdk-*:e2e
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

KIND="${KIND:-kind}"
CLUSTER="${TT_E2E_CLUSTER:-tt-e2e}"
case "$CLUSTER" in tt-e2e*) ;; *) echo "TT_E2E_CLUSTER must start with tt-e2e (got $CLUSTER)" >&2; exit 2 ;; esac
WORK="$(mktemp -d "${TMPDIR:-/tmp}/tt-e2e.XXXXXX")"
# A kubeconfig of its own: ~/.kube/config and its current context are never read or written.
export KUBECONFIG="$WORK/kubeconfig"
PASS=0
FAILED=0

log()  { printf '\n==> %s\n' "$*"; }
ok()   { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad()  { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "$*" >&2; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1" >&2; exit 2; }; }
check() { # check "description" expected actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: expected [$2], got [$3]"; fi
}
check_contains() { # check_contains "description" needle haystack
  case "$3" in *"$2"*) ok "$1" ;; *) bad "$1: [$2] not found in [$3]" ;; esac
}
check_absent() { # check_absent "description" needle haystack
  case "$3" in *"$2"*) bad "$1: [$2] found in [$3]" ;; *) ok "$1" ;; esac
}
k()  { kubectl "$@"; }

cleanup() {
  local code=$?
  for f in pf.pid pf-admin.pid; do
    if [ -f "$WORK/$f" ]; then kill "$(cat "$WORK/$f")" 2>/dev/null || true; fi
  done
  if [ "${TT_E2E_KEEP:-0}" != 1 ] && [ "${TT_E2E_REUSE:-0}" != 1 ]; then
    "$KIND" delete cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG" >/dev/null 2>&1 || true
  elif [ "${TT_E2E_REUSE:-0}" = 1 ] && [ "${TT_E2E_KEEP:-0}" != 1 ]; then
    helm uninstall tt-injector -n tt-system >/dev/null 2>&1 || true
    k delete mutatingwebhookconfiguration tt-injector --ignore-not-found >/dev/null 2>&1 || true
    for ns in app tt-system traffic-twin tt-keyguard tt-ci; do k delete ns "$ns" --wait=false >/dev/null 2>&1 || true; done
  fi
  if [ "${TT_E2E_KEEP:-0}" = 1 ]; then
    echo "cluster $CLUSTER kept; kubeconfig: $KUBECONFIG"
  else
    rm -rf "$WORK"
  fi
  if [ "$code" -ne 0 ] || [ "$FAILED" -ne 0 ]; then
    echo "RESULT: $FAILED check(s) failed, $PASS passed (exit $code)" >&2
    exit 1
  fi
  echo "RESULT: all $PASS checks passed"
}
trap cleanup EXIT

for t in docker "$KIND" kubectl helm go; do need "$t"; done

# ---------------------------------------------------------------------------------------------------
log "images"
if [ "${TT_E2E_SKIP_BUILD:-0}" != 1 ]; then
  docker build -q -f deploy/test/Dockerfile.tt -t tt:e2e . >/dev/null
  docker build -q -f deploy/images/sdk-node/Dockerfile -t tt-sdk-node:e2e . >/dev/null
  docker build -q -f deploy/images/sdk-python/Dockerfile -t tt-sdk-python:e2e . >/dev/null
  if [ "${TT_E2E_JAVA:-0}" = 1 ]; then
    docker build -q -f deploy/images/sdk-java/Dockerfile -t tt-sdk-java:e2e . >/dev/null
  fi
  if [ "${TT_E2E_DOTNET:-0}" = 1 ]; then
    docker build -q -f deploy/images/sdk-dotnet/Dockerfile -t tt-sdk-dotnet:e2e . >/dev/null
  fi
fi
BASES=(node:24-alpine python:3.12-alpine busybox:1.37.0-musl)
[ "${TT_E2E_JAVA:-0}" = 1 ] && BASES+=(eclipse-temurin:17-jre)
for img in "${BASES[@]}"; do
  docker image inspect "$img" >/dev/null 2>&1 || docker pull -q "$img" >/dev/null
done
go build -o "$WORK/tt" ./cmd/tt
ok "images built"

# ---------------------------------------------------------------------------------------------------
log "cluster $CLUSTER"
if "$KIND" get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  [ "${TT_E2E_REUSE:-0}" = 1 ] || { echo "cluster $CLUSTER exists: delete it or set TT_E2E_REUSE=1" >&2; exit 2; }
  "$KIND" get kubeconfig --name "$CLUSTER" > "$KUBECONFIG"
  chmod 600 "$KUBECONFIG"
  # Leftovers of a previous run: releases first (the webhook configuration is cluster scoped), then namespaces.
  for rel in "tt-system tt-injector" "traffic-twin tt-core" "tt-keyguard tt-keyguard" "tt-ci tt-mock" "tt-ci tt-egress"; do
    helm uninstall ${rel#* } -n "${rel% *}" >/dev/null 2>&1 || true
  done
  k delete mutatingwebhookconfiguration tt-injector --ignore-not-found >/dev/null
  k delete ns app tt-system traffic-twin tt-keyguard tt-ci --ignore-not-found --wait=true >/dev/null
else
  "$KIND" create cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG" --wait 180s >/dev/null
  chmod 600 "$KUBECONFIG"
fi
LOAD=(tt:e2e tt-sdk-node:e2e tt-sdk-python:e2e node:24-alpine python:3.12-alpine busybox:1.37.0-musl)
[ "${TT_E2E_JAVA:-0}" = 1 ] && LOAD+=(tt-sdk-java:e2e eclipse-temurin:17-jre)
[ "${TT_E2E_DOTNET:-0}" = 1 ] && LOAD+=(tt-sdk-dotnet:e2e)
load_images() { # load_images <image>... ; single-platform archive: works with the containerd image store of recent Docker
  local arch
  case "$(docker info --format '{{.Architecture}}')" in aarch64|arm64) arch=arm64 ;; *) arch=amd64 ;; esac
  docker save --platform "linux/$arch" -o "$WORK/images.tar" "$@"
  "$KIND" load image-archive --name "$CLUSTER" "$WORK/images.tar" >/dev/null
  rm -f "$WORK/images.tar"
}
load_images "${LOAD[@]}"
ok "cluster ready: kubernetes $(k get nodes -o jsonpath='{.items[0].status.nodeInfo.kubeletVersion}')"

ns() { # ns <name> <pod-security-level>
  k create namespace "$1" >/dev/null 2>&1 || true
  k label namespace "$1" --overwrite "pod-security.kubernetes.io/enforce=$2" >/dev/null
}
ns tt-system restricted
ns app restricted

# ---------------------------------------------------------------------------------------------------
log "platform: keyguard and tt-core"
ns traffic-twin restricted
ns tt-keyguard baseline   # the key installer init container runs as root with CAP_CHOWN
ns tt-ci restricted

go run ./deploy/test/mkpki -out "$WORK/pki" \
  -core-dns "tt-core,tt-core-intake,tt-core.traffic-twin.svc,tt-core-intake.traffic-twin.svc,tt-core.traffic-twin.svc.cluster.local,tt-core-intake.traffic-twin.svc.cluster.local" \
  -keyguard-dns "tt-keyguard,tt-keyguard.tt-keyguard.svc,tt-keyguard.tt-keyguard.svc.cluster.local"
"$WORK/tt" keyguard genkey -type hmac -kid e2ek1 -out "$WORK/hmac.keys" >/dev/null
"$WORK/tt" keyguard genkey -type ed25519 -kid e2epol1 -out "$WORK/policy.key" >/dev/null
"$WORK/tt" keyguard genkey -type ed25519 -kid e2epack1 -out "$WORK/pack.key" >/dev/null
PIN="$("$WORK/tt" keyguard pin "$WORK/pki/core-client.crt")"

k -n tt-keyguard create secret tls tt-keyguard-tls --cert="$WORK/pki/keyguard.crt" --key="$WORK/pki/keyguard.key" >/dev/null
k -n tt-keyguard create secret generic tt-keyguard-keys --from-file=hmac-keys="$WORK/hmac.keys" \
  --from-file=policy-signing-key="$WORK/policy.key" --from-file=pack-signing-key="$WORK/pack.key" >/dev/null
k -n traffic-twin create secret tls tt-core-tls --cert="$WORK/pki/core.crt" --key="$WORK/pki/core.key" >/dev/null
k -n traffic-twin create secret generic tt-core-keyguard-client --from-file=tls.crt="$WORK/pki/core-client.crt" \
  --from-file=tls.key="$WORK/pki/core-client.key" --from-file=ca.crt="$WORK/pki/ca.crt" >/dev/null

IMG=(--set image.repository=tt --set-string image.tag=e2e --set image.pullPolicy=Never)
for c in tt-core tt-keyguard tt-egress tt-mock; do helm lint "deploy/helm/$c" >/dev/null && ok "helm lint $c"; done

helm install tt-keyguard deploy/helm/tt-keyguard -n tt-keyguard "${IMG[@]}" --set "clientPins[0]=$PIN" \
  --set 'persistence.size=100Mi' --wait --timeout 240s >/dev/null
ok "tt-keyguard Ready (key files accepted with mode 0400 by the installer)"
check "keyguard: container is non-root with read-only rootfs" "65532 true" \
  "$(k -n tt-keyguard get pod tt-keyguard-0 -o jsonpath='{.spec.securityContext.runAsUser} {.spec.containers[0].securityContext.readOnlyRootFilesystem}')"

helm install tt-core deploy/helm/tt-core -n traffic-twin "${IMG[@]}" --set tls.existingSecret=tt-core-tls \
  --set 'persistence.size=100Mi' --wait --timeout 240s >/dev/null
ok "tt-core Ready (readiness probe /readyz over HTTPS)"
check_contains "core: serving over https" "https://" "$(k -n traffic-twin logs tt-core-0)"
check "core: the PVC is bound" "Bound" "$(k -n traffic-twin get pvc data-tt-core-0 -o jsonpath='{.status.phase}')"

# NetworkPolicy: a pod outside tt-core must not reach keyguard. Needs a CNI that enforces policies; kindnet does since v0.27.
if k run np-probe -n default --image=busybox:1.37.0-musl --image-pull-policy=IfNotPresent --restart=Never --rm -i --quiet --command -- \
     sh -c 'nc -z -w 3 tt-keyguard.tt-keyguard.svc.cluster.local 7443' >/dev/null 2>&1; then
  echo "  WARN the CNI of this cluster does not enforce NetworkPolicy: isolation of keyguard not verified"
else
  ok "keyguard: unreachable from a pod that is not tt-core (NetworkPolicy)"
fi


# ---------------------------------------------------------------------------------------------------
log "tt-core: administrator, group and enrollment token"
ADMIN=https://tt-core.traffic-twin.svc:7070
(k -n traffic-twin port-forward svc/tt-core 17070:7070 >"$WORK/pf-admin.log" 2>&1 & echo $! > "$WORK/pf-admin.pid")
api() { # api <jar> <method> <path> [json]: sets API_CODE and API_BODY. One cookie jar and CSRF token per user.
  local jar=$1 method=$2 path=$3 body=${4:-}
  local args=(-sS --cacert "$WORK/pki/ca.crt" --connect-to "tt-core.traffic-twin.svc:7070:127.0.0.1:17070"
    -b "$WORK/jar-$jar" -c "$WORK/jar-$jar" -X "$method" -H 'Content-Type: application/json' -o "$WORK/api.out" -w '%{http_code}')
  if [ -f "$WORK/csrf-$jar" ]; then args+=(-H "X-CSRF-Token: $(cat "$WORK/csrf-$jar")"); fi
  if [ -n "$body" ]; then args+=(--data "$body"); fi
  API_CODE="$(curl "${args[@]}" "$ADMIN$path" 2>"$WORK/api.err")" || API_CODE=000
  API_BODY="$(cat "$WORK/api.out" 2>/dev/null || true)"
}
jfield() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" <<<"$API_BODY" | head -1; }
api_ok() { # api_ok <want-code> <description> <jar> <method> <path> [json]
  local want=$1 what=$2; shift 2
  api "$@"
  if [ "$API_CODE" = "$want" ]; then ok "$what"; else bad "$what: HTTP $API_CODE: $API_BODY"; fi
}
for _ in $(seq 1 30); do
  curl -fsS --cacert "$WORK/pki/ca.crt" --connect-to "tt-core.traffic-twin.svc:7070:127.0.0.1:17070" "$ADMIN/healthz" >/dev/null 2>&1 && break
  sleep 1
done
PW="$(head -c 24 /dev/urandom | base64 | tr -d '+/=\n')"
SETUP_TOKEN="$(k -n traffic-twin exec tt-core-0 -- cat /data/setup-token 2>/dev/null | tr -d ' \r\n')"
[ -n "$SETUP_TOKEN" ] || { bad "no setup token file (/data/setup-token) in tt-core"; exit 1; }
api ada POST /api/v1/setup "{\"setup_token\":\"$SETUP_TOKEN\",\"username\":\"ada\",\"password\":\"$PW\"}"
if [ "$API_CODE" = 200 ] || [ "$API_CODE" = 201 ]; then ok "first administrator created with the setup token"; else bad "setup: HTTP $API_CODE: $API_BODY"; fi
jfield csrf_token > "$WORK/csrf-ada"
api_ok 201 "operator created" ada POST /api/v1/users "{\"username\":\"olga\",\"password\":\"$PW\",\"roles\":[\"operator\"]}"
api olga POST /api/v1/auth/login "{\"username\":\"olga\",\"password\":\"$PW\"}"
jfield csrf_token > "$WORK/csrf-olga"
api_ok 201 "group created" olga POST /api/v1/fleet/groups '{"name":"e2e","allowed_service_names":["node-app","py-app"],"policy_id":"p-e2e"}'
api_ok 201 "group enrollment token created" olga POST /api/v1/fleet/enrollment-tokens '{"kind":"sdk-node","group":"e2e","token_type":"group"}'
ENROLL_TOKEN="$(jfield token)"
TOKEN_ID="$(jfield token_id)"
# A token is bound to the kind of SDK that uses it: one more for the Python application.
api_ok 201 "group enrollment token for sdk-python created" olga POST /api/v1/fleet/enrollment-tokens '{"kind":"sdk-python","group":"e2e","token_type":"group"}'
ENROLL_TOKEN_PY="$(jfield token)"
api_ok 201 "starter policy proposed (sampling 100%)" olga POST /api/v1/fleet/groups/e2e/starter-policy '{"hmac_kid":"e2ek1","epoch":"2026-10","sampling_rate":"1.0"}'
POLICY_VERSION="$(sed -n 's/.*"version":\([0-9]*\).*/\1/p' <<<"$API_BODY" | head -1)"
api_ok 200 "starter policy approved by the administrator (reason given) and signed by keyguard" ada POST \
  "/api/v1/fleet/policies/p-e2e/versions/$POLICY_VERSION/approve" '{"reason":"kind e2e single-maintainer trial"}'
check_contains "enrollment token carries the Fleet CA pin" "tte_" "$ENROLL_TOKEN"

# ---------------------------------------------------------------------------------------------------
log "tt-injector"
INJ_SET=(--set image.repository=tt --set-string image.tag=e2e --set image.pullPolicy=Never
  --set sdkImages.node=tt-sdk-node:e2e --set sdkImages.python=tt-sdk-python:e2e --set sdkPullPolicy=Never
  --set replicaCount=1)
[ "${TT_E2E_JAVA:-0}" = 1 ] && INJ_SET+=(--set sdkImages.java=tt-sdk-java:e2e) || INJ_SET+=(--set sdkImages.java=)
[ "${TT_E2E_DOTNET:-0}" = 1 ] && INJ_SET+=(--set sdkImages.dotnet=tt-sdk-dotnet:e2e) || INJ_SET+=(--set sdkImages.dotnet=)
helm lint deploy/helm/tt-injector "${INJ_SET[@]}" >/dev/null && ok "helm lint tt-injector"
helm install tt-injector deploy/helm/tt-injector -n tt-system "${INJ_SET[@]}" --wait --timeout 180s >/dev/null
ok "tt-injector installed"

# With failurePolicy Ignore a pod created before the API server can reach the webhook is simply not
# injected, so wait until a server-side dry run shows the injection.
for _ in $(seq 1 60); do
  if k create --dry-run=server -o jsonpath='{.spec.initContainers[0].name}' -f - 2>/dev/null <<EOF | grep -q tt-sdk-init
apiVersion: v1
kind: Pod
metadata: {name: probe, namespace: app, annotations: {traffic-twin.io/inject: node}}
spec: {containers: [{name: c, image: node:24-alpine}]}
EOF
  then break; fi
  sleep 2
done
ok "the webhook answers the API server"

# The same Secrets a user would create: the intake URL of tt-core, the group token and the HMAC key of the
# group (the file keyguard holds, so that its reverse-HMAC check can match the tokens of this source).
HMAC="$(tr -d '\n' < "$WORK/hmac.keys")"
k -n app create secret generic tt-enroll --from-literal=url=https://tt-core-intake.traffic-twin.svc.cluster.local:4318 \
  --from-literal=token="$ENROLL_TOKEN" >/dev/null
k -n app create secret generic tt-enroll-py --from-literal=url=https://tt-core-intake.traffic-twin.svc.cluster.local:4318 \
  --from-literal=token="$ENROLL_TOKEN_PY" >/dev/null   # selected with the annotation traffic-twin.io/enroll-secret
k -n app create secret generic tt-hmac --from-file=hmac-key="$WORK/hmac.keys" >/dev/null

# Restricted application container, to prove that the injected pod stays Pod-Security compliant.
SEC='securityContext: {allowPrivilegeEscalation: false, runAsNonRoot: true, runAsUser: 1000, capabilities: {drop: [ALL]}, seccompProfile: {type: RuntimeDefault}}'

apply_app() { # reads a manifest on stdin, prints the kubectl output (with admission warnings) on stdout
  k apply -f - 2>&1
}

pod_of() { k -n app get pod -l "app=$1" -o jsonpath='{.items[0].metadata.name}'; }
jp()     { k -n app get pod "$1" -o jsonpath="$2"; }

log "node injection"
OUT="$(apply_app <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: {name: node-app, namespace: app}
spec:
  replicas: 1
  selector: {matchLabels: {app: node-app}}
  template:
    metadata:
      labels: {app: node-app}
      annotations: {traffic-twin.io/inject: node}
    spec:
      containers:
        - name: app
          image: node:24-alpine
          imagePullPolicy: Never
          command: [node, -e, "require('http').createServer((q,r)=>r.end('ok')).listen(8080)"]
          env: [{name: TT_DEBUG, value: "1"}]
          $SEC
EOF
)"
k -n app rollout status deploy/node-app --timeout=150s >/dev/null
P="$(pod_of node-app)"
check "node: init container added"            "tt-sdk-init" "$(jp "$P" '{.spec.initContainers[*].name}')"
check "node: init container exited 0"         "0" "$(jp "$P" '{.status.initContainerStatuses[0].state.terminated.exitCode}')"
check "node: NODE_OPTIONS wired"              "--import /tt/sdk/node/dist/esm/register.js" "$(jp "$P" '{.spec.containers[0].env[?(@.name=="NODE_OPTIONS")].value}')"
check "node: TT_SERVICE_NAME from label"      "node-app" "$(jp "$P" '{.spec.containers[0].env[?(@.name=="TT_SERVICE_NAME")].value}')"
check "node: TT_ENROLL_URL from Secret"       "tt-enroll" "$(jp "$P" '{.spec.containers[0].env[?(@.name=="TT_ENROLL_URL")].valueFrom.secretKeyRef.name}')"
check "node: status annotation"               "injected" "$(jp "$P" '{.metadata.annotations.traffic-twin\.io/inject-status}')"
check "node: SDK files visible to the app"    "/tt/sdk/node/dist/esm/register.js" "$(k -n app exec "$P" -c app -- ls /tt/sdk/node/dist/esm/register.js)"
check "node: HMAC key mounted"                "$HMAC" "$(k -n app exec "$P" -c app -- cat /var/run/secrets/traffic-twin/hmac-key)"
check_contains "node: the agent started in the app process" "[traffic-twin]" "$(k -n app logs "$P" -c app)"
check "node: the application still serves"    "ok" "$(k -n app exec "$P" -c app -- node -e "fetch('http://127.0.0.1:8080').then(r=>r.text()).then(console.log)")"
check "node: exactly one init container" "1" "$(jp "$P" '{.spec.initContainers[*].name}' | wc -w | tr -d ' ')"

log "python injection"
apply_app >/dev/null <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: {name: py-app, namespace: app}
spec:
  replicas: 1
  selector: {matchLabels: {app: py-app}}
  template:
    metadata:
      labels: {app: py-app}
      annotations: {traffic-twin.io/inject: python, traffic-twin.io/enroll-secret: tt-enroll-py}
    spec:
      containers:
        - name: web
          image: python:3.12-alpine
          imagePullPolicy: Never
          command: [python, -m, http.server, "8080"]
          env: [{name: TT_DEBUG, value: "1"}, {name: PYTHONPATH, value: /srv/lib}]
          $SEC
EOF
k -n app rollout status deploy/py-app --timeout=150s >/dev/null
P="$(pod_of py-app)"
check "python: PYTHONPATH wired, existing entry kept" "/tt/sdk/python/bootstrap:/tt/sdk/python/site:/srv/lib" "$(jp "$P" '{.spec.containers[0].env[?(@.name=="PYTHONPATH")].value}')"
check_contains "python: the agent started in the app process" "[traffic-twin]" "$(k -n app logs "$P" -c web)"

log "enrollment of the injected pods against the real tt-core"
wait_source() { # wait_source <service-name>: the source is listed as capturing
  local i
  for i in $(seq 1 90); do
    api olga GET /api/v1/fleet/sources
    case "$API_BODY" in *"\"service_name\":\"$1\""*) case "$API_BODY" in *'"state":"capturing"'*) return 0 ;; esac ;; esac
    sleep 2
  done
  return 1
}
if wait_source node-app; then ok "node-app: enrolled through the injected SDK and capturing under the signed policy"; else bad "node-app never reached capturing: $API_BODY"; fi
if wait_source py-app; then ok "py-app: enrolled through the injected SDK (Secret chosen by annotation)"; else bad "py-app was not enrolled: $API_BODY"; fi
P="$(pod_of node-app)"
for i in $(seq 1 40); do
  k -n app exec "$P" -c app -- env -u NODE_OPTIONS node -e "fetch('http://127.0.0.1:8080/orders/$i').then(r=>r.text())" >/dev/null 2>&1 || true
done
EVENTS=0
for _ in $(seq 1 45); do
  api olga GET "/api/v1/fleet/onboarding/$TOKEN_ID/status"
  EVENTS="$(sed -n 's/.*"first_events":\([0-9]*\).*/\1/p' <<<"$API_BODY" | head -1)"
  [ "${EVENTS:-0}" -gt 0 ] && break
  sleep 2
done
if [ "${EVENTS:-0}" -gt 0 ]; then ok "tt-core accepted $EVENTS sanitized event(s) from the injected pod"; else bad "no event accepted by tt-core: $API_BODY"; fi
check_contains "onboarding: enrolled and policy received" '"enrolled":true' "$API_BODY"
check_contains "onboarding: policy received" '"policy_received":true' "$API_BODY"

if [ "${TT_E2E_JAVA:-0}" = 1 ]; then
  log "java injection"
  apply_app >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: java-app
  namespace: app
  labels: {app: java-app}
  annotations: {traffic-twin.io/inject: java, traffic-twin.io/java-classpath: "true", traffic-twin.io/java-otel-extension: "true"}
spec:
  containers:
    - name: app
      image: eclipse-temurin:17-jre
      imagePullPolicy: Never
      command: [sh, -c, "ls /tt/sdk/java/lib /tt/sdk/java/ext /tt/sdk/java/agent && sleep 3600"]
      $SEC
EOF
  k -n app wait pod/java-app --for=condition=Ready --timeout=150s >/dev/null
  check_contains "java: jars copied" "sdk.jar" "$(k -n app logs java-app -c app)"
  check_contains "java: OTel extension option" "-Dotel.javaagent.extensions=/tt/sdk/java/ext/sdk-otel-extension.jar" "$(k -n app get pod java-app -o jsonpath='{.spec.containers[0].env[?(@.name=="JAVA_TOOL_OPTIONS")].value}')"
  # The init image (deploy/images/sdk-java/Dockerfile) puts the agent in /sdk/java/agent, copied to /tt/sdk/java/agent.
  check_contains "java: agent jar copied" "traffic-twin-agent.jar" "$(k -n app logs java-app -c app)"
  check "java: CLASSPATH opt-in" "/tt/sdk/java/lib/*" "$(k -n app get pod java-app -o jsonpath='{.spec.containers[0].env[?(@.name=="CLASSPATH")].value}')"

  # Zero-code mode: the -javaagent path must be the one the init image installs, and the JVM must be able to open it.
  apply_app >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: java-agent-app
  namespace: app
  annotations: {traffic-twin.io/inject: java}
spec:
  containers:
    - name: app
      image: eclipse-temurin:17-jre
      imagePullPolicy: Never
      command: [sh, -c, "java -version 2>&1; ls -l /tt/sdk/java/agent/traffic-twin-agent.jar; sleep 3600"]
      $SEC
EOF
  k -n app wait pod/java-agent-app --for=condition=Ready --timeout=150s >/dev/null
  check_contains "java agent: -javaagent path" "-javaagent:/tt/sdk/java/agent/traffic-twin-agent.jar" "$(jp java-agent-app '{.spec.containers[0].env[?(@.name=="JAVA_TOOL_OPTIONS")].value}')"
  check_contains "java agent: the JVM starts with the agent" "openjdk version" "$(k -n app logs java-agent-app -c app)"
  check_absent "java agent: no error opening the jar" "Error opening zip file" "$(k -n app logs java-agent-app -c app)"
fi

log "coexistence with OpenTelemetry settings"
apply_app >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: otel-app
  namespace: app
  annotations: {traffic-twin.io/inject: node, instrumentation.opentelemetry.io/inject-nodejs: "true"}
spec:
  containers:
    - name: app
      image: node:24-alpine
      imagePullPolicy: Never
      command: [node, -e, "setInterval(()=>{},1000)"]
      env:
        - {name: NODE_OPTIONS, value: "--max-old-space-size=128"}
        - {name: OTEL_SERVICE_NAME, value: "shop-from-otel"}
        - {name: OTEL_EXPORTER_OTLP_ENDPOINT, value: "http://collector.invalid:4318"}
      $SEC
EOF
k -n app wait pod/otel-app --for=condition=Ready --timeout=150s >/dev/null
check "otel: NODE_OPTIONS extended, not replaced" "--max-old-space-size=128 --import /tt/sdk/node/dist/esm/register.js" "$(jp otel-app '{.spec.containers[0].env[?(@.name=="NODE_OPTIONS")].value}')"
check "otel: OTEL_SERVICE_NAME untouched"         "shop-from-otel" "$(jp otel-app '{.spec.containers[0].env[?(@.name=="OTEL_SERVICE_NAME")].value}')"
check "otel: OTEL_EXPORTER_OTLP_ENDPOINT untouched" "http://collector.invalid:4318" "$(jp otel-app '{.spec.containers[0].env[?(@.name=="OTEL_EXPORTER_OTLP_ENDPOINT")].value}')"
check "otel: no TT_SERVICE_NAME next to OTEL_SERVICE_NAME" "" "$(jp otel-app '{.spec.containers[0].env[?(@.name=="TT_SERVICE_NAME")].value}')"
check_absent "otel: no OTEL variable added" "OTEL_TRACES" "$(jp otel-app '{.spec.containers[0].env[*].name}')"

log "pods that must not change"
apply_app >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: plain-app, namespace: app}
spec:
  containers:
    - name: app
      image: node:24-alpine
      imagePullPolicy: Never
      command: [node, -e, "setInterval(()=>{},1000)"]
      $SEC
EOF
k -n app wait pod/plain-app --for=condition=Ready --timeout=150s >/dev/null
check "plain: no init container" "" "$(jp plain-app '{.spec.initContainers[*].name}')"
check "plain: no TT_* variable"  "" "$(jp plain-app '{.spec.containers[0].env[*].name}')"

OUT="$(apply_app <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ruby-app
  namespace: app
  annotations: {traffic-twin.io/inject: ruby}
spec:
  containers:
    - name: app
      image: node:24-alpine
      imagePullPolicy: Never
      command: [node, -e, "setInterval(()=>{},1000)"]
      $SEC
EOF
)"
k -n app wait pod/ruby-app --for=condition=Ready --timeout=150s >/dev/null
check_contains "unknown language: admission warning shown" "unknown language" "$OUT"
check "unknown language: pod runs unmodified" "" "$(jp ruby-app '{.spec.initContainers[*].name}')"
check_contains "unknown language: status annotation" "refused: unknown language" "$(jp ruby-app '{.metadata.annotations.traffic-twin\.io/inject-status}')"

if [ "${TT_E2E_DOTNET:-0}" = 1 ]; then
  log "dotnet injection"
  # Zero-code: DOTNET_STARTUP_HOOKS + ASPNETCORE_HOSTINGSTARTUPASSEMBLIES (sdk/dotnet/README.md). The init image
  # copies the hook, TrafficTwin.Sdk and TrafficTwin.Sdk.AspNetCore to /tt/sdk/dotnet; any image will do for this check.
  apply_app >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: dotnet-app
  namespace: app
  labels: {app: orders}
  annotations: {traffic-twin.io/inject: dotnet}
spec:
  containers:
    - name: app
      image: busybox:1.37.0-musl
      imagePullPolicy: Never
      command: [sh, -c, "ls /tt/sdk/dotnet && sleep 3600"]
      $SEC
EOF
  k -n app wait pod/dotnet-app --for=condition=Ready --timeout=150s >/dev/null
  check "dotnet: init container" "tt-sdk-init" "$(jp dotnet-app '{.spec.initContainers[*].name}')"
  check_contains "dotnet: hook copied" "TrafficTwin.StartupHook.dll" "$(k -n app logs dotnet-app -c app)"
  check_contains "dotnet: SDK assemblies copied" "TrafficTwin.Sdk.AspNetCore.dll" "$(k -n app logs dotnet-app -c app)"
  check "dotnet: DOTNET_STARTUP_HOOKS" "/tt/sdk/dotnet/TrafficTwin.StartupHook.dll" "$(jp dotnet-app '{.spec.containers[0].env[?(@.name=="DOTNET_STARTUP_HOOKS")].value}')"
  check "dotnet: ASPNETCORE_HOSTINGSTARTUPASSEMBLIES" "TrafficTwin.Sdk.AspNetCore" "$(jp dotnet-app '{.spec.containers[0].env[?(@.name=="ASPNETCORE_HOSTINGSTARTUPASSEMBLIES")].value}')"
  check "dotnet: TT_SERVICE_NAME" "orders" "$(jp dotnet-app '{.spec.containers[0].env[?(@.name=="TT_SERVICE_NAME")].value}')"
fi

log "failurePolicy Ignore: an unavailable injector does not block pods"
k -n tt-system scale deploy/tt-injector --replicas=0 >/dev/null
k -n tt-system wait --for=delete pod -l app.kubernetes.io/name=tt-injector --timeout=60s >/dev/null 2>&1 || true
apply_app >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: no-injector
  namespace: app
  annotations: {traffic-twin.io/inject: node}
spec:
  containers:
    - name: app
      image: node:24-alpine
      imagePullPolicy: Never
      command: [node, -e, "setInterval(()=>{},1000)"]
      $SEC
EOF
k -n app wait pod/no-injector --for=condition=Ready --timeout=150s >/dev/null
check "no injector: the pod was created and runs, without the SDK" "" "$(jp no-injector '{.spec.initContainers[*].name}')"
k -n tt-system scale deploy/tt-injector --replicas=1 >/dev/null

# ---------------------------------------------------------------------------------------------------
log "charts: mock and egress"
# tt-mock with a signed package shipped as an OCI image (init container copy).
mkdir -p "$WORK/packctx"   # a build context of its own: the keys in $WORK must not reach the Docker daemon
GATE_KEYS="$(go run ./deploy/test/mkpack "$WORK/packctx/pack")"
cat > "$WORK/packctx/Dockerfile" <<EOF
FROM busybox:1.37.0-musl
COPY pack /pack
USER 65532:65532
EOF
docker build -q -t tt-pack:e2e "$WORK/packctx" >/dev/null
load_images tt-pack:e2e
k -n tt-ci create secret generic tt-mock-control --from-literal=token=e2e-control-token >/dev/null
helm install tt-mock deploy/helm/tt-mock -n tt-ci "${IMG[@]}" --set pack.image.repository=tt-pack --set-string pack.image.tag=e2e \
  --set pack.image.pullPolicy=Never --set "gatePubKeys=$GATE_KEYS" --set controlToken.existingSecret=tt-mock-control \
  --set 'extraArgs={--latency,record}' --wait --timeout 180s >/dev/null
ok "tt-mock Ready with a signed package"
(k -n tt-ci port-forward svc/tt-mock 18480:8480 >"$WORK/pf.log" 2>&1 & echo $! > "$WORK/pf.pid")
for _ in $(seq 1 30); do curl -fsS -o /dev/null http://127.0.0.1:18480/__tt/health 2>/dev/null && break; sleep 1; done
check "mock: /__tt/health" '{"status":"ok"}' "$(curl -fsS http://127.0.0.1:18480/__tt/health | tr -d '\n ')"
check_contains "mock: control API needs the token" "401" "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18480/__tt/pack)"
check_contains "mock: package loaded" "pack_id" "$(curl -fsS -H 'Authorization: Bearer e2e-control-token' http://127.0.0.1:18480/__tt/pack)"
kill "$(cat "$WORK/pf.pid")" 2>/dev/null || true

helm install tt-egress deploy/helm/tt-egress -n tt-ci "${IMG[@]}" --set 'upstreams[0].alias=mock' \
  --set 'upstreams[0].url=http://tt-mock.tt-ci.svc.cluster.local:8480' --set sidecar.enabled=true --wait --timeout 180s >/dev/null
ok "tt-egress Ready (forward-only mode)"
check_contains "egress: sidecar snippet published" "name: tt-egress" "$(k -n tt-ci get configmap tt-egress-sidecar -o jsonpath='{.data.snippet\.yaml}')"
