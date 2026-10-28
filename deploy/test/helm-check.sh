#!/usr/bin/env bash
# helm lint --strict and helm template of every chart, with the default values and with the main variants.
# Needs no cluster. If helm is not installed the official alpine/helm image is used through Docker.
#
#   deploy/test/helm-check.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

HELM_IMAGE="alpine/helm:3.14.4"
if command -v helm >/dev/null 2>&1; then
  helm() { command helm "$@"; }
else
  command -v docker >/dev/null 2>&1 || { echo "neither helm nor docker found" >&2; exit 2; }
  helm() { docker run --rm -v "$ROOT:/work" -w /work "$HELM_IMAGE" "$@"; }
fi

fail=0
run() { # run <description> helm-args...
  local d="$1"; shift
  if out="$(helm "$@" 2>&1)"; then printf '  ok   %s\n' "$d"; else printf '  FAIL %s\n%s\n' "$d" "$out" >&2; fail=1; fi
}

for c in tt-core tt-keyguard tt-egress tt-mock tt-injector; do
  echo "==> $c"
  run "lint --strict"          lint --strict "deploy/helm/$c"
  run "template (defaults)"    template t "deploy/helm/$c" -n tt-test
done

echo "==> variants"
run "tt-core: cert-manager, webhooks, OIDC secret" template t deploy/helm/tt-core -n tt-test \
  --set tls.certManager.enabled=true --set tls.certManager.issuerRef.name=ca-issuer \
  --set 'webhooks[0].host=alerts.tt.internal' --set 'webhooks[0].cidr=203.0.113.10/32' --set oidcClientSecret.existingSecret=oidc \
  --set keyguard.url=https://tt-keyguard.tt-keyguard.svc:7443 --set keyguard.clientTLSSecret=kg-client --set keyguard.caFromSecret=false --set keyguard.serverPin=sha256:00 \
  --set persistence.existingClaim=my-claim
run "tt-core: no persistence, no networkpolicy" template t deploy/helm/tt-core -n tt-test \
  --set persistence.enabled=false --set networkPolicy.enabled=false
run "tt-keyguard: installer disabled, client CA, allowed egress" template t deploy/helm/tt-keyguard -n tt-test \
  --set keys.installer.enabled=false --set tls.clientCASecret=core-ca --set 'clientPins[0]=sha256:00' \
  --set 'networkPolicy.egress.allowed[0].cidr=203.0.113.10/32' --set networkPolicy.egress.dns.enabled=true
run "tt-egress: sidecar and upstreams" template t deploy/helm/tt-egress -n tt-test --set sidecar.enabled=true \
  --set 'upstreams[0].alias=carrier' --set 'upstreams[0].url=https://api.carrier.example' \
  --set enroll.url=https://tt-core-intake.traffic-twin.svc:4318 --set enroll.tokenSecret.name=tok --set hmacKey.existingSecret=hm
run "tt-mock: PVC package" template t deploy/helm/tt-mock -n tt-test --set pack.persistentVolumeClaim=packs --set pack.path=twin.ttpack
run "tt-mock: ConfigMap package" template t deploy/helm/tt-mock -n tt-test --set pack.configMap=pack
run "tt-mock: console mode, OpenShift route, console CA" template t deploy/helm/tt-mock -n tt-test \
  --set console.url=https://tt-core.traffic-twin.svc.cluster.local:7070 --set console.group=shop \
  --set console.tokenSecret=tt-mock-token --set console.caConfigMap=tt-ca --set route.enabled=true --set route.host=mock.apps.example
run "tt-core: mock manager" template t deploy/helm/tt-core -n tt-test \
  --set mockManager.enabled=true --set mockManager.namespace=mocks --set mockManager.apiServer.cidr=10.96.0.1/32
run "tt-injector: cert-manager" template t deploy/helm/tt-injector -n tt-test --set tls.mode=certManager
run "tt-injector: existing certificate" template t deploy/helm/tt-injector -n tt-test --set tls.mode=existing \
  --set tls.existingSecret=injector-tls --set tls.caBundle=Zm9v
run "tt-injector: single replica, old Kubernetes (no matchConditions)" template t deploy/helm/tt-injector -n tt-test \
  --set replicaCount=1 --kube-version 1.27.0

[ "$fail" -eq 0 ] && echo "all charts ok" || { echo "chart checks failed" >&2; exit 1; }
