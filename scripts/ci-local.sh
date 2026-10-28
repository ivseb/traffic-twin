#!/bin/sh
# Runs the same checks as .github/workflows/ci.yml on this machine.
# Toolchains that are not installed (or too old) run in the official Docker
# images; everything else uses the local toolchain.
#
#   make ci-local                          every step, one runtime per SDK
#   make ci-local ONLY="go sdk-node"       only these steps
#   make ci-local SKIP="sdk-dotnet"        everything but these
#   make ci-local MATRIX=full              the whole runtime matrix of CI (many Docker pulls, slow)
#
# Steps: go vectors ui build sdk-go sdk-node sdk-python sdk-java sdk-dotnet
#        sdk-php sdk-package actionlint goreleaser
#
# Every step runs even if an earlier one fails; the exit status is non-zero if
# any step failed. Full logs: $TT_CI_LOGDIR (default $TMPDIR/tt-ci-local).
set -u

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

ONLY=${ONLY:-}
SKIP=${SKIP:-}
MATRIX=${MATRIX:-default}
logdir=${TT_CI_LOGDIR:-${TMPDIR:-/tmp}/tt-ci-local}
mkdir -p "$logdir"

# Runtime matrix of the SDK jobs in ci.yml (keep in sync).
if [ "$MATRIX" = full ]; then
  NODE_VERSIONS="20 22 24"
  PYTHON_VERSIONS="3.9 3.11 3.13"
  JAVA_VERSIONS="17 21"
  DOTNET_VERSIONS="8.0 10.0"
  PHP_VERSIONS="8.1 8.3 8.4"
else
  NODE_VERSIONS="24"
  PYTHON_VERSIONS="3.13"
  JAVA_VERSIONS="17"
  DOTNET_VERSIONS="8.0"
  PHP_VERSIONS="8.3"
fi

# ---------------------------------------------------------------- helpers

have() { command -v "$1" >/dev/null 2>&1; }

need_docker() {
  have docker && docker info >/dev/null 2>&1 && return 0
  echo "Docker is required for this step and is not running" >&2
  return 1
}

# docker_run IMAGE [docker args...] -- command...
# Mounts the repository at /repo; HOME-like caches live in named volumes.
docker_run() {
  img=$1; shift
  dargs=""
  while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do dargs="$dargs $1"; shift; done
  shift
  need_docker || return 1
  # shellcheck disable=SC2086
  docker run --rm -v "$root":/repo -w /repo $dargs "$img" "$@"
}

# local_major CMD VERSION_ARGS REGEX: major version of a local tool, or empty.
node_major() { have node && node -p 'process.versions.node.split(".")[0]' 2>/dev/null; }
java_major() { have java && java -version 2>&1 | sed -n '1s/.*version "\([0-9]*\).*/\1/p'; }

results=""
failed=0

# step NAME COMMAND...: runs, logs, records.
step() {
  name=$1; shift
  if [ -n "$ONLY" ]; then case " $ONLY " in *" $name "*) ;; *) return 0 ;; esac; fi
  case " $SKIP " in *" $name "*) return 0 ;; esac
  echo ""
  echo "=== $name"
  start=$(date +%s)
  if "$@" >"$logdir/$name.log" 2>&1; then status=PASS; else status=FAIL; failed=1; fi
  secs=$(( $(date +%s) - start ))
  if [ "$status" = FAIL ]; then
    echo "--- last lines of $logdir/$name.log"
    tail -n 25 "$logdir/$name.log"
  fi
  echo "=== $name: $status (${secs}s)"
  results="$results
$(printf '%-16s %-5s %5ss' "$name" "$status" "$secs")"
}

# ---------------------------------------------------------------- Go

go_run() {
  # Local Go if recent enough, else the official image (go.mod: "go 1.25.0").
  want=$(sed -n 's/^go \([0-9]*\.[0-9]*\).*/\1/p' go.mod | head -n 1)
  if have go && go version | grep -q "go$want"; then
    sh -c "$1"
  else
    docker_run "golang:$want" -v tt-ci-gomod:/go/pkg/mod -e GOFLAGS=-buildvcs=false -- sh -c "$1"
  fi
}

step_go() {
  go_run 'make fmt-check tidy-check vet build-all test race'
}

step_vectors() {
  if have python3; then make vectors
  else docker_run python:3.13-slim -e PYTHONDONTWRITEBYTECODE=1 -- sh -c 'python3 conformance/ref/gen_vectors.py --check && python3 conformance/ref/run.py && python3 conformance/ref/leakcheck.py'
  fi
}

step_ui() {
  if [ "$(node_major)" -ge 20 ] 2>/dev/null; then sh scripts/ui-build-check.sh
  else docker_run node:24 -v tt-ci-ui-modules:/repo/ui/node_modules -- sh scripts/ui-build-check.sh
  fi
}

step_build() {
  # Needs the production UI in internal/ui/dist (the `ui` step leaves it there; make rebuilds if stale).
  if [ "$(node_major)" -ge 20 ] 2>/dev/null && have go; then
    make build && sh scripts/smoke.sh bin/tt
  else
    echo "make build needs local Go and Node; skipped (CI runs it)"; return 1
  fi
}

step_sdk_go() {
  for m in . gin chi otelctx; do
    go_run "sh scripts/sdk-test.sh go all $m" || return 1
  done
}

# ---------------------------------------------------------------- SDKs

step_sdk_node() {
  for v in $NODE_VERSIONS; do
    echo "-- node $v"
    if [ "$(node_major)" = "$v" ]; then runner="sh"; else runner="node_docker $v"; fi
    $runner scripts/sdk-test.sh node setup || return 1
    $runner scripts/sdk-test.sh node vectors || return 1
    if ! $runner scripts/sdk-test.sh node test; then
      # Same exception as ci.yml: before Node 24 fetch response bodies are not visible.
      if [ "$v" != 24 ]; then echo "WARNING: node $v integration tests fail (known, tolerated like in CI)"; else return 1; fi
    fi
  done
}

node_docker() {
  v=$1; shift
  docker_run "node:$v" -v "tt-ci-node-modules-$v:/repo/sdk/node/node_modules" -- sh "$@"
}

step_sdk_python() {
  for v in $PYTHON_VERSIONS; do
    echo "-- python $v"
    docker_run "python:$v-slim" -v tt-ci-pip:/root/.cache/pip -e PYTHONDONTWRITEBYTECODE=1 -- sh scripts/sdk-test.sh python all || return 1
  done
}

step_sdk_java() {
  for v in $JAVA_VERSIONS; do
    echo "-- java $v"
    if [ "$(java_major)" = "$v" ]; then sh scripts/sdk-test.sh java all || return 1
    else docker_run "eclipse-temurin:$v-jdk" -v tt-ci-m2:/root/.m2 -- sh scripts/sdk-test.sh java all || return 1
    fi
  done
}

step_sdk_dotnet() {
  for v in $DOTNET_VERSIONS; do
    echo "-- dotnet $v"
    roll=""
    # The projects target net8.0: newer runtimes run them with roll-forward.
    [ "$v" != "8.0" ] && roll="-e DOTNET_ROLL_FORWARD=LatestMajor"
    docker_run "mcr.microsoft.com/dotnet/sdk:$v" -v tt-dotnet-nuget:/root/.nuget/packages $roll -- sh scripts/sdk-test.sh dotnet all || return 1
  done
}

step_sdk_php() {
  need_docker || return 1
  for v in $PHP_VERSIONS; do
    echo "-- php $v"
    sh scripts/sdk-test.sh php all "$v" || return 1
  done
}

step_sdk_package() {
  out="$logdir/packages"
  rm -rf "$out"; mkdir -p "$out"
  if [ "$(node_major)" -ge 20 ] 2>/dev/null; then sh scripts/sdk-package.sh node "$out" || return 1
  else docker_run node:24 -v tt-ci-node-modules-24:/repo/sdk/node/node_modules -v "$out":/out -- sh scripts/sdk-package.sh node /out || return 1
  fi
  docker_run python:3.13-slim -v "$out":/out -e PYTHONDONTWRITEBYTECODE=1 -- sh scripts/sdk-package.sh python /out || return 1
  if [ "$(java_major)" -ge 17 ] 2>/dev/null; then sh scripts/sdk-package.sh java "$out" || return 1
  else docker_run eclipse-temurin:17-jdk -v tt-ci-m2:/root/.m2 -v "$out":/out -- sh scripts/sdk-package.sh java /out || return 1
  fi
  docker_run mcr.microsoft.com/dotnet/sdk:8.0 -v tt-dotnet-nuget:/root/.nuget/packages -v "$out":/out -- sh scripts/sdk-package.sh dotnet /out || return 1
  docker_run composer:2 -- sh scripts/sdk-package.sh php "$out" || return 1
  go_run "sh scripts/sdk-package.sh go /tmp/out" || return 1
  ls -1 "$out"
}

# ---------------------------------------------------------------- workflows, release config

step_actionlint() {
  need_docker || return 1
  docker run --rm -v "$root":/repo -w /repo "rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667"
}

step_goreleaser() {
  need_docker || return 1
  docker run --rm -v "$root":/repo -w /repo --entrypoint goreleaser "goreleaser/goreleaser:v2.19.0" check
}

# ---------------------------------------------------------------- run

step go           step_go
step vectors      step_vectors
step ui           step_ui
step build        step_build
step sdk-go       step_sdk_go
step sdk-node     step_sdk_node
step sdk-python   step_sdk_python
step sdk-java     step_sdk_java
step sdk-dotnet   step_sdk_dotnet
step sdk-php      step_sdk_php
step sdk-package  step_sdk_package
step actionlint   step_actionlint
step goreleaser   step_goreleaser

echo ""
echo "================ ci-local summary (matrix: $MATRIX) ================"
printf '%s\n' "$results" | sed '/^$/d'
echo "logs: $logdir"
if [ "$failed" -ne 0 ]; then echo "RESULT: FAIL"; exit 1; fi
echo "RESULT: PASS"
