#!/bin/sh
# One definition of how each SDK is tested, shared by CI and `make ci-local`.
#
#   scripts/sdk-test.sh <sdk> [phase] [arg]
#
#   sdk    node | python | java | dotnet | php | go
#   phase  setup | vectors | test | all (default). `vectors` runs only the
#          sanitizer conformance vectors (conformance/vectors), `test` the rest.
#   arg    php: PHP version (8.1, 8.3, 8.4; the tests run in a php:<v>-cli
#          image, so Docker is required). go: module (. gin chi otelctx).
#
# The toolchain of the SDK must be on PATH (CI: setup-* actions; locally:
# scripts/ci-local.sh runs this very script inside the official image).
set -eu

sdk=${1:?usage: sdk-test.sh <node|python|java|dotnet|php|go> [setup|vectors|test|all] [arg]}
phase=${2:-all}
arg=${3:-}
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

want() { [ "$phase" = all ] || [ "$phase" = "$1" ]; }

case "$sdk" in
  node)
    cd sdk/node
    if want setup; then npm ci --no-audit --no-fund --ignore-scripts; fi
    if want vectors; then npm run vectors; fi
    # `npm test` builds (ESM + CJS) before running unit and integration tests.
    if want test; then npm run typecheck; npm test; fi
    ;;

  python)
    cd sdk/python
    export PYTHONPATH=src:.
    if want setup; then
      # Optional test dependencies, one by one: some pins need a newer Python
      # than the SDK supports (e.g. Django 6), and the tests that need a
      # missing package skip themselves.
      for pkg in $(grep -Eo '^[A-Za-z0-9_.-]+==[0-9][^ #]*' requirements-dev.txt); do
        python -m pip install --quiet --disable-pip-version-check --no-input "$pkg" \
          || echo "optional test dependency $pkg is not installable on this Python: its tests will be skipped"
      done
    fi
    if want vectors; then python -m traffic_twin.conformance; fi
    if want test; then python -m unittest discover -s tests -t .; fi
    ;;

  java)
    cd sdk/java
    if want vectors; then
      ./mvnw -B -ntp -pl sdk test -Dtest=ConformanceTest -Dsurefire.failIfNoSpecifiedTests=false
    fi
    # verify = compile for Java 17, all unit and integration tests, the short benchmark.
    if want test; then
      ./mvnw -B -ntp verify
      # The failsafe integration tests (real -javaagent JVMs) must have run, not been skipped silently.
      for it in AgentIT OtelAgentIT; do
        [ -f "sdk-agent/target/failsafe-reports/io.github.ivseb.traffictwin.agent.$it.txt" ] \
          || { echo "integration test $it did not run (no failsafe report)" >&2; exit 1; }
      done
    fi
    ;;

  dotnet)
    cd sdk/dotnet
    # ZeroCodeTests start real `dotnet` processes (DOTNET_STARTUP_HOOKS): the CLI must be on PATH.
    command -v dotnet >/dev/null 2>&1 || { echo "dotnet is not on PATH (CI: actions/setup-dotnet)" >&2; exit 1; }
    export TT_CONFORMANCE_DIR="$root/conformance"
    export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
    if want setup; then dotnet restore; fi
    if want vectors; then dotnet test --no-restore --configuration Release --filter "FullyQualifiedName~VectorTests"; fi
    if want test; then dotnet test --no-restore --configuration Release; fi
    ;;

  php)
    ver=${arg:-8.3}
    if want vectors; then sdk/php/scripts/test.sh "$ver" vectors; fi
    if want test; then sdk/php/scripts/test.sh "$ver"; fi
    ;;

  go)
    mod=${arg:-.}
    case "$mod" in
      .)
        # The package is part of the root module.
        if want vectors; then go test -race -count=1 -run 'TestSDKPathMatchesConformanceVectors' ./sdk/go; fi
        if want test; then go vet ./sdk/go/... && go test -race -count=1 ./sdk/go/...; fi
        ;;
      gin|chi|otelctx)
        # Nested modules: `go test ./...` at the repository root does not run them.
        # Their conformance goes through the root package (they only wrap it).
        cd "sdk/go/$mod"
        if want test; then
          go vet ./...
          go test -race -count=1 ./...
          CGO_ENABLED=0 go build ./...
        fi
        ;;
      *) echo "unknown Go module: $mod" >&2; exit 2 ;;
    esac
    ;;

  *) echo "unknown SDK: $sdk" >&2; exit 2 ;;
esac
