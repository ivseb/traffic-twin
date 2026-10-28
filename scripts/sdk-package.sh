#!/bin/sh
# Packaging of one SDK: builds the distributable package exactly like a release
# would, into <outdir>, and publishes NOTHING. Publishing to npm, PyPI, Maven
# Central, NuGet and the Packagist mirror is done by
# .github/workflows/publish-sdks.yml (which calls this script first); the Go
# proxy only needs tags. See RELEASING.md.
#
#   scripts/sdk-package.sh <node|python|java|dotnet|php|go> [outdir]
#
# The toolchain of the SDK must be on PATH (see scripts/sdk-test.sh).
set -eu

sdk=${1:?usage: sdk-package.sh <node|python|java|dotnet|php|go> [outdir]}
root=$(cd "$(dirname "$0")/.." && pwd)
out=${2:-$root/dist/sdk}
mkdir -p "$out"
out=$(cd "$out" && pwd)
cd "$root"

case "$sdk" in
  node)
    cd sdk/node
    npm ci --no-audit --no-fund --ignore-scripts
    npm run build
    npm pack --pack-destination "$out"
    ;;

  python)
    cd sdk/python
    python -m pip install --quiet --disable-pip-version-check --no-input build
    python -m build --outdir "$out" .
    ;;

  java)
    cd sdk/java
    # The release profile adds the sources and javadoc jars Maven Central requires
    # (signing is skipped here: it needs the release key).
    ./mvnw -B -ntp -P release -Dgpg.skip=true package -DskipTests
    find . -mindepth 3 -maxdepth 3 -path './*/target/*.jar' ! -name 'original-*' -exec cp {} "$out"/ \;
    ;;

  dotnet)
    cd sdk/dotnet
    export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
    dotnet pack src/TrafficTwin.Sdk --configuration Release --output "$out"
    dotnet pack src/TrafficTwin.Sdk.AspNetCore --configuration Release --output "$out"
    ;;

  php)
    # Packagist reads composer.json from the repository; there is no archive to
    # build, so the dry-run is the strict validation of the manifest.
    cd sdk/php
    composer validate --strict
    ;;

  go)
    # Go modules are published by pushing tags; nothing to build. Check that the
    # nested modules still build against the root module and print the plan.
    for m in gin chi otelctx; do
      (cd "sdk/go/$m" && go list -m >/dev/null && CGO_ENABLED=0 go build ./...)
    done
    cat <<'EOF'
Go SDK, tags to create (see RELEASING.md), for a release vX.Y.Z:

  1. root module (also holds sdk/go):      vX.Y.Z
  2. in each nested module (gin, chi, otelctx) on a release commit:
       go mod edit -dropreplace=github.com/ivseb/traffic-twin
       go mod edit -require=github.com/ivseb/traffic-twin@vX.Y.Z
       go mod tidy
     then the tags (the directory prefix is part of the tag):
       sdk/go/gin/vX.Y.Z   sdk/go/chi/vX.Y.Z   sdk/go/otelctx/vX.Y.Z
EOF
    ;;

  *) echo "unknown SDK: $sdk" >&2; exit 2 ;;
esac

echo "package dry-run of $sdk done (nothing published); output in $out"
