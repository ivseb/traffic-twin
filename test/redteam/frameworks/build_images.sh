#!/usr/bin/env bash
# Red team round 3, framework integrations: builds the SDK init images from
# this checkout (deploy/images/sdk-*/Dockerfile, the same artifacts the k8s
# injector copies into pods) and the per-stack test apps.
#
# Usage (from anywhere):  test/redteam/frameworks/build_images.sh [java dotnet python node php]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
stacks=("$@")
[ ${#stacks[@]} -eq 0 ] && stacks=(java dotnet python node php)

for s in "${stacks[@]}"; do
  case "$s" in
    java|dotnet|python|node)
      echo "== rt3fw-sdk-$s:local (deploy/images/sdk-$s)"
      docker build -q -f "$root/deploy/images/sdk-$s/Dockerfile" -t "rt3fw-sdk-$s:local" "$root" >/dev/null
      ;;
    php) ;; # the PHP SDK is copied into the app image (composer path repository)
    *) echo "unknown stack $s" >&2; exit 2 ;;
  esac
  echo "== rt3fw-app-$s:local ($here/$s)"
  docker build -q -f "$here/$s/Dockerfile" -t "rt3fw-app-$s:local" "$root" >/dev/null
done
echo "images built"
