#!/usr/bin/env bash
# Red team round 3, framework integrations (scope item 5): builds the SDK
# init images and one app per stack, then runs the Go orchestrator, which
# starts a real tt-core in-process and the apps in Docker (see fw_test.go).
#
#   test/redteam/frameworks/run_all.sh                # java dotnet python php node
#   test/redteam/frameworks/run_all.sh node python    # a subset
#
# Regression check: exit status 0 when every stack passes (RT3-FW-1..3 fixed),
# non-zero on any regression. RT3FW_KEEP=1 keeps the
# containers, RT3FW_DUMP=1 writes the events and logs of each stack to $TMPDIR.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
stacks=("$@")
[ ${#stacks[@]} -eq 0 ] && stacks=(java dotnet python php node)
"$here/build_images.sh" "${stacks[@]}"
list="$(IFS=,; echo "${stacks[*]}")"
cleanup() { docker ps -aq --filter name=rt3fw- | xargs -r docker rm -f >/dev/null 2>&1 || true; }
trap cleanup EXIT
cd "$root"
RT3FW_STACKS="$list" go test ./test/redteam/frameworks/ -run TestFW -count=1 -v -timeout 60m
