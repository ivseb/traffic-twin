#!/bin/sh
# Runs a command in the official PHP image: scripts/docker-php.sh <version> <command...>
# The repository root is mounted read-write at /work; the working directory is sdk/php.
set -eu
ver="$1"; shift
root="$(cd "$(dirname "$0")/../../.." && pwd)"
exec docker run --rm -v "$root:/work" -w /work/sdk/php "php:${ver}-cli" "$@"
