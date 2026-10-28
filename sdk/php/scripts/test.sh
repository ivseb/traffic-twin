#!/bin/sh
# Builds the test image for one PHP version and runs a command in it (default: composer install + phpunit).
#   scripts/test.sh 8.3                 install dev dependencies and run the whole suite
#   scripts/test.sh 8.1 vectors         only the conformance vectors
#   scripts/test.sh 8.3 sh              a shell in the container
# The repository is mounted at /work. vendor/ is kept per PHP version in a Docker volume so the
# host checkout stays clean. composer.lock is not committed: each run resolves for the PHP version in use.
set -eu
ver="${1:-8.3}"; shift || true
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
img="tt-php-test:${ver}"
docker build -q --build-arg "PHP_VERSION=${ver}" -t "$img" "$here/../tests/docker" > /dev/null
run() { docker run --rm -v "$root:/work" -v "tt-php-vendor-${ver}:/work/sdk/php/vendor" -v tt-php-composer-cache:/root/.cache/composer -w /work/sdk/php "$@"; }
case "${1:-all}" in
  vectors) run "$img" php scripts/run-vectors.php ;;
  sh) if [ "$#" -eq 1 ]; then run -it "$img" sh; else run "$img" "$@"; fi ;;
  all) run "$img" sh -c 'composer update --no-progress --prefer-dist -q && vendor/bin/phpunit' ;;
  *) run "$img" "$@" ;;
esac
