#!/bin/sh
# Builds the UI like CI does and checks what ends up in the production bundle.
#
#   scripts/ui-build-check.sh
#
# 1. npm ci, svelte-check, unit tests.
# 2. The demo build, if ui/package.json defines the `build:demo` script
#    (the mock adapter is allowed there). It runs first because every build
#    writes into internal/ui/dist.
# 3. The production build (`npm run build`), which is what gets embedded in tt.
# 4. The production bundle must contain none of the strings listed in
#    scripts/ui-forbidden-strings.txt (demo logins, mock fixtures, ...), so a
#    release can never ship the demo data.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
dist="$root/internal/ui/dist"
forbidden="$root/scripts/ui-forbidden-strings.txt"

cd "$root/ui"
npm ci --no-audit --no-fund --ignore-scripts
npm run check
npm test

if node -e 'process.exit(require("./package.json").scripts?.["build:demo"] ? 0 : 1)'; then
  echo "== demo build"
  npm run build:demo
else
  echo "== no build:demo script in ui/package.json: demo build skipped"
fi

echo "== production build"
npm run build

echo "== production bundle must not contain demo or mock strings"
status=0
while IFS= read -r pattern; do
  case "$pattern" in ''|'#'*) continue ;; esac
  # -r: all files (js, css, html, json); -I: skip binary; -i: case-insensitive; -F: fixed string.
  if hits=$(grep -rIilF -e "$pattern" "$dist" 2>/dev/null) && [ -n "$hits" ]; then
    echo "FORBIDDEN string \"$pattern\" found in the production bundle:" >&2
    echo "$hits" | sed "s#^$dist/#  #" >&2
    status=1
  fi
done < "$forbidden"
if [ "$status" -ne 0 ]; then
  echo "The production UI still ships demo/mock code: demo code belongs only to the demo bundle (npm run build:demo)." >&2
  exit 1
fi
echo "ok: no demo/mock strings in the production bundle"
