#!/bin/sh
# Decides which CI jobs a change needs. Prints "name=true|false" lines (the
# format of $GITHUB_OUTPUT), one per area.
#
#   scripts/ci-changes.sh <base> <head>     compare two revisions
#   scripts/ci-changes.sh                   everything is true (scheduled run, manual run, unknown base)
#   scripts/ci-changes.sh --files < list    read the changed paths from stdin (tests)
#
# An unknown or all-zero base (first push of a branch, force push) selects
# everything: running too much is safe, running too little is not.
set -eu

areas="go ui build sdk_go sdk_node sdk_python sdk_java sdk_dotnet sdk_php release workflows"

emit_all() {
  for a in $areas; do echo "$a=$1"; done
}

files=
case "${1:-}" in
  --files) files=$(cat) ;;
  "") emit_all true; exit 0 ;;
  *)
    base=$1
    head=${2:-HEAD}
    case "$base" in *[!0]*) ;; *) emit_all true; exit 0 ;; esac
    if ! git cat-file -e "$base^{commit}" 2>/dev/null; then emit_all true; exit 0; fi
    files=$(git diff --name-only "$base" "$head" --) || { emit_all true; exit 0; }
    ;;
esac

has() { printf '%s\n' "$files" | grep -Eq "$1"; }

go=false ui=false build=false sdk_go=false sdk_node=false sdk_python=false
sdk_java=false sdk_dotnet=false sdk_php=false release=false workflows=false

# The CI definition itself and its helper scripts: re-test everything.
if has '^(\.github/workflows/ci\.yml|scripts/(ci-changes|ci-local|sdk-test)\.sh|Makefile)$'; then
  go=true ui=true sdk_go=true sdk_node=true sdk_python=true sdk_java=true sdk_dotnet=true sdk_php=true
fi
# The conformance vectors are the contract of the sanitizer in every language.
if has '^conformance/'; then
  go=true sdk_go=true sdk_node=true sdk_python=true sdk_java=true sdk_dotnet=true sdk_php=true
fi
# The Go SDK lives in the root module and reuses internal/sourceclient.
if has '^(cmd|internal|test|api|schemas)/|^go\.(mod|sum)$'; then go=true sdk_go=true; fi
if has '^sdk/go/'; then sdk_go=true; fi
if has '^(ui/|internal/ui/|scripts/(ui-build-check\.sh|ui-forbidden-strings\.txt))'; then ui=true; fi
if has '^sdk/node/'; then sdk_node=true; fi
if has '^sdk/python/'; then sdk_python=true; fi
if has '^sdk/java/'; then sdk_java=true; fi
if has '^sdk/dotnet/'; then sdk_dotnet=true; fi
if has '^sdk/php/'; then sdk_php=true; fi
if has '^(Dockerfile.*|\.goreleaser\.yaml|\.dockerignore|\.github/workflows/release\.yml|scripts/sdk-package\.sh)$'; then release=true; fi
if has '^\.github/'; then workflows=true; fi
if [ "$go" = true ] || [ "$ui" = true ]; then build=true; fi

for a in $areas; do eval "echo $a=\$$a"; done
