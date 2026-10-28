#!/bin/sh
# Prints the version of one SDK and checks that every place that carries it agrees
# (package manifest, modules, the version constant compiled into the SDK). With a
# second argument it also fails when that version is not the expected one. Used by
# the publish workflow (.github/workflows/publish-sdks.yml) before anything is
# built or published.
#
#   scripts/sdk-version.sh <node|python|java|dotnet|php|go> [expected-version]
#
# Needs only POSIX sh, sed, grep and awk.
set -eu

sdk=${1:?usage: sdk-version.sh <node|python|java|dotnet|php|go> [expected-version]}
expected=${2:-}
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

fail() { echo "sdk-version ($sdk): $*" >&2; exit 1; }

# first_match FILE SED-EXPRESSION: first capture of the expression, or fail.
first_match() {
  v=$(sed -n "$2" "$1" | head -n 1)
  [ -n "$v" ] || fail "no version found in $1"
  printf '%s' "$v"
}

# same_as MANIFEST-VERSION WHERE VALUE: the two must be equal.
same_as() {
  [ "$1" = "$3" ] || fail "$2 says '$3' but the manifest says '$1'"
}

case "$sdk" in
  node)
    ver=$(first_match sdk/node/package.json 's/^  "version": "\([^"]*\)".*/\1/p')
    same_as "$ver" sdk/node/src/version.ts "$(first_match sdk/node/src/version.ts "s/^export const SDK_VERSION = '\([^']*\)'.*/\1/p")"
    ;;

  python)
    ver=$(first_match sdk/python/pyproject.toml 's/^version = "\([^"]*\)".*/\1/p')
    same_as "$ver" sdk/python/src/traffic_twin/_version.py "$(first_match sdk/python/src/traffic_twin/_version.py 's/^SDK_VERSION = "\([^"]*\)".*/\1/p')"
    ;;

  java)
    # The parent pom carries the version; every module must name that very parent version.
    ver=$(first_match sdk/java/pom.xml 's/^  <version>\([^<]*\)<\/version>.*/\1/p')
    for m in sdk sdk-servlet-javax sdk-otel-extension sdk-agent; do
      pv=$(awk '/<parent>/{p=1} p&&/<version>/{gsub(/.*<version>|<\/version>.*/,""); print; exit}' "sdk/java/$m/pom.xml")
      [ -n "$pv" ] || fail "no parent version in sdk/java/$m/pom.xml"
      same_as "$ver" "sdk/java/$m/pom.xml (parent)" "$pv"
    done
    same_as "$ver" sdk/java/sdk/src/main/java/io/github/ivseb/traffictwin/Version.java \
      "$(first_match sdk/java/sdk/src/main/java/io/github/ivseb/traffictwin/Version.java 's/.*SDK_VERSION = "\([^"]*\)".*/\1/p')"
    ;;

  dotnet)
    ver=$(first_match sdk/dotnet/Directory.Build.props 's/^ *<Version>\([^<]*\)<\/Version>.*/\1/p')
    if grep -l '<Version>' sdk/dotnet/src/*/*.csproj >/dev/null 2>&1; then
      fail "a .csproj overrides <Version>: the version must live in sdk/dotnet/Directory.Build.props only"
    fi
    same_as "$ver" sdk/dotnet/src/TrafficTwin.Sdk/Version.cs "$(first_match sdk/dotnet/src/TrafficTwin.Sdk/Version.cs 's/.*Version = "\([^"]*\)".*/\1/p')"
    ;;

  php)
    # The version of a Composer package is the git tag: composer.json must NOT carry one.
    if grep -q '^ *"version" *:' sdk/php/composer.json; then
      fail 'composer.json has a "version" field: remove it (Packagist takes the version from the tag)'
    fi
    ver=$(first_match sdk/php/src/Version.php "s/.*const SDK = '\([^']*\)'.*/\1/p")
    ;;

  go)
    ver=$(first_match sdk/go/doc.go 's/^const Version = "\([^"]*\)".*/\1/p')
    ;;

  *) echo "unknown SDK: $sdk" >&2; exit 2 ;;
esac

if [ -n "$expected" ] && [ "$ver" != "$expected" ]; then
  fail "version is $ver, expected $expected"
fi
printf '%s\n' "$ver"
