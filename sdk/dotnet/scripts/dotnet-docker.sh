#!/bin/sh
# Runs `dotnet <args>` inside the official SDK image (the dev machine has no .NET).
# The repository root is mounted at /repo; NuGet packages are cached in a Docker volume.
#   scripts/dotnet-docker.sh test
#   TT_DOTNET_IMAGE=mcr.microsoft.com/dotnet/sdk:10.0 scripts/dotnet-docker.sh test
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
root=$(cd "$here/../.." && pwd)
image=${TT_DOTNET_IMAGE:-mcr.microsoft.com/dotnet/sdk:8.0}
exec docker run --rm \
  -v "$root":/repo \
  -v tt-dotnet-nuget:/root/.nuget/packages \
  -w /repo/sdk/dotnet \
  -e DOTNET_CLI_TELEMETRY_OPTOUT=1 \
  -e DOTNET_NOLOGO=1 \
  -e DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
  -e TT_CONFORMANCE_DIR=/repo/conformance \
  ${TT_DOCKER_ARGS:-} \
  "$image" dotnet "$@"
