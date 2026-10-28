#!/bin/sh
# Red team round 2, .NET SDK: copies sdk/dotnet into a container, adds RedTeamTests.cs to the SDK's test
# project (internals are visible to it only) and runs those tests. The repository is mounted read-only.
#   test/redteam/dotnet/run.sh            (from the repository root)
set -eu
repo=$(cd "$(dirname "$0")/../../.." && pwd)
exec docker run --rm -v "$repo":/repo:ro mcr.microsoft.com/dotnet/sdk:8.0 sh -c '
  cp -r /repo/sdk/dotnet /tmp/s && cp /repo/test/redteam/dotnet/RedTeamTests.cs /tmp/s/tests/TrafficTwin.Sdk.Tests/ &&
  cd /tmp/s && dotnet test tests/TrafficTwin.Sdk.Tests --nologo -v q --filter "FullyQualifiedName~RedTeamRound2"'
