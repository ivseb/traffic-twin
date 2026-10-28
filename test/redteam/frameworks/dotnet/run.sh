#!/usr/bin/env bash
# Red team round 3: ASP.NET Core + .NET startup hook (DOTNET_STARTUP_HOOKS). See ../fw_test.go.
exec "$(cd "$(dirname "$0")/.." && pwd)/run_all.sh" dotnet
