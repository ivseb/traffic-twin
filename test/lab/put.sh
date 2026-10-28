#!/usr/bin/env bash
# Copy a local file to a lab host: test/lab/put.sh <demo|keyguard|core> <local> <remote> [mode]
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
put "$@"
