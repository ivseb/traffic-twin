#!/usr/bin/env bash
# Red team round 3: Express + Node SDK (zero-code --import). See ../fw_test.go.
exec "$(cd "$(dirname "$0")/.." && pwd)/run_all.sh" node
