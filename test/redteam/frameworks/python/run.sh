#!/usr/bin/env bash
# Red team round 3: FastAPI + Python SDK (traffic_twin.install). See ../fw_test.go.
exec "$(cd "$(dirname "$0")/.." && pwd)/run_all.sh" python
