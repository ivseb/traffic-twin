#!/usr/bin/env bash
# Red team round 3: Symfony 7 + PHP SDK (SymfonySubscriber + tt-shipper). See ../fw_test.go.
exec "$(cd "$(dirname "$0")/.." && pwd)/run_all.sh" php
