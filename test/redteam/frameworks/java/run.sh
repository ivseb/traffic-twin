#!/usr/bin/env bash
# Red team round 3: Spring Boot + Java agent (-javaagent via JAVA_TOOL_OPTIONS). See ../fw_test.go.
exec "$(cd "$(dirname "$0")/.." && pwd)/run_all.sh" java
