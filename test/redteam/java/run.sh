#!/bin/sh
# Red team round 2, Java SDK. Non-zero exit = finding present. Repository mounted read-only.
#   test/redteam/java/run.sh           (from anywhere)
repo=$(cd "$(dirname "$0")/../../.." && pwd)
rc=0
echo "== RtFleetResponseCap (exit 3 = OutOfMemoryError)"
docker run --rm -v "$repo":/repo:ro eclipse-temurin:17 sh -c 'javac -d /tmp/o -sourcepath /repo/sdk/java/sdk/src/main/java /repo/test/redteam/java/RtFleetResponseCap.java && java -Xmx128m -XX:+ExitOnOutOfMemoryError -cp /tmp/o RtFleetResponseCap' || rc=1
echo "== RtStateDirPerms"
docker run --rm -v "$repo":/repo:ro eclipse-temurin:17 sh -c 'javac -d /tmp/o -sourcepath /repo/sdk/java/sdk/src/main/java /repo/test/redteam/java/RtStateDirPerms.java && java -cp /tmp/o RtStateDirPerms' || rc=1
exit $rc
