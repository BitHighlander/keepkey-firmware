#!/bin/sh

mkdir -p /kkemu/test-reports/firmware-unit
# Propagate make's exit code: the report copy must still run on failure, but
# the container has to exit non-zero or --exit-code-from reports success and
# the caller's gate never fires.
make xunit; RC=$?
echo "$RC" > /kkemu/test-reports/firmware-unit/status
cp -r unittests/*.xml /kkemu/test-reports/firmware-unit
exit $RC
