#!/bin/sh
#
# The container's exit status IS the gate: CI runs this through
#   docker compose up --exit-code-from firmware-unit
# and uses that code directly (see .github/workflows/ci.yml, FW_RC).
#
# This script used to end with `cp`, so the exit status was the COPY's, not the
# test run's. A failing `make xunit` wrote its real code into the status file
# below -- which nothing reads -- and the container still exited 0, so the suite
# could not fail this job. Capture the status, always extract the reports (the
# evidence matters most when tests fail), then exit with the status.

mkdir -p /kkemu/test-reports/firmware-unit || exit 1
make xunit
RC=$?

echo "$RC" > /kkemu/test-reports/firmware-unit/status
STATUS_RC=$?
cp -r unittests/*.xml /kkemu/test-reports/firmware-unit
COPY_RC=$?
if [ "$RC" -ne 0 ]; then exit "$RC"; fi
if [ "$STATUS_RC" -ne 0 ]; then exit "$STATUS_RC"; fi
exit "$COPY_RC"
