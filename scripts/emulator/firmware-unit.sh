#!/bin/sh

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
