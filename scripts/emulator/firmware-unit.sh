#!/bin/sh

mkdir -p /kkemu/test-reports/firmware-unit || exit 1
# Publish the exact variant binary for python-keepkey's owned power-cycle
# tests. Copy through a temporary name so a retry can never observe a partial
# executable from a concurrently starting unit-test container.
if [ -d /kkemu-emulator-bin ]; then
  cp /kkemu/bin/kkemu /kkemu-emulator-bin/kkemu.tmp || exit 1
  chmod 0755 /kkemu-emulator-bin/kkemu.tmp || exit 1
  mv /kkemu-emulator-bin/kkemu.tmp /kkemu-emulator-bin/kkemu || exit 1
fi
make xunit
RC=$?
echo "$RC" > /kkemu/test-reports/firmware-unit/status
STATUS_RC=$?
cp -r unittests/*.xml /kkemu/test-reports/firmware-unit
COPY_RC=$?
if [ "$RC" -ne 0 ]; then exit "$RC"; fi
if [ "$STATUS_RC" -ne 0 ]; then exit "$STATUS_RC"; fi
exit "$COPY_RC"
