#!/bin/sh

mkdir -p /kkemu/test-reports/firmware-unit
# Publish the exact variant binary for python-keepkey's owned power-cycle
# tests. Copy through a temporary name so a retry can never observe a partial
# executable from a concurrently starting unit-test container.
if [ -d /kkemu-emulator-bin ]; then
  cp /kkemu/bin/kkemu /kkemu-emulator-bin/kkemu.tmp
  chmod 0755 /kkemu-emulator-bin/kkemu.tmp
  mv /kkemu-emulator-bin/kkemu.tmp /kkemu-emulator-bin/kkemu
fi
make xunit
RC=$?
echo "$RC" > /kkemu/test-reports/firmware-unit/status
cp -r unittests/*.xml /kkemu/test-reports/firmware-unit
exit "$RC"
