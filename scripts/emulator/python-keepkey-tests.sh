#!/bin/sh
set -e

mkdir -p /kkemu/test-reports/python-keepkey
mkdir -p /kkemu/test-reports/screenshots

# Wait for emulator
echo "=== Waiting for emulator ==="
for i in $(seq 1 20); do
  if echo -n "PINGPING" | nc -u -w1 kkemu 11044 2>/dev/null | grep -q PONG; then
    echo "Emulator ready (attempt $i)"
    break
  fi
  echo "  attempt $i/20..."
  sleep 2
done

cd deps/python-keepkey/tests

# Smoke test: ONE test with screenshots to prove the pipeline works
echo "=== Screenshot smoke test (test_wipe_device) ==="
KEEPKEY_SCREENSHOT=1 \
SCREENSHOT_DIR=/kkemu/test-reports/screenshots \
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v -x -k "test_wipe_device" \
  --junitxml=/kkemu/test-reports/python-keepkey/junit-screenshots.xml \
  2>&1

# Report what we got
echo "=== Screenshot results ==="
find /kkemu/test-reports/screenshots -name '*.png' -ls 2>/dev/null || echo "NO SCREENSHOTS"
SCREENSHOT_COUNT=$(find /kkemu/test-reports/screenshots -name '*.png' 2>/dev/null | wc -l)
echo "Total PNGs: $SCREENSHOT_COUNT"

# Full suite (no screenshots)
echo "=== Full test suite ==="
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v --junitxml=/kkemu/test-reports/python-keepkey/junit.xml
echo "$?" > /kkemu/test-reports/python-keepkey/status
