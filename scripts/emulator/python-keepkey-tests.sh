#!/bin/sh

mkdir -p /kkemu/test-reports/python-keepkey
mkdir -p /kkemu/test-reports/screenshots
cd deps/python-keepkey/tests

# Phase 1: screenshot capture (display tests only, broad filter, tests self-skip via requires_message)
KEEPKEY_SCREENSHOT=1 \
SCREENSHOT_DIR=/kkemu/test-reports/screenshots \
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v -k "test_show or test_show_address or test_wipe_device or test_bip85 or test_apply_settings or test_ping" \
  --junitxml=/kkemu/test-reports/python-keepkey/junit-screenshots.xml \
  2>&1 || true

echo "Screenshot PNGs: $(find /kkemu/test-reports/screenshots -type f -name '*.png' 2>/dev/null | wc -l)"

# Phase 2: full test suite (no screenshots, normal speed)
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v --junitxml=/kkemu/test-reports/python-keepkey/junit.xml
echo "$?" > /kkemu/test-reports/python-keepkey/status
