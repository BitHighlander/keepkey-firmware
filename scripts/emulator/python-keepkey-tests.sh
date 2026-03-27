#!/bin/sh

mkdir -p /kkemu/test-reports/python-keepkey
mkdir -p /kkemu/test-reports/screenshots
cd deps/python-keepkey/tests

# Phase 1: Screenshot capture (address display + key confirmation screens)
echo "=== Phase 1: Screenshot capture ==="
KEEPKEY_SCREENSHOT=1 \
SCREENSHOT_DIR=/kkemu/test-reports/screenshots \
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v -k "test_getaddress or test_get_address or test_wipedevice or test_bip85 or test_solana_get or test_tron_get or test_ton_get or test_character_fail or test_apply_settings or test_ping or test_set_pin" \
  --junitxml=/kkemu/test-reports/python-keepkey/junit-screenshots.xml \
  --timeout=120 2>&1 || true

echo "Screenshot PNGs: $(find /kkemu/test-reports/screenshots -type f -name '*.png' 2>/dev/null | wc -l)"

# Phase 2: Full test suite (no screenshots — normal speed)
echo "=== Phase 2: Full test suite ==="
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v --junitxml=/kkemu/test-reports/python-keepkey/junit.xml
echo "$?" > /kkemu/test-reports/python-keepkey/status
