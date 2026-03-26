#!/bin/sh

mkdir -p /kkemu/test-reports/python-keepkey
mkdir -p /kkemu/test-reports/screenshots
cd deps/python-keepkey/tests

# Phase 1: Screenshot capture — run key UI tests with OLED capture enabled.
# Captures device screen during address display, wipe, reset, PIN, signing.
# Includes both existing chains (BTC/ETH/Cosmos) and 7.14.0 chains (version-gated tests skip gracefully).
echo "=== Screenshot capture ==="
KEEPKEY_SCREENSHOT=1 \
SCREENSHOT_DIR=/kkemu/test-reports/screenshots \
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v -k "test_btc or test_ltc or test_show or test_wipe or test_reset_device or test_set_pin or test_ping or test_encrypt or test_decrypt or test_sign or test_ethereum_getaddress or test_cosmos_get or test_ripple_get or test_thorchain_get or test_getaddress or test_get_address or test_bip85 or test_solana_get or test_tron_get or test_ton_get or test_apply_settings" \
  --junitxml=/kkemu/test-reports/python-keepkey/junit-screenshots.xml \
  2>&1 || true

# Phase 2: Full test suite (no screenshots — normal speed)
echo "=== Full test suite ==="
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v --junitxml=/kkemu/test-reports/python-keepkey/junit.xml
echo "$?" > /kkemu/test-reports/python-keepkey/status
