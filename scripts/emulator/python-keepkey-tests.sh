#!/bin/sh

mkdir -p /kkemu/test-reports/python-keepkey
mkdir -p /kkemu/test-reports/screenshots
cd deps/python-keepkey/tests

# Debug: verify screenshot env and module state
echo "=== Screenshot env check ==="
KEEPKEY_SCREENSHOT=1 SCREENSHOT_DIR=/kkemu/test-reports/screenshots \
python3 -c "
import os
print('KEEPKEY_SCREENSHOT:', os.environ.get('KEEPKEY_SCREENSHOT'))
print('SCREENSHOT_DIR:', os.environ.get('SCREENSHOT_DIR'))
import sys; sys.path.insert(0, '..')
from keepkeylib.client import SCREENSHOT
print('client.SCREENSHOT:', SCREENSHOT)
from keepkeylib.client import _write_png
print('_write_png available:', callable(_write_png))
# Check if conftest.py exists
print('conftest.py exists:', os.path.exists('conftest.py'))
if os.path.exists('conftest.py'):
    with open('conftest.py') as f: print('conftest.py first line:', f.readline().strip())
"

# Phase 1: Screenshot capture
echo "=== Screenshot capture ==="
KEEPKEY_SCREENSHOT=1 \
SCREENSHOT_DIR=/kkemu/test-reports/screenshots \
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v -k "test_btc or test_ltc or test_show or test_wipe or test_reset_device or test_set_pin or test_ping or test_encrypt or test_decrypt or test_sign or test_ethereum_getaddress or test_cosmos_get or test_ripple_get or test_thorchain_get or test_getaddress or test_get_address or test_bip85 or test_solana_get or test_tron_get or test_ton_get or test_apply_settings" \
  --junitxml=/kkemu/test-reports/python-keepkey/junit-screenshots.xml \
  2>&1 || true

# Debug: check what screenshots were captured
echo "=== Screenshot output check ==="
find /kkemu/test-reports/screenshots -type f 2>/dev/null | head -20 || echo "No screenshot files found"
ls -la /kkemu/test-reports/screenshots/ 2>/dev/null || echo "screenshots dir empty or missing"

# Phase 2: Full test suite (no screenshots — normal speed)
echo "=== Full test suite ==="
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v --junitxml=/kkemu/test-reports/python-keepkey/junit.xml
echo "$?" > /kkemu/test-reports/python-keepkey/status
