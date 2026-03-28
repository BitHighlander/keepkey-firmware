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

# Diagnostic: verify SCREENSHOT flag reaches Python
echo "=== Pre-flight diagnostic ==="
KEEPKEY_SCREENSHOT=1 python3 -c "
import os, sys
sys.path.insert(0, '..')
print('KEEPKEY_SCREENSHOT env:', os.environ.get('KEEPKEY_SCREENSHOT', 'NOT SET'))
from keepkeylib.client import SCREENSHOT
print('SCREENSHOT global:', SCREENSHOT)
# Check if _capture_oled has debug logging
import inspect
from keepkeylib.client import DebugLinkMixin
src = inspect.getsource(DebugLinkMixin._capture_oled)
has_debug = '[SCREENSHOT]' in src
print('_capture_oled has debug logging:', has_debug)
print('_capture_oled first 200 chars:', repr(src[:200]))
" 2>&1
echo "=== End diagnostic ==="

# Phase 1: 6 targeted screenshots — security-critical OLED content only
# 1. Wipe confirm — "erase your private keys?" (security gate)
# 2. BTC sign — output address + amount + fee (anti-tampering proof)
# 3. ETH sign — recipient + gas (different chain flow)
# 4. THORChain swap — memo with routing (most complex confirmation)
# 5. Reset device — seed words on OLED (proves words never leave device)
# 6. BIP-39 rejection — "Word not in wordlist" (invalid word error screen)
echo "=== Phase 1: Targeted screenshot capture (6 tests) ==="
KEEPKEY_SCREENSHOT=1 \
SCREENSHOT_DIR=/kkemu/test-reports/screenshots \
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v --tb=short \
  -k "(test_wipe_device and wipedevice) or (test_one_one_fee and msg_signtx and not raw and not grs) or (test_ethereum_signtx_nodata and not eip) or (test_sign_btc_eth_swap and thorchain) or (test_reset_device and resetdevice and not pin) or test_invalid_bip39_word_rejected" \
  --junitxml=/kkemu/test-reports/python-keepkey/junit-screenshots.xml \
  -s 2>&1

# Gate: fail fast if screenshots broken
echo "=== Screenshot results ==="
find /kkemu/test-reports/screenshots -name '*.png' -ls 2>/dev/null || echo "NO SCREENSHOTS"
SCREENSHOT_COUNT=$(find /kkemu/test-reports/screenshots -name '*.png' 2>/dev/null | wc -l)
echo "Total PNGs: $SCREENSHOT_COUNT"
if [ "$SCREENSHOT_COUNT" -eq 0 ]; then
    echo "FATAL: KEEPKEY_SCREENSHOT=1 but 0 PNGs captured. Screenshot pipeline is broken."
    echo "1" > /kkemu/test-reports/python-keepkey/status
    exit 1
fi

# Full suite (no screenshots)
echo "=== Full test suite ==="
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v --junitxml=/kkemu/test-reports/python-keepkey/junit.xml
echo "$?" > /kkemu/test-reports/python-keepkey/status
