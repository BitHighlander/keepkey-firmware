#!/bin/sh

mkdir -p /kkemu/test-reports/python-keepkey
mkdir -p /kkemu/test-reports/screenshots
cd deps/python-keepkey/tests

# === DIAGNOSTIC: verify the container has the right code ===
echo "=== Container verification ==="
python3 -c "
import os, sys
sys.path.insert(0, '..')

# 1. Env vars
print('KEEPKEY_SCREENSHOT:', os.environ.get('KEEPKEY_SCREENSHOT', 'NOT SET'))

# 2. conftest.py presence and content
if os.path.exists('conftest.py'):
    with open('conftest.py') as f:
        content = f.read()
    print('conftest.py: exists, %d bytes' % len(content))
    print('  has KEEPKEY_SCREENSHOT:', 'KEEPKEY_SCREENSHOT' in content)
    print('  has screenshot_dir:', 'screenshot_dir' in content)
else:
    print('conftest.py: MISSING')

# 3. client.py screenshot code
from keepkeylib import client
print('client.SCREENSHOT:', client.SCREENSHOT)
print('client._write_png:', hasattr(client, '_write_png'))

# 4. DebugLink read_layout
from keepkeylib import debuglink
print('debuglink.read_layout:', hasattr(debuglink.DebugLink, 'read_layout'))
" KEEPKEY_SCREENSHOT=1

# === DIAGNOSTIC: smoke test read_layout against running emulator ===
echo "=== DebugLink smoke test ==="
KEEPKEY_SCREENSHOT=1 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
python3 -c "
import os, sys
sys.path.insert(0, '..')
from keepkeylib.transport_udp import UDPTransport
from keepkeylib import messages_pb2 as proto
from keepkeylib.debuglink import DebugLink

debug_host = os.environ.get('KK_TRANSPORT_DEBUG', '127.0.0.1:11045')
try:
    t = UDPTransport(debug_host)
    dl = DebugLink(t)
    state = dl._call(proto.DebugLinkGetState())
    layout = state.layout
    print('read_layout: got %d bytes' % len(layout) if layout else 'read_layout: EMPTY/None')
    if layout and len(layout) >= 2048:
        print('layout OK: full 2048-byte OLED buffer')
    elif layout and len(layout) > 0:
        print('layout PARTIAL: %d bytes (expected 2048)' % len(layout))
    else:
        print('layout FAILED: empty response — max_size fix may not be in emulator build')
    t.close()
except Exception as e:
    print('DebugLink error: %s: %s' % (type(e).__name__, e))
" 2>&1

# === Phase 1: Screenshot capture — NOT masked, failures visible ===
echo "=== Phase 1: Screenshot capture ==="
SCREENSHOT_EXIT=0
KEEPKEY_SCREENSHOT=1 \
SCREENSHOT_DIR=/kkemu/test-reports/screenshots \
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v -k "test_show or test_wipe or test_ping or test_apply_settings or test_set_pin or test_btc or test_ethereum_getaddress" \
  --junitxml=/kkemu/test-reports/python-keepkey/junit-screenshots.xml \
  -s 2>&1; SCREENSHOT_EXIT=$?

echo "Phase 1 exit code: $SCREENSHOT_EXIT"

# === DIAGNOSTIC: verify PNGs were written ===
echo "=== Screenshot file check ==="
PNG_COUNT=$(find /kkemu/test-reports/screenshots -type f -name '*.png' 2>/dev/null | wc -l)
echo "PNG files found: $PNG_COUNT"
if [ "$PNG_COUNT" -gt 0 ]; then
    find /kkemu/test-reports/screenshots -type f -name '*.png' | head -10
else
    echo "NO PNGs written. Checking directory structure:"
    find /kkemu/test-reports/screenshots -type d | head -10
    echo "Checking for any files at all:"
    find /kkemu/test-reports/screenshots -type f | head -10
fi

# === Phase 2: Full test suite (no screenshots) ===
echo "=== Phase 2: Full test suite ==="
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v --junitxml=/kkemu/test-reports/python-keepkey/junit.xml
echo "$?" > /kkemu/test-reports/python-keepkey/status
