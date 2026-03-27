#!/bin/sh

mkdir -p /kkemu/test-reports/python-keepkey
mkdir -p /kkemu/test-reports/screenshots
LOGFILE=/kkemu/test-reports/python-keepkey/screenshot-debug.log

# --- Wait for emulator to be ready on UDP ---
echo "=== Waiting for emulator (kkemu:11044) ==="
python3 -c "
import socket, time, sys
for i in range(30):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        # Send Initialize message (msg_type=0, length=0)
        s.sendto(b'##\x00\x00\x00\x00\x00\x00', ('kkemu', 11044))
        data, _ = s.recvfrom(64)
        s.close()
        print('Emulator ready after %d attempts' % (i+1))
        sys.exit(0)
    except Exception as e:
        print('  attempt %d/30: %s' % (i+1, e))
        try: s.close()
        except: pass
        time.sleep(2)
print('FATAL: emulator not ready after 60s')
sys.exit(1)
"
EMU_READY=$?
if [ "$EMU_READY" != "0" ]; then
    echo "ERROR: Emulator never became ready" | tee "$LOGFILE"
    echo "1" > /kkemu/test-reports/python-keepkey/status
    exit 1
fi

# Debug link (port 11045) is tested implicitly by Phase 1 tests via DebugLink transport.
# No explicit probe — python-keepkey's UDPTransport handles connection on demand.

cd deps/python-keepkey/tests

# Phase 1: Targeted screenshot capture (fast — key address display tests only)
echo "=== Screenshot capture (targeted tests) ==="
export KEEPKEY_SCREENSHOT=1
export SCREENSHOT_DIR=/kkemu/test-reports/screenshots
export KK_TRANSPORT_MAIN=kkemu:11044
export KK_TRANSPORT_DEBUG=kkemu:11045
pytest -v -k "test_getaddress or test_get_address or test_wipedevice or test_bip85 or test_solana_get or test_tron_get or test_ton_get" \
  --junitxml=/kkemu/test-reports/python-keepkey/junit-screenshots.xml \
  2>&1 | tee "$LOGFILE" || true
echo "Phase 1 done"

# Count screenshots
SCREENSHOT_COUNT=$(find /kkemu/test-reports/screenshots -name '*.png' 2>/dev/null | wc -l)
echo "=== Screenshots captured: $SCREENSHOT_COUNT ==="
if [ "$SCREENSHOT_COUNT" -eq 0 ]; then
    echo "WARNING: Zero screenshots captured!" | tee -a "$LOGFILE"
    echo "Checking SCREENSHOT env and debug state..." | tee -a "$LOGFILE"
    grep -i "screenshot" "$LOGFILE" || echo "  (no screenshot-related output found)" | tee -a "$LOGFILE"
else
    echo "Screenshot files:" | tee -a "$LOGFILE"
    find /kkemu/test-reports/screenshots -name '*.png' -ls | tee -a "$LOGFILE"
fi

# Phase 2: Full test suite (no screenshots — normal speed)
echo "=== Full test suite ==="
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v --junitxml=/kkemu/test-reports/python-keepkey/junit.xml
echo "$?" > /kkemu/test-reports/python-keepkey/status
