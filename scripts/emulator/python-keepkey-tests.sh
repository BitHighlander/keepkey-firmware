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

# Also verify debug link (kkemu:11045) — give it more time since it starts after main
echo "=== Verifying debug link (kkemu:11045) ==="
python3 -c "
import socket, time, sys
for i in range(20):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        # Send DebugLinkGetState (msg_type=101=0x0065, length=0)
        s.sendto(b'##\x00\x65\x00\x00\x00\x00', ('kkemu', 11045))
        data, _ = s.recvfrom(4096)
        s.close()
        print('Debug link ready (%d bytes response)' % len(data))
        sys.exit(0)
    except Exception as e:
        print('  attempt %d/20: %s' % (i+1, e))
        try: s.close()
        except: pass
        time.sleep(3)
print('WARNING: debug link not ready after 60s')
sys.exit(1)
"
DEBUG_READY=$?
if [ "$DEBUG_READY" != "0" ]; then
    echo "WARNING: Debug link not ready — screenshots may fail" | tee "$LOGFILE"
fi

cd deps/python-keepkey/tests

# Phase 1: Targeted screenshot capture (fast — key address display tests only)
echo "=== Screenshot capture (targeted tests) ==="
KEEPKEY_SCREENSHOT=1 \
SCREENSHOT_DIR=/kkemu/test-reports/screenshots \
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
{ pytest -v -k "test_getaddress or test_get_address or test_wipedevice or test_bip85 or test_solana_get or test_tron_get or test_ton_get" \
  --junitxml=/kkemu/test-reports/python-keepkey/junit-screenshots.xml \
  2>&1; echo $? > /tmp/phase1_exit; } | tee "$LOGFILE"
PHASE1_EXIT=$(cat /tmp/phase1_exit 2>/dev/null || echo "1")
echo "Phase 1 exit code: $PHASE1_EXIT"

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
