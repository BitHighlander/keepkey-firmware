#!/bin/sh
# Generate device screen zoo — captures OLED framebuffer PNGs from targeted
# test flows against the emulator via the debug link.
#
# Outputs: /kkemu/screen-zoo/<chain>/*.png
#
# Requires: emulator running on kkemu:11044/11045 (or localhost via env vars)

set -e

echo "[screen-zoo] Installing dependencies..."
pip install --quiet Pillow pytest 2>/dev/null || pip3 install --quiet Pillow pytest 2>/dev/null || {
    echo "[screen-zoo] ERROR: Failed to install Pillow/pytest"
    exit 1
}

# Install python-keepkey package itself (needed for imports)
cd /kkemu/deps/python-keepkey
pip install --quiet -e . 2>/dev/null || pip3 install --quiet -e . 2>/dev/null || true
cd /kkemu

# Patch client.py to enable screenshots via env var (non-destructive sed).
# The original has SCREENSHOT = False hardcoded. We insert an env-var check.
CLIENT_PY="/kkemu/deps/python-keepkey/keepkeylib/client.py"
if [ -f "$CLIENT_PY" ] && grep -q "^SCREENSHOT = False" "$CLIENT_PY"; then
    # Replace the single line with a multi-line env-var check
    python3 -c "
import re
with open('$CLIENT_PY', 'r') as f:
    content = f.read()
patch = '''# Screenshot support: enable with KEEPKEY_SCREENSHOT=1
import os as _screenshot_os
SCREENSHOT = False
if _screenshot_os.environ.get('KEEPKEY_SCREENSHOT', '') in ('1', 'true', 'yes'):
    try:
        from PIL import Image
        SCREENSHOT = True
    except ImportError:
        pass'''
content = content.replace('SCREENSHOT = False', patch, 1)
with open('$CLIENT_PY', 'w') as f:
    f.write(content)
"
    echo "[screen-zoo] Patched client.py for screenshot support"
fi

cd /kkemu/deps/python-keepkey/tests

run_zoo() {
    local chain="$1"
    local test_file="$2"
    local out_dir="/kkemu/screen-zoo/${chain}"

    mkdir -p "${out_dir}"
    echo "=== Generating ${chain} screen zoo ==="

    if [ ! -f "${test_file}" ]; then
        echo "  -> SKIP (${test_file} not found)"
        return
    fi

    # Run from tests dir so imports work
    cd /kkemu/deps/python-keepkey/tests
    KEEPKEY_SCREENSHOT=1 \
    python -m pytest -x -v "${test_file}" 2>&1 | tail -5 || true

    # Collect screenshots
    mv scr*.png "${out_dir}/" 2>/dev/null || true
    COUNT=$(ls "${out_dir}"/*.png 2>/dev/null | wc -l | tr -d ' ')
    echo "  -> ${COUNT} screens captured for ${chain}"
}

# ── Zcash ──────────────────────────────────────────────────
run_zoo "zcash-orchard-fvk" "test_msg_zcash_orchard.py"
run_zoo "zcash-orchard-pczt" "test_msg_zcash_sign_pczt.py"
run_zoo "zcash-transparent" "test_msg_signtx_zcash.py"

# ── Solana ─────────────────────────────────────────────────
run_zoo "solana" "test_msg_solana_getaddress.py"

# ── Ethereum / EVM ─────────────────────────────────────────
run_zoo "ethereum-address" "test_msg_ethereum_getaddress.py"
run_zoo "ethereum-sign" "test_msg_ethereum_signtx.py"
run_zoo "ethereum-xfer" "test_msg_ethereum_signtx_xfer.py"
run_zoo "ethereum-erc20" "test_msg_ethereum_erc20_approve.py"
run_zoo "ethereum-message" "test_msg_ethereum_message.py"

# ── Summary ────────────────────────────────────────────────
echo ""
echo "=== Screen Zoo Summary ==="
TOTAL=0
for dir in /kkemu/screen-zoo/*/; do
    [ -d "$dir" ] || continue
    chain=$(basename "$dir")
    count=$(ls "$dir"/*.png 2>/dev/null | wc -l | tr -d ' ')
    TOTAL=$((TOTAL + count))
    printf "  %-30s %d screens\n" "$chain" "$count"
done
echo "  ------------------------------------"
printf "  %-30s %d screens\n" "TOTAL" "$TOTAL"
