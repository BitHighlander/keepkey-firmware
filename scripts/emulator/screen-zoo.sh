#!/bin/sh
# Generate device screen zoo — captures OLED framebuffer PNGs from targeted
# test flows against the emulator via the debug link.
#
# Outputs: /kkemu/screen-zoo/<chain>/*.png

set -e

# Patch client.py to enable screenshots when KEEPKEY_SCREENSHOT=1.
# The original has SCREENSHOT = False hardcoded. We replace it in-place.
CLIENT_PY="/kkemu/deps/python-keepkey/keepkeylib/client.py"
if grep -q "^SCREENSHOT = False" "$CLIENT_PY" 2>/dev/null; then
    sed -i 's/^SCREENSHOT = False/from PIL import Image; SCREENSHOT = True/' "$CLIENT_PY"
    echo "[screen-zoo] Patched client.py: SCREENSHOT = True"
else
    echo "[screen-zoo] client.py already patched or not found"
fi

cd /kkemu/deps/python-keepkey/tests

run_zoo() {
    chain="$1"
    test_file="$2"
    out_dir="/kkemu/screen-zoo/${chain}"

    mkdir -p "${out_dir}"
    echo "=== ${chain} ==="

    if [ ! -f "${test_file}" ]; then
        echo "  SKIP (not found)"
        return
    fi

    # pytest runs from tests/ dir, imports keepkeylib via sys.path=['../']
    python3 -m pytest -x -v "${test_file}" 2>&1 | tail -3 || true

    # Collect screenshots (written to cwd by call_raw)
    mv scr*.png "${out_dir}/" 2>/dev/null || true
    COUNT=$(ls "${out_dir}"/*.png 2>/dev/null | wc -l | tr -d ' ')
    echo "  -> ${COUNT} screens"
}

# ── Zcash ──────────────────────────────────────────
run_zoo "zcash-orchard-fvk"  "test_msg_zcash_orchard.py"
run_zoo "zcash-orchard-pczt" "test_msg_zcash_sign_pczt.py"
run_zoo "zcash-transparent"  "test_msg_signtx_zcash.py"

# ── Solana ─────────────────────────────────────────
run_zoo "solana" "test_msg_solana_getaddress.py"

# ── Ethereum / EVM ─────────────────────────────────
run_zoo "ethereum-address" "test_msg_ethereum_getaddress.py"
run_zoo "ethereum-sign"    "test_msg_ethereum_signtx.py"
run_zoo "ethereum-xfer"    "test_msg_ethereum_signtx_xfer.py"
run_zoo "ethereum-erc20"   "test_msg_ethereum_erc20_approve.py"
run_zoo "ethereum-message" "test_msg_ethereum_message.py"

# ── Summary ────────────────────────────────────────
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
