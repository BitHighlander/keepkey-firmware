#!/bin/sh
# Generate device screen zoo — captures OLED framebuffer PNGs from targeted
# test flows against the emulator via the debug link.
#
# Outputs: /kkemu/screen-zoo/<chain>/*.png
#
# Requires: PIL/Pillow (installed via pip), emulator running on kkemu:11044/11045

set -e

pip install --quiet Pillow 2>/dev/null || pip3 install --quiet Pillow 2>/dev/null

cd deps/python-keepkey/tests

# Each test class generates its own set of sequential screenshots.
# We run them in separate directories to keep the zoos organized.

run_zoo() {
    local chain="$1"
    local test_file="$2"
    local out_dir="/kkemu/screen-zoo/${chain}"

    mkdir -p "${out_dir}"
    echo "=== Generating ${chain} screen zoo ==="

    cd /kkemu/deps/python-keepkey/tests
    KEEPKEY_SCREENSHOT=1 \
    KK_TRANSPORT_MAIN=kkemu:11044 \
    KK_TRANSPORT_DEBUG=kkemu:11045 \
    python -m pytest -x -v "${test_file}" 2>&1 || true

    # Collect any generated screenshots
    mv scr*.png "${out_dir}/" 2>/dev/null || true
    COUNT=$(ls "${out_dir}"/*.png 2>/dev/null | wc -l)
    echo "  → ${COUNT} screens captured for ${chain}"
}

# ── Zcash Orchard ──────────────────────────────────────────
run_zoo "zcash-orchard-fvk" "test_msg_zcash_orchard.py"
run_zoo "zcash-orchard-pczt" "test_msg_zcash_sign_pczt.py"
run_zoo "zcash-transparent" "test_msg_signtx_zcash.py"

# ── Solana ─────────────────────────────────────────────────
if [ -f "test_msg_solana_getaddress.py" ]; then
    run_zoo "solana" "test_msg_solana_getaddress.py"
fi

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
    chain=$(basename "$dir")
    count=$(ls "$dir"/*.png 2>/dev/null | wc -l)
    TOTAL=$((TOTAL + count))
    printf "  %-30s %d screens\n" "$chain" "$count"
done
echo "  ────────────────────────────────────"
printf "  %-30s %d screens\n" "TOTAL" "$TOTAL"
echo ""
echo "Zoo saved to /kkemu/screen-zoo/"
