#!/bin/sh
# Two-pass test report: clean results + targeted screenshots.
# Pass 1: Full suite WITHOUT screenshots — accurate junit
# Pass 2: Targeted subset WITH screenshots — key OLED screens
# Report merges both into a PDF artifact.

mkdir -p /kkemu/test-reports/python-keepkey

cd deps/python-keepkey/tests

# Pass 1: Full suite, no screenshots
echo "=== Pass 1: Full test suite ==="
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
  pytest -v --junitxml=/kkemu/test-reports/python-keepkey/junit.xml
echo "$?" > /kkemu/test-reports/python-keepkey/status

# Pass 2: Targeted screenshots
echo "=== Pass 2: Targeted screenshots ==="
export KEEPKEY_SCREENSHOT=1
export SCREENSHOT_DIR=/kkemu/test-reports/python-keepkey/screenshots
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
  pytest -v -s -k "test_wipe or test_show or test_one_one_fee or test_ethereum_signtx_nodata or test_apply_settings or test_ping or test_entropy or test_encrypt or test_decrypt or test_ripple_sign or test_cosmos_sign_tx or test_thorchain_sign_tx" \
  2>&1 || true

# Generate report PDF
cd /kkemu/deps/python-keepkey
python3 scripts/generate-test-report.py \
  --junit=/kkemu/test-reports/python-keepkey/junit.xml \
  --screenshots=/kkemu/test-reports/python-keepkey/screenshots \
  --output=/kkemu/test-reports/python-keepkey/test-report.pdf \
  || echo "Report generation failed (non-fatal)"
