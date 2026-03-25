#!/bin/sh
# Generate test report PDF from python-keepkey test results.
# Runs full test suite, generates pass/fail PDF report as CI artifact.
# OLED screenshots are captured locally (not in CI) — see RELEASE-SOP.md.

mkdir -p /kkemu/test-reports/python-keepkey

cd deps/python-keepkey/tests

# Run full test suite
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
  pytest -v --junitxml=/kkemu/test-reports/python-keepkey/junit.xml
echo "$?" > /kkemu/test-reports/python-keepkey/status

# Generate report PDF from junit results (no screenshots in CI)
cd /kkemu/deps/python-keepkey
python3 scripts/generate-test-report.py \
  --junit=/kkemu/test-reports/python-keepkey/junit.xml \
  --output=/kkemu/test-reports/python-keepkey/test-report.pdf \
  || echo "Report generation failed (non-fatal)"
