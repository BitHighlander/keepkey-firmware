#!/bin/sh

mkdir -p /kkemu/test-reports/python-keepkey/screenshots
pip3 install Pillow >/dev/null 2>&1

cd deps/python-keepkey/tests
KEEPKEY_SCREENSHOT=1 \
SCREENSHOT_DIR=/kkemu/test-reports/python-keepkey/screenshots \
KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v --junitxml=/kkemu/test-reports/python-keepkey/junit.xml
echo "$?" > /kkemu/test-reports/python-keepkey/status

# Generate visual zoo report from screenshots
cd /kkemu
python3 scripts/zoo/generate-test-report.py \
  --screenshots=/kkemu/test-reports/python-keepkey/screenshots \
  --junit=/kkemu/test-reports/python-keepkey/junit.xml \
  --output=/kkemu/test-reports/python-keepkey/zoo-report.html
