set -eu
cp /evidence/kkemu-cointable-full /tmp/kkemu
chmod +x /tmp/kkemu
mkdir /tmp/emulator-work
cd /tmp/emulator-work
/tmp/kkemu > /audit/emulator.log 2>&1 &
export KK_TRANSPORT_MAIN=127.0.0.1:11044 KK_TRANSPORT_DEBUG=127.0.0.1:11045
export PYTHONPATH=/audit-host:/audit-host/tests
export KK_RELEASE_MISSING_CAPABILITIES=
pytest -v --tb=short -p no:cacheprovider /audit/test_liquidity_consent.py --junitxml=/audit/consent.xml
