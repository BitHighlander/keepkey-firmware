set -eu
cp /evidence/kkemu-cointable-full /tmp/kkemu
chmod +x /tmp/kkemu
mkdir /tmp/emulator-work
cd /tmp/emulator-work
/tmp/kkemu > /audit/liquidity-emulator.log 2>&1 &
export KK_TRANSPORT_MAIN=127.0.0.1:11044 KK_TRANSPORT_DEBUG=127.0.0.1:11045
export PYTHONPATH=/audit-host
export KK_RELEASE_MISSING_CAPABILITIES=
cd /audit-host/tests
pytest -v --tb=short -p no:cacheprovider test_msg_ethereum_erc20_uniswap_liquidity.py --junitxml=/audit/liquidity-host.xml
