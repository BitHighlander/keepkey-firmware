#!/bin/sh
#
# Run python-keepkey tests for BTC-only firmware.
# Excludes all alt-chain test files and alt-coin test cases.
#

mkdir -p /kkemu/test-reports/python-keepkey
cd deps/python-keepkey/tests

KK_TRANSPORT_MAIN=kkemu:11044 \
KK_TRANSPORT_DEBUG=kkemu:11045 \
pytest -v \
  --junitxml=/kkemu/test-reports/python-keepkey/junit.xml \
  --ignore=test_msg_ethereum_signtx.py \
  --ignore=test_msg_ethereum_signtx_xfer.py \
  --ignore=test_msg_ethereum_getaddress.py \
  --ignore=test_msg_ethereum_message.py \
  --ignore=test_msg_ethereum_cfunc.py \
  --ignore=test_msg_ethereum_makerdao.py \
  --ignore=test_msg_ethereum_sablier.py \
  --ignore=test_msg_ethereum_erc20_0x_signtx.py \
  --ignore=test_msg_ethereum_erc20_approve.py \
  --ignore=test_msg_ethereum_erc20_uniswap_liquidity.py \
  --ignore=test_msg_signtx_ethereum_erc20.py \
  --ignore=test_msg_cosmos_getaddress.py \
  --ignore=test_msg_cosmos_signtx.py \
  --ignore=test_msg_binance_sign_tx.py \
  --ignore=test_msg_eos_getpublickey.py \
  --ignore=test_msg_eos_signtx.py \
  --ignore=test_msg_nano_getaddress.py \
  --ignore=test_msg_nano_signtx.py \
  --ignore=test_msg_ripple_get_address.py \
  --ignore=test_msg_ripple_sign_tx.py \
  --ignore=test_msg_thorchain_getaddress.py \
  --ignore=test_msg_thorchain_signtx.py \
  --ignore=test_msg_2thorchain_signtx.py \
  --ignore=test_msg_mayachain_getaddress.py \
  --ignore=test_msg_mayachain_signtx.py \
  --ignore=test_msg_signtx_zcash.py \
  --ignore=test_msg_zcash_orchard.py \
  --ignore=test_msg_signtx_bgold.py \
  --ignore=test_msg_signtx_dash.py \
  --ignore=test_msg_signtx_grs.py \
  --ignore=test_msg_signtx_segwit_grs.py \
  --ignore=test_msg_signtx_segwit_native_grs.py \
  --ignore=test_sign_typed_data.py \
  --ignore=test_verify_typed_data.py \
  -k "not (grs or ltc or tgrs or GRS)"

echo "$?" > /kkemu/test-reports/python-keepkey/status
