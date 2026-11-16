#!/bin/sh
# build-plan-adapter.sh <output-binary>
# Builds plan-adapter.cpp against an existing Monero Core v0.18.5.4 build
# that has the wallet library (cmake --build <core-build> --target wallet).
#   MONERO_CORE_SRC    Core source tree
#   MONERO_CORE_BUILD  its build directory
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
S=${MONERO_CORE_SRC:?set MONERO_CORE_SRC}
B=${MONERO_CORE_BUILD:?set MONERO_CORE_BUILD}
BREW=${HOMEBREW_PREFIX:-/opt/homebrew}
OUT=${1:?usage: build-plan-adapter.sh <output-binary>}
c++ -std=c++14 -O2 -fno-strict-aliasing -DNDEBUG -DAUTO_INITIALIZE_EASYLOGGINGPP \
  -DBOOST_NO_AUTO_PTR -DBOOST_UUID_DISABLE_ALIGNMENT -DHAVE_HIDAPI -w \
  -I"$S/external/rapidjson/include" -I"$S/external/easylogging++" -I"$S/src" \
  -I"$S/contrib/epee/include" -I"$S/external" -I"$S/external/supercop/include" \
  -I"$B/generated_include" -I"$B/translations" -I"$S/external/db_drivers/liblmdb" \
  -I"$BREW/opt/openssl@3/include" -isystem "$BREW/include" \
  "$HERE/plan-adapter.cpp" -o "$OUT" \
  "$B/lib/libwallet.a" "$B/src/libversion.a" "$B/src/rpc/librpc_base.a" \
  "$B/src/multisig/libmultisig.a" "$B/src/cryptonote_core/libcryptonote_core.a" \
  "$B/src/blockchain_db/libblockchain_db.a" "$B/src/ringct/libringct.a" \
  "$B/src/cryptonote_basic/libcryptonote_basic.a" "$B/src/checkpoints/libcheckpoints.a" \
  "$B/src/device/libdevice.a" "$B/src/cryptonote_basic/libcryptonote_format_utils_basic.a" \
  "$B/src/ringct/libringct_basic.a" "$B/src/blocks/libblocks.a" \
  "$B/src/hardforks/libhardforks.a" "$B/src/libversion.a" "$B/src/mnemonics/libmnemonics.a" \
  "$B/src/device_trezor/libdevice_trezor.a" "$B/src/net/libnet.a" "$B/src/common/libcommon.a" \
  "$B/src/crypto/libcncrypto.a" "$B/external/randomx/librandomx.a" \
  "$B/contrib/epee/src/libepee.a" "$B/external/easylogging++/libeasylogging.a" \
  "$B/external/db_drivers/liblmdb/liblmdb.a" \
  -L"$BREW/lib" -L"$BREW/opt/openssl@3/lib" -lboost_program_options -lboost_date_time \
  -lboost_chrono -lboost_serialization -lboost_filesystem -lboost_thread \
  -lhidapi -lunbound -lssl -lcrypto -lzmq -lsodium -lgssapi_krb5 \
  -framework AppKit -framework IOKit -framework CoreFoundation
echo "built $OUT"
