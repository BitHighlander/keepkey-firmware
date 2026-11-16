#!/bin/sh
# Regenerates unittests/firmware/monero_tx_vectors.h: runs the MoneroTx unit
# tests so they record every transaction they assemble from the signer's
# replies, and checks each record with Monero Core v0.18.5.4.
#
#   monero_tx_vectors_gen.sh FIRMWARE_UNIT OUTDIR
#
# FIRMWARE_UNIT is a built bin/firmware-unit. Also needs:
#   MONERO_CORE_SRC    monero-project/monero checkout at tag v0.18.5.4
#   MONERO_CORE_BUILD  its CMake build tree (libringct.a and friends)
#   MONERO_DEPS        prefix holding boost, openssl@3, libsodium, unbound and
#                      hidapi (default: /opt/homebrew/opt, macOS Homebrew)
#   KEEPKEY_UDP_PORT   a free UDP port for the test binary (default 22050)
# The header is only replaced when Core agrees with every record: it accepts
# every transaction the signer produced and rejects every tampered copy.
set -eu
UNIT=$1
OUT=$2
HERE=$(cd "$(dirname "$0")" && pwd)
DEPS=${MONERO_DEPS:-/opt/homebrew/opt}
S=$MONERO_CORE_SRC
B=$MONERO_CORE_BUILD
mkdir -p "$OUT"
rm -f "$OUT/tx_records.bin"

# The tests write a record per transaction instead of comparing it with the
# committed digest; Core decides below. This includes the no-change sweep
# and two-recipient cases; regenerate with this Core harness after changes,
# never insert transaction digests by hand.
KK_XMR_TX_RECORDS="$OUT/tx_records.bin" \
  KEEPKEY_UDP_PORT=${KEEPKEY_UDP_PORT:-22050} \
  GTEST_FILTER='MoneroTx.*VerifiesWithMoneroCore' "$UNIT" \
  >"$OUT/tx_unit.log" 2>&1 || {
  tail -30 "$OUT/tx_unit.log"
  echo "the signer tests failed; header NOT updated" >&2
  exit 1
}

# shellcheck disable=SC2086
c++ -std=c++14 -O2 -I"$S/src" -I"$S/contrib/epee/include" \
  -I"$S/external/easylogging++" -I"$S/external" -I"$B" \
  -I"$DEPS/boost/include" -I"$DEPS/libsodium/include" \
  -I"$DEPS/openssl@3/include" \
  "$HERE/monero_tx_core_verify.cpp" -o "$OUT/monero_tx_core_verify" \
  "$B/src/ringct/libringct.a" "$B/src/cryptonote_basic/libcryptonote_basic.a" \
  "$B/src/cryptonote_basic/libcryptonote_format_utils_basic.a" \
  "$B/src/ringct/libringct_basic.a" "$B/src/device/libdevice.a" \
  "$B/src/common/libcommon.a" "$B/src/crypto/libcncrypto.a" \
  "$B/src/checkpoints/libcheckpoints.a" "$B/src/libversion.a" \
  "$B/contrib/epee/src/libepee.a" "$B/external/easylogging++/libeasylogging.a" \
  "$B/external/randomx/librandomx.a" -L"$DEPS/boost/lib" -lboost_thread \
  -lboost_filesystem -lboost_chrono -lboost_serialization \
  -lboost_program_options -lboost_date_time -lboost_regex -lboost_locale \
  -lboost_atomic -L"$DEPS/openssl@3/lib" -lssl -lcrypto \
  -L"$DEPS/libsodium/lib" -lsodium -L"$DEPS/unbound/lib" -lunbound \
  -L"$DEPS/hidapi/lib" -lhidapi -framework AppKit -framework CoreFoundation \
  -framework IOKit -framework Security
if ! "$OUT/monero_tx_core_verify" "$OUT/tx_records.bin" \
  "$OUT/monero_tx_vectors.h" >"$OUT/tx_core_verify.log"; then
  cat "$OUT/tx_core_verify.log"
  echo "Monero Core disagrees with a record; header NOT updated" >&2
  exit 1
fi
cat "$OUT/tx_core_verify.log"
cp "$OUT/monero_tx_vectors.h" "$HERE/monero_tx_vectors.h"
echo "updated $HERE/monero_tx_vectors.h"
