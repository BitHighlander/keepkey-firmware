#!/bin/sh
# Regenerates unittests/firmware/monero_crypto_vectors.h and checks every
# record with Monero Core v0.18.5.4 before the header is replaced.
#
#   monero_vectors_gen.sh OUTDIR
#
# Needs a host C compiler, and for the Core check:
#   MONERO_CORE_SRC    monero-project/monero checkout at tag v0.18.5.4
#   MONERO_CORE_BUILD  its CMake build tree (libringct.a and friends)
#   MONERO_DEPS        prefix holding boost, openssl@3, libsodium, unbound and
#                      hidapi (default: /opt/homebrew/opt, macOS Homebrew)
# The header is only replaced when Core agrees with every record.
set -eu
OUT=$1
HERE=$(cd "$(dirname "$0")" && pwd)
SRC=$(cd "$HERE/../.." && pwd)
C=$SRC/deps/crypto/trezor-firmware/crypto
DEPS=${MONERO_DEPS:-/opt/homebrew/opt}
mkdir -p "$OUT"

FLAGS="-O2 -std=gnu99 -DUSE_MONERO=1 -DUSE_KECCAK=1 -DUSE_ETHEREUM=1 \
 -DUSE_GROESTL=0 -DXMR_TEST_RNG_NO_CHECKED=1 \
 -I$SRC/include -I$C -I$SRC/lib/firmware/monero -I$HERE"
CRY="$C/hasher.c $C/sha2.c $C/sha3.c $C/ripemd160.c $C/blake256.c \
 $C/blake2b.c $C/memzero.c \
 $C/ed25519-donna/curve25519-donna-scalarmult-base.c \
 $C/ed25519-donna/ed25519-donna-32bit-tables.c $C/ed25519-donna/ed25519.c \
 $C/ed25519-donna/curve25519-donna-helpers.c \
 $C/ed25519-donna/ed25519-donna-basepoint-table.c \
 $C/ed25519-donna/modm-donna-32bit.c $C/ed25519-donna/curve25519-donna-32bit.c \
 $C/ed25519-donna/ed25519-donna-impl-base.c $C/monero/xmr.c $C/monero/serialize.c"
MON="$SRC/lib/firmware/monero/crypto_bpp.c \
 $SRC/lib/firmware/monero/crypto_clsag.c \
 $SRC/lib/firmware/monero/crypto_hedge.c"
# shellcheck disable=SC2086
# Dead-stripped: random_buffer() (behind trezor-crypto's xmr_random_scalar) is
# deliberately not defined, so the link fails if the prover or signer reached
# an unchecked draw.
cc $FLAGS -Wl,-dead_strip $CRY $MON "$HERE/monero_test_rng.c" \
  "$HERE/monero_vectors_gen.c" -o "$OUT/monero_vectors_gen"
"$OUT/monero_vectors_gen" "$OUT/records.bin" "$OUT/monero_crypto_vectors.h"

S=$MONERO_CORE_SRC
B=$MONERO_CORE_BUILD
# shellcheck disable=SC2086
c++ -std=c++14 -O2 -I"$S/src" -I"$S/contrib/epee/include" \
  -I"$S/external/easylogging++" -I"$S/external" -I"$B" \
  -I"$DEPS/boost/include" -I"$DEPS/libsodium/include" \
  "$HERE/monero_core_verify.cpp" -o "$OUT/monero_core_verify" \
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
if ! "$OUT/monero_core_verify" "$OUT/records.bin" >"$OUT/core_verify.log"; then
  cat "$OUT/core_verify.log"
  echo "Monero Core disagrees with a record; header NOT updated" >&2
  exit 1
fi
cat "$OUT/core_verify.log"
cp "$OUT/monero_crypto_vectors.h" "$HERE/monero_crypto_vectors.h"
echo "updated $HERE/monero_crypto_vectors.h"
