#!/bin/sh
# Generate the published hash manifest for a directory of release artifacts.
#
# This exists as a script rather than as steps inside release.yml because the
# manifest has to be produced TWICE: once by CI over the unsigned build, and
# again by the key holders over the signed binaries they are about to upload.
# When only CI could generate it, the published full-image hash described the
# unsigned draft -- the binary nobody installs -- while the checklist quietly
# swapped the signed one in underneath it. That is the most likely origin of
# the wrong v7.14.1 hash that ended up pinned in KeepKey Vault.
#
# Usage:
#   scripts/release/hash-manifest.sh <dir> <version> <variant> [suffix]
#   scripts/release/hash-manifest.sh --require-signed <dir> <version> <variant> [suffix]
#   scripts/release/hash-manifest.sh --self-test
#
# Writes HASHES<suffix>.txt into <dir>. With --require-signed it exits non-zero
# unless every application firmware image carries three distinct signer slots
# and three non-zero signatures -- run it that way before publishing.
#
# Application metadata descriptor (include/keepkey/board/memory.h):
#   0x00  4  magic 'KPKY'      0x08  1  sig_index1     0x40  64  signature 1
#   0x04  4  codelen (LE)      0x09  1  sig_index2     0x80  64  signature 2
#                              0x0A  1  sig_index3     0xC0  64  signature 3
#                              0x0B  1  sig_flag
set -eu

sha256() { { command -v sha256sum >/dev/null && sha256sum; } || shasum -a 256; }
digest() { sha256 | awk '{print $1}'; }

# Little-endian uint32 at byte offset $2 of file $1. NR==1 because od closes
# with a trailing offset line that awk would otherwise emit as a second value.
le32() {
  od -An -tu1 -j"$2" -N4 "$1" |
    awk 'NR == 1 {print $1 + $2 * 256 + $3 * 65536 + $4 * 16777216}'
}
u8() { od -An -tu1 -j"$2" -N1 "$1" | awk 'NR == 1 {print $1}'; }
is_kpky() { [ "$(od -An -c -N4 "$1" | tr -d ' \n')" = "KPKY" ]; }

# Three distinct non-zero signer slots and three non-zero signatures. This is a
# structural quorum check, NOT signature verification -- it catches "the
# unsigned binary got uploaded", which is the failure actually observed.
has_quorum() {
  _i1=$(u8 "$1" 8); _i2=$(u8 "$1" 9); _i3=$(u8 "$1" 10)
  [ "$_i1" -ne 0 ] && [ "$_i2" -ne 0 ] && [ "$_i3" -ne 0 ] || return 1
  [ "$_i1" -ne "$_i2" ] && [ "$_i1" -ne "$_i3" ] && [ "$_i2" -ne "$_i3" ] || return 1
  _sigs=$(od -An -tx1 -j64 -N192 "$1" | tr -d ' \n')
  [ -n "$(printf '%s' "$_sigs" | tr -d '0')" ]
}
signer_slots() { printf '%s,%s,%s' "$(u8 "$1" 8)" "$(u8 "$1" 9)" "$(u8 "$1" 10)"; }

self_test() {
  d=$(mktemp -d)
  trap 'rm -rf "$d"' EXIT
  # 256-byte descriptor + 4 bytes of "code": magic, codelen=4, no signatures.
  printf 'KPKY\004\000\000\000' > "$d/f.bin"
  dd if=/dev/zero bs=1 count=248 >> "$d/f.bin" 2>/dev/null
  printf 'code' >> "$d/f.bin"
  is_kpky "$d/f.bin" || { echo "self-test: magic not detected"; exit 1; }
  [ "$(le32 "$d/f.bin" 4)" = "4" ] || { echo "self-test: codelen misread"; exit 1; }
  has_quorum "$d/f.bin" && { echo "self-test: unsigned image claimed quorum"; exit 1; }
  # Sign it: slots 1,2,4 and non-zero signature bytes.
  printf '\001\002\004\001' | dd of="$d/f.bin" bs=1 seek=8 conv=notrunc 2>/dev/null
  printf '\052' | dd of="$d/f.bin" bs=1 seek=64 conv=notrunc 2>/dev/null
  has_quorum "$d/f.bin" || { echo "self-test: signed image failed quorum"; exit 1; }
  # Repeated slots are not a quorum, however non-zero.
  printf '\001\001\004' | dd of="$d/f.bin" bs=1 seek=8 conv=notrunc 2>/dev/null
  has_quorum "$d/f.bin" && { echo "self-test: duplicate slots passed quorum"; exit 1; }
  echo "self-test: ok"
}

[ "${1:-}" = "--self-test" ] && { self_test; exit 0; }

REQUIRE_SIGNED=0
if [ "${1:-}" = "--require-signed" ]; then REQUIRE_SIGNED=1; shift; fi

DIR=$1; VERSION=$2; VARIANT=$3; SUFFIX=${4:-}
cd "$DIR"

OUT="HASHES${SUFFIX}.txt"
: > "$OUT"

# Signed-ness is read off the artifacts rather than passed in, so the manifest
# cannot claim a state the bytes do not support.
UNSIGNED=0
for f in *.bin; do
  [ -f "$f" ] || continue
  is_kpky "$f" || continue
  has_quorum "$f" || UNSIGNED=1
done

{
  echo "# KeepKey Firmware v${VERSION} (${VARIANT}) — Hash Manifest"
  echo "#"
  if [ "$UNSIGNED" -eq 1 ]; then
    echo "# THESE ARE THE UNSIGNED BUILD ARTIFACTS. Signing rewrites the 256-byte"
    echo "# metadata descriptor, which CHANGES every 'device image' and 'whole file'"
    echo "# hash below. Regenerate this file from the signed binaries before"
    echo "# publishing:"
    echo "#   scripts/release/hash-manifest.sh --require-signed . ${VERSION} ${VARIANT} ${SUFFIX}"
    echo "# Only the 'payload' hash survives signing unchanged."
  else
    echo "# Generated from the signed release artifacts."
  fi
  echo ""
} >> "$OUT"

for f in *.bin *.elf; do
  [ -f "$f" ] || continue
  WHOLE=$(digest < "$f")

  if ! is_kpky "$f"; then
    # No KPKY descriptor: a bootloader image or a build product. The
    # device-image and payload framings below simply do not apply to it, and
    # applying them is how 'tail -c +257' ended up recommended for
    # bootloader.bin.
    {
      echo "$f  (no KPKY application descriptor)"
      echo "  sha256 (whole file)    $WHOLE"
      echo "    The file as published. This is NOT what Features.firmware_hash"
      echo "    reports, and 'tail -c +257' does not apply to it."
      echo ""
    } >> "$OUT"
    continue
  fi

  CODELEN=$(le32 "$f" 4)
  SIZE=$(wc -c < "$f" | tr -d ' ')
  DEVICE=$(head -c $((256 + CODELEN)) "$f" | digest)
  PAYLOAD=$(tail -c +257 "$f" | digest)

  if has_quorum "$f"; then
    STATE="signed, signer slots $(signer_slots "$f")"
  else
    STATE="UNSIGNED"
  fi

  {
    echo "$f  (application firmware, ${STATE})"
    echo "  sha256 (device image)  $DEVICE"
    echo "    Compare against the firmware hash your device reports"
    echo "    (Features.firmware_hash, shown in KeepKey Vault)."
    echo "    Covers the 256-byte metadata descriptor -- signatures included --"
    echo "    plus codelen (${CODELEN}) bytes of application code."
    echo "    Signing CHANGES this hash."
    echo "  sha256 (whole file)    $WHOLE"
    if [ "$SIZE" -eq $((256 + CODELEN)) ]; then
      echo "    The file as published; identical to the device image hash above."
    else
      echo "    The file as published. It is ${SIZE} bytes against a"
      echo "    256+codelen device image of $((256 + CODELEN)), so the two hashes"
      echo "    DIFFER. Pin the device image hash, not this one."
    fi
    echo "  sha256 (payload)       $PAYLOAD"
    echo "    Compare against your own reproducible build, with"
    echo "    'tail -c +257' applied to BOTH files -- a local build"
    echo "    has no signatures in its 256-byte descriptor."
    echo "    This proves the release binary came from the source."
    echo "    Signing does NOT change this hash, and it is NOT the hash"
    echo "    the device reports."
    echo ""
  } >> "$OUT"
done

cat "$OUT"

if [ "$REQUIRE_SIGNED" -eq 1 ] && [ "$UNSIGNED" -eq 1 ]; then
  echo "ERROR: an application firmware image is missing its 3-of-5 quorum." >&2
  exit 1
fi
