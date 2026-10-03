#!/usr/bin/env bash
# Identity table for the dress rehearsal: for every first-parent merge on fork develop after the
# starting tip, record merge commit, tree, the block's own diff against its first parent, and the
# pyk / dp / trezor-firmware pins. Appends to the receipt.
#   receipt-identity.sh [<start-sha>]   (default: fc1e93746, the fork develop tip before the rehearsal)
set -uo pipefail
FW=$HOME/keepkey-toolchain/fw-fold
RECEIPT=${RECEIPT:-$HOME/keepkey-toolchain/rehearsal-receipt-20261002.md}
START=${1:-fc1e93746}
cd "$FW" && git fetch -q fork develop
{
  echo
  echo "## Identity per merge (first-parent history of develop since ${START:0:9})"
  echo
  echo "| # | Merge | Tree | Parents | Own diff (files, +/-) | pyk | dp | trezor-firmware |"
  echo "|---|-------|------|---------|-----------------------|-----|----|-----------------|"
  n=0
  for m in $(git rev-list --first-parent --reverse "$START"..fork/develop); do
    p1=$(git rev-parse "$m^1"); p2=$(git rev-parse -q --verify "$m^2" || true)
    stat=$(git diff --shortstat "$p1" "$m" | sed -E 's/ files? changed//; s/ insertions?\(\+\)//; s/ deletions?\(-\)//; s/^ *//')
    printf "| %s | \`%s\` | \`%s\` | \`%s\` + \`%s\` | %s | \`%s\` | \`%s\` | \`%s\` |\n" "$n" "${m:0:9}" "$(git rev-parse --short=9 "$m^{tree}")" \
      "${p1:0:9}" "${p2:0:9}" "$stat" \
      "$(git rev-parse --short=9 "$m:deps/python-keepkey")" "$(git rev-parse --short=9 "$m:deps/device-protocol")" "$(git rev-parse --short=9 "$m:deps/crypto/trezor-firmware")"
    n=$((n+1))
  done
} >> "$RECEIPT"
echo "identity table appended to $RECEIPT"
