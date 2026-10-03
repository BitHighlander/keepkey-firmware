#!/usr/bin/env bash
# Pin gate for the dress rehearsal. One canonical branch per dependency, never split.
#
#   rehearsal-preflight.sh <ref>...        refs in the firmware clone ($FW, default fw-fold)
#
# Rule (docs/release/BRANCHING-SOP.md, "develop pins must exist upstream"): every PR, block head,
# merge commit and release branch pins, for each dependency, the HEAD of the single open upstream
# PR into master:
#
#   python-keepkey   keepkey/python-keepkey  reconcile/upstream-sync   (PR #197 -> master)
#   device-protocol  keepkey/device-protocol up/release-protocol       (PR #112 -> master)
#
# and .gitmodules names exactly those upstream urls and branches. A pin on an ancestor of the head,
# on a fork or side or staging branch, or a different SHA on another block FAILS.
#
# ALLOW_ANCESTOR=1 relaxes only the SHA test to "ancestor of the head". Use it solely for the
# upstream base release PR (e.g. 7.14.3 #475), whose pins are upstream's own, never for our blocks.
#
# Needs, in each deps clone under $FW, a remote named "kk" pointing at the keepkey/* upstream.
set -uo pipefail
FW=${FW:-$HOME/keepkey-toolchain/fw-fold}
PYK=$FW/deps/python-keepkey
DP=$FW/deps/device-protocol
PYK_REPO=keepkey/python-keepkey; PYK_BRANCH=reconcile/upstream-sync
DP_REPO=keepkey/device-protocol; DP_BRANCH=up/release-protocol
fail=0
bad() { echo "FAIL: $*"; fail=1; }

# 1. The canonical PRs: exactly one open PR from the canonical branch into master, head == branch head.
git -C "$PYK" fetch -q kk "$PYK_BRANCH" || bad "cannot fetch $PYK_REPO $PYK_BRANCH"
git -C "$DP" fetch -q kk "$DP_BRANCH" || bad "cannot fetch $DP_REPO $DP_BRANCH"
pyk_head=$(git -C "$PYK" rev-parse "kk/$PYK_BRANCH"); dp_head=$(git -C "$DP" rev-parse "kk/$DP_BRANCH")
for spec in "$PYK_REPO:$PYK_BRANCH:$pyk_head" "$DP_REPO:$DP_BRANCH:$dp_head"; do
  IFS=: read -r repo br want <<<"$spec"
  prs=$(gh pr list --repo "$repo" --base master --head "$br" --state open --json number,headRefOid \
        -q '[.[]|"\(.number):\(.headRefOid)"]|join(" ")')
  n=$(wc -w <<<"$prs" | tr -d " ")
  [ "$n" = 1 ] || bad "$repo: expected exactly one open PR from $br into master, found $n ($prs)"
  [ "${prs#*:}" = "$want" ] || bad "$repo: PR head ${prs#*:} != branch head $want"
done
echo "canonical heads: pyk ${pyk_head:0:9} (PR from $PYK_BRANCH)  dp ${dp_head:0:9} (PR from $DP_BRANCH)"

# 2. Every ref.
printf "%-44s %-9s %-5s | %-9s %-5s | %s\n" REF PYK ok DP ok GITMODULES
for ref in "$@"; do
  pp=$(git -C "$FW" rev-parse -q --verify "$ref:deps/python-keepkey" || echo MISSING)
  dd=$(git -C "$FW" rev-parse -q --verify "$ref:deps/device-protocol" || echo MISSING)
  if [ "$pp" = MISSING ] || [ "$dd" = MISSING ]; then bad "$ref has no pin"; continue; fi
  ok_p=NO; ok_d=NO
  if [ "$pp" = "$pyk_head" ]; then ok_p=head
  elif [ "${ALLOW_ANCESTOR:-0}" = 1 ] && git -C "$PYK" merge-base --is-ancestor "$pp" "$pyk_head" 2>/dev/null; then ok_p=anc; fi
  if [ "$dd" = "$dp_head" ]; then ok_d=head
  elif [ "${ALLOW_ANCESTOR:-0}" = 1 ] && git -C "$DP" merge-base --is-ancestor "$dd" "$dp_head" 2>/dev/null; then ok_d=anc; fi
  gm=ok
  for dep in "deps/python-keepkey|$PYK_REPO|$PYK_BRANCH" "deps/device-protocol|$DP_REPO|$DP_BRANCH"; do
    IFS='|' read -r path repo br <<<"$dep"
    u=$(git -C "$FW" config --blob "$ref:.gitmodules" --get "submodule.$path.url" 2>/dev/null)
    b=$(git -C "$FW" config --blob "$ref:.gitmodules" --get "submodule.$path.branch" 2>/dev/null)
    [ "$u" = "https://github.com/$repo.git" ] && [ "$b" = "$br" ] || gm="$path=$u@$b"
  done
  printf "%-44s %-9s %-5s | %-9s %-5s | %s\n" "${ref:0:44}" "${pp:0:9}" "$ok_p" "${dd:0:9}" "$ok_d" "$gm"
  [ "$ok_p" != NO ] && [ "$ok_d" != NO ] && [ "$gm" = ok ] || fail=1
done
[ $fail = 0 ] && echo "PASS: every ref pins the canonical heads and .gitmodules is uniform" || echo "FAIL: pins are split or not canonical"
exit $fail
