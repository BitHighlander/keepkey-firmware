#!/usr/bin/env bash
# Put every caps/<block> on the exact heads of the canonical upstream PRs (BRANCHING-SOP dress-rehearsal pin).
#   repin-caps.sh <pyk-head> <dp-head>
# For each block in order: merge the block below (a gitlink conflict keeps the block's own pin, which is
# overwritten right after), then commit the pin if it differs. Commits only the two gitlinks, via
# update-index, so a stray submodule worktree can never leak into a pin commit.
set -euo pipefail
PYK=$1; DP=$2
cd ~/keepkey-toolchain/fw-fold
R=(715-b1-core-ci-20260930 715-b2-evm-20260930 715-b3-erc7730-20260930 715-b4-chains-20260930
   715-b5-zcash-20260930 715-b6-gaps-20260930 716-b7-binance-retire-20260930
   716-b8a-certified-evm-20261001 716-b8b-certified-solana-20261001 716-b9-version-gate-20261001
   716-b11-passkeys-20261001 716-b12-solana-trades-20261001 716-b13-intent-review-20261002
   716-b14-evm-intent-20261002 716-b15-permit2-20261002)
for i in $(seq 0 14); do
  r=${R[$i]}
  git checkout -q caps/$r
  if [ "$i" -gt 0 ]; then
    p=${R[$((i-1))]}
    if ! git merge-base --is-ancestor caps/$p HEAD; then
      own=$(git rev-parse HEAD:deps/python-keepkey)
      if ! git merge -q --no-ff --no-commit caps/$p >/dev/null 2>&1; then
        for c in $(git diff --name-only --diff-filter=U); do
          [ "$c" = deps/python-keepkey ] || { echo "UNEXPECTED conflict at $r: $c"; exit 1; }
          git update-index --cacheinfo 160000,$own,deps/python-keepkey
        done
      fi
      git commit -q --no-edit -m "Merge caps/$p forward (canonical pins)"
    fi
  fi
  old=$(git rev-parse HEAD:deps/python-keepkey); olddp=$(git rev-parse HEAD:deps/device-protocol)
  if [ "$old" != "$PYK" ] || [ "$olddp" != "$DP" ]; then
    git update-index --cacheinfo 160000,$PYK,deps/python-keepkey
    git update-index --cacheinfo 160000,$DP,deps/device-protocol
    [ "$(git diff --cached --name-only | sort | tr '\n' ' ')" = "deps/device-protocol deps/python-keepkey " ] \
      || [ "$(git diff --cached --name-only | tr '\n' ' ')" = "deps/python-keepkey " ] \
      || { echo "unexpected staged files at $r: $(git diff --cached --name-only | tr '\n' ' ')"; exit 1; }
    git commit -q -m "deps: pin python-keepkey ${PYK:0:9}, the head of upstream PR #197

Every block pins the exact head of the single open upstream PR for each submodule
(BRANCHING-SOP: the dress-rehearsal pin), so no block pins a side or ancestor commit.
This block pinned ${old:0:9}, an ancestor of that head on the same branch; the head's tree
adds only the canonical branch's own CI and whitespace changes over the b15 pin.
device-protocol stays ${DP:0:9}, the head of upstream PR #112."
  fi
  echo "$r pyk=$(git rev-parse --short=9 HEAD:deps/python-keepkey) dp=$(git rev-parse --short=9 HEAD:deps/device-protocol) (was ${old:0:9})"
done
