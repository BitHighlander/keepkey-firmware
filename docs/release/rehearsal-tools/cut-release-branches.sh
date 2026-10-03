#!/usr/bin/env bash
# End of the dress rehearsal: cut the two fork release branches from fork develop.
#   release/7.15.0-$ID  = develop right after PR #899 (b6, the 7.15 tip) merged
#   release/7.16.0-$ID  = develop right after PR #919 (b15, the 7.16 tip) merged
# Refuses unless each merge commit's TREE equals the tree of the stack tip that CI verified, so the
# rehearsal provably reproduced the tested code. Creates new branches only (never moves one).
set -euo pipefail
R=${R:-BitHighlander/keepkey-firmware}
FW=${FW:-$HOME/keepkey-toolchain/fw-fold}
PR715=${PR715:-899}; PR716=${PR716:-919}     # the PRs of the 7.15 and 7.16 tip blocks
TIP715=${TIP715:-fork/stack/715-b6-gaps-20260930}; TIP716=${TIP716:-fork/stack/716-b15-permit2-20261002}
ID=${ID:-rehearsal-20261002}            # rehearsal id; branch names must not collide with release/*
B715=release/7.15.0-$ID
B716=release/7.16.0-$ID
cd "$FW" && git fetch -q fork

m6=$(gh api repos/$R/pulls/$PR715 -q .merge_commit_sha)
m15=$(gh api repos/$R/pulls/$PR716 -q .merge_commit_sha)
for pair in "$m6:$TIP715:7.15" "$m15:$TIP716:7.16"; do
  IFS=: read -r m tip label <<<"$pair"
  git merge-base --is-ancestor "$m" fork/develop || { echo "FAIL: $label merge ${m:0:9} is not on fork develop"; exit 1; }
  [ "$(git rev-parse "$m^{tree}")" = "$(git rev-parse "$tip^{tree}")" ] \
    || { echo "FAIL: $label merge ${m:0:9} tree differs from $tip"; exit 1; }
  echo "$label: merge ${m:0:9} tree $(git rev-parse --short=9 "$m^{tree}") == $tip"
done
for b in $B715 $B716; do
  git ls-remote --exit-code -q fork "refs/heads/$b" >/dev/null 2>&1 && { echo "FAIL: $b already exists on the fork"; exit 1; }
done
git push fork "$m6:refs/heads/$B715" "$m15:refs/heads/$B716"
echo "created $B715 @ ${m6:0:9} and $B716 @ ${m15:0:9}"
