#!/usr/bin/env bash
# Dress rehearsal: merge the block PRs into fork develop one at a time, verifying CI each time.
#
#   merge-blocks.sh [first-index]        index 0 = the base PR (#938); 1..15 = b1..b15
#
# For each block N the script:
#   1. retargets the PR to develop and reopens it, so a NEW pull_request run starts on the
#      merge of the block with the CURRENT develop tip (stale checks from earlier runs on the
#      same commit never count: it waits for a run created after the reopen)
#   2. waits for that run to finish green, and for every other check on the PR to be clean
#   3. waits for the previous merge's push run on develop to be green
#   4. merges with a merge commit, guarded by the head SHA the PR run verified
#   5. runs the strict pin gate on the head before the merge and on the merge commit after it
#      (index 0, the upstream base release, uses ALLOW_ANCESTOR=1), and records the block in the receipt
# Any red or missing run stops the script; nothing is merged over it.
set -uo pipefail
R=BitHighlander/keepkey-firmware
FW=$HOME/keepkey-toolchain/fw-fold
RECEIPT=${RECEIPT:-$HOME/keepkey-toolchain/rehearsal-receipt-20261002.md}
LOG=${LOG:-$HOME/keepkey-toolchain/rehearsal-merge.log}
HERE=$(cd "$(dirname "$0")" && pwd)
PREFLIGHT=${PREFLIGHT:-$HERE/rehearsal-preflight.sh}   # strict pin gate (BRANCHING-SOP)
BLOCKS=(
  "rehearsal/develop-base-20261002:938"
  "stack/715-b1-core-ci-20260930:894" "stack/715-b2-evm-20260930:895" "stack/715-b3-erc7730-20260930:896"
  "stack/715-b4-chains-20260930:897" "stack/715-b5-zcash-20260930:898" "stack/715-b6-gaps-20260930:899"
  "stack/716-b7-binance-retire-20260930:900" "stack/716-b8a-certified-evm-20261001:901"
  "stack/716-b8b-certified-solana-20261001:903" "stack/716-b9-version-gate-20261001:904"
  "stack/716-b11-passkeys-20261001:906" "stack/716-b12-solana-trades-20261001:912"
  "stack/716-b13-intent-review-20261002:915" "stack/716-b14-evm-intent-20261002:917"
  "stack/716-b15-permit2-20261002:919"
)
START=${1:-0}
say() { local l="[$(date +%H:%M:%S)] $*"; echo "$l" >> "$LOG"; echo "$l"; }
die() { say "STOP: $*"; exit 1; }
mins() { python3 -c "from datetime import datetime as d;f='%Y-%m-%dT%H:%M:%SZ';print(round((d.strptime('$2',f)-d.strptime('$1',f)).total_seconds()/60))"; }

# A pull_request run of ci.yml for this exact head, created at/after $3. Prints "status conclusion id created updated".
pr_run() { # branch head since
  gh run list --repo $R --workflow ci.yml --branch "$1" --event pull_request -L 20 \
    --json headSha,status,conclusion,databaseId,createdAt,updatedAt \
    -q "[.[]|select(.headSha==\"$2\" and .createdAt>=\"$3\")]|sort_by(.createdAt)|last|\"\(.status) \(.conclusion) \(.databaseId) \(.createdAt) \(.updatedAt)\"" 2>/dev/null
}
push_run() { # sha
  gh run list --repo $R --workflow ci.yml --branch develop --event push -L 20 \
    --json headSha,status,conclusion,databaseId,createdAt,updatedAt \
    -q "[.[]|select(.headSha==\"$1\")][0]|\"\(.status) \(.conclusion) \(.databaseId) \(.createdAt) \(.updatedAt)\"" 2>/dev/null
}
wait_run() { # fn args... ; sets RUN_ID RUN_CON RUN_MIN ; waits for appear (up to ~15 min) then completion
  local fn=$1; shift
  local out st con id c u
  for _ in $(seq 1 20); do
    out=$($fn "$@"); read -r st con id c u <<<"$out"
    [ -n "${id:-}" ] && [ "$id" != null ] && break
    sleep 45
  done
  [ -n "${id:-}" ] && [ "$id" != null ] || return 2
  while [ "$st" != completed ]; do sleep 45; out=$($fn "$@"); read -r st con id c u <<<"$out"; done
  RUN_ID=$id; RUN_CON=$con; RUN_MIN=$(mins "$c" "$u")
  [ "$con" = success ]
}
other_checks_clean() { # PR chosen-run-id head branch -> 0 if every OTHER pull_request run on this head is clean
  # A run cancelled before the chosen one was superseded by it (a push or my reopen cancels the older
  # run in the same concurrency group), so its leftover checks do not count. Anything else must be green.
  local bad
  bad=$(gh run list --repo $R --branch "$4" --event pull_request -L 50 --json databaseId,workflowName,status,conclusion,headSha \
    -q "[.[]|select(.headSha==\"$3\" and .databaseId!=$2 and (.status!=\"completed\" or ((.conclusion!=\"success\" and .conclusion!=\"skipped\") and (.conclusion!=\"cancelled\" or .databaseId>$2))))|\"\\(.workflowName) \\(.databaseId)=\\(.status)/\\(.conclusion)\"]|join(\", \")" 2>/dev/null)
  [ -z "$bad" ] || { say "PR #$1 has other runs that are not clean: $bad"; return 1; }
}

[ -f "$RECEIPT" ] || cat > "$RECEIPT" <<'EOF'
# Dress rehearsal receipt: merging the 7.15/7.16 blocks into fork develop

Each block is merged with a merge commit into BitHighlander/keepkey-firmware `develop` after its
pull_request run (on the merge with the current develop tip) is green; the next block is not merged
until the push run on develop for the previous merge is green too. KK_CI_REHEARSAL=1 skips the OLED
capture and the two evidence jobs, so these runs prove the merges are green, not release evidence.

| # | Block | PR | Merge commit | PR run (min) | Push run on develop (min) | Pyk pin | Dp pin |
|---|-------|----|--------------|--------------|---------------------------|---------|--------|
EOF

prev_sha=""; prev_label=""; prev_prefix=""; prev_pins=""
finish_prev() { # waits for prev push run, then appends the receipt row
  [ -n "$prev_sha" ] || return 0
  say "waiting for the push run on develop for $prev_label (${prev_sha:0:9})"
  wait_run push_run "$prev_sha" || die "develop is not green after $prev_label (run ${RUN_ID:-none}: ${RUN_CON:-missing})"
  say "develop green after $prev_label: run $RUN_ID in ${RUN_MIN}m"
  echo "$prev_prefix [run $RUN_ID](https://github.com/$R/actions/runs/$RUN_ID) (${RUN_MIN}m) | $prev_pins" >> "$RECEIPT"
}
for idx in $(seq "$START" $((${#BLOCKS[@]}-1))); do
  IFS=: read -r branch pr <<<"${BLOCKS[$idx]}"
  label=${branch#stack/}; label=${label#rehearsal/}
  say "=== [$idx] $label  PR #$pr"
  head=$(git -C $FW ls-remote -q fork "refs/heads/$branch" | cut -c1-40)
  [ -n "$head" ] || die "branch $branch not found on the fork"
  [ "$(gh api repos/$R/pulls/$pr -q .head.sha)" = "$head" ] || die "PR #$pr head differs from branch $branch"
  since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  if [ "$idx" = 0 ]; then
    since=$(gh api repos/$R/pulls/$pr -q .created_at)     # its run started when the PR opened
  else
    gh api -X PATCH repos/$R/pulls/$pr -f base=develop -q .base.ref >/dev/null || die "cannot retarget PR #$pr"
    gh api -X PATCH repos/$R/pulls/$pr -f state=closed -q .state >/dev/null || die "cannot close PR #$pr"
    sleep 3
    gh api -X PATCH repos/$R/pulls/$pr -f state=open -q .state >/dev/null || die "cannot reopen PR #$pr"
  fi
  wait_run pr_run "$branch" "$head" "$since" || die "PR #$pr run ${RUN_ID:-none} is not green (${RUN_CON:-missing})"
  pr_run_id=$RUN_ID; pr_run_min=$RUN_MIN
  other_checks_clean "$pr" "$pr_run_id" "$head" "$branch" || die "PR #$pr has unclean runs"
  say "PR #$pr green: run $pr_run_id in ${pr_run_min}m"
  finish_prev                      # the previous merge must be green on develop before this one lands
  if [ "$(gh api repos/$R/pulls/$pr -q .draft)" = true ]; then
    nid=$(gh api repos/$R/pulls/$pr -q .node_id)
    gh api graphql -f query="mutation{markPullRequestReadyForReview(input:{pullRequestId:\"$nid\"}){pullRequest{isDraft}}}" -q .data.markPullRequestReadyForReview.pullRequest.isDraft | grep -q false \
      || die "could not mark PR #$pr ready for review"
    say "PR #$pr marked ready for review"
  fi
  gate_env=""; [ "$idx" = 0 ] && gate_env="ALLOW_ANCESTOR=1"
  git -C $FW fetch -q fork "$branch" || die "cannot fetch $branch"
  out=$(cd $FW && env $gate_env bash "$PREFLIGHT" "$head" 2>&1) || { echo "$out" | tail -5; die "pin gate FAILED on PR #$pr head ${head:0:9}: pins are split or not canonical"; }
  res=$(gh api -X PUT repos/$R/pulls/$pr/merge -f merge_method=merge -f sha="$head" -q '.merged,.sha' 2>&1) || die "merge of PR #$pr failed: $res"
  [ "$(echo "$res" | head -1)" = true ] || die "PR #$pr was not merged: $res"
  msha=$(echo "$res" | tail -1)
  say "merged PR #$pr -> develop ${msha:0:9}"
  git -C $FW fetch -q fork develop
  out=$(cd $FW && env $gate_env bash "$PREFLIGHT" "$msha" 2>&1) || { echo "$out" | tail -5; die "pin gate FAILED on merge commit ${msha:0:9}"; }
  read -r _ pk pkc _ dk dkc _ <<<"$(echo "$out" | awk -v s="$msha" '$1==s{print}')"
  prev_pins="\`$pk\` ($pkc) | \`$dk\` ($dkc) |"
  prev_prefix="| $idx | $label | #$pr | \`${msha:0:9}\` | [run $pr_run_id](https://github.com/$R/actions/runs/$pr_run_id) (${pr_run_min}m) |"
  prev_sha=$msha; prev_label=$label
done
finish_prev
say "ALL BLOCKS MERGED AND GREEN. receipt: $RECEIPT"
