# Branch and submodule SOP

Three branches, three jobs. Getting the submodule pins wrong is the main source
of tech debt here, and every rule below exists because something broke.

## The branches

| branch | what it is | submodules pin | review |
|---|---|---|---|
| **alpha** | fork integration. Everything lands here first. | **fork masters** | none needed |
| **develop** | staging for upstream. PRs from here go upstream. | commits that exist **upstream** | upstream review |
| **upstream master** | shipped | released pins | upstream |

Flow: `alpha` -> `develop` -> PR into upstream -> upstream `master`.

## The rule that prevents most of the pain

**alpha pins fork masters. Not commits, not feature branches.**

That is the point of alpha: because every pin is a fork master, alpha can always
be resolved without human review. A pin at a loose commit cannot be resolved by
anyone who does not already know which branch it came from, and the merge stalls
waiting for that person.

So when 7.15 work lives on a device-protocol feature branch, the fix is **not**
to pin that branch from alpha. Land the work on `BitHighlander/device-protocol`
master, then pin master.

Cost of getting this wrong, observed 2026-08-20: alpha pinned device-protocol
`cf308fd5e`, 32 ahead of fork master and 29 behind. Merging develop into alpha
then required a four-level reconcile -- firmware, python-keepkey,
device-protocol, and the lockfiles inside it -- before any 7.15 work could move.

## develop pins must exist upstream

A PR into upstream carries its submodule pins. If a pin exists only on the fork,
a reviewer cannot resolve the submodule and CI cannot check out the tree.

Two legitimate shapes on develop:

- a commit already on the upstream submodule's master
- the head of an **open upstream PR** for that submodule -- the dress-rehearsal
  pin, which merges once the firmware PR goes green

Say which one it is in the PR body.

### One canonical branch per dependency, never split

Owner rule, 2026-10-03. In a dress rehearsal, in every block PR, on every merge commit and on every
release branch, **every PR pins exactly the same upstream canonical branch for each dependency, at its
exact head**. Never split.

| dependency | canonical branch (upstream) | its single open PR |
|---|---|---|
| python-keepkey | `keepkey/python-keepkey` `reconcile/upstream-sync` | #197 into `master` |
| device-protocol | `keepkey/device-protocol` `up/release-protocol` | #112 into `master` |

1. **The head, not an ancestor.** A pin is the SHA at the head of that branch on the live upstream
   repository. An older commit on the same branch is not the dress-rehearsal pin, and neither is a
   prepared head that exists only on a fork, even though both can be fetched by SHA.
2. **The same SHA on every PR.** Block 1 and block 15 pin the same two SHAs. Version and capability gates
   in the dependency (`requires_firmware`, `requires_release_capability`) are what let one head serve
   every block. A block that "needs an older pyk" needs a gate in the dependency, not an older pin.
3. **One branch, linear history, fast-forward only.** When a block needs a newer dependency commit, the
   commit goes onto the canonical branch and every PR re-pins to the new head. It never gets a branch of
   its own: no `staging/...`, no per-block, per-release or companion branches, and no patch-equivalent
   copies of a commit. Two such branches existed on 2026-10-02 (`staging/716-b13-intent-review` and
   `staging/716-develop-20261001`) because blocks 13 and 14 pinned them; each cost a merge to put right.
4. **`.gitmodules` is identical on every ref:** url `https://github.com/keepkey/<dep>.git`, branch = the
   canonical branch name. Never the fork URL. (When the canonical PRs merge, one line per dependency
   changes the branch to `master`.)
5. **Bring the canonical branch up BEFORE any firmware PR is opened or merged, never after.** If it lags
   the pins, build one unified head by merging, never rebasing, so every earlier pin stays an ancestor.
   Prove it is a pure fast-forward of the upstream head. Get the owner's explicit approval, because the
   push updates an open upstream PR and notifies its reviewers. Push fast-forward only, then re-read the
   PR head and re-run the gate.
6. **Gate it.** `docs/release/rehearsal-tools/rehearsal-preflight.sh <ref>...` prints PASS only when the
   canonical PRs are the only open ones from their branches with heads equal to their branches, and every
   ref pins both heads exactly and has the canonical `.gitmodules`. Run it on every PR head right before
   its merge, on each resulting merge commit and on each release branch. Any FAIL stops the rehearsal.
   The single exception is the upstream base release PR (7.14.3 #475), whose pins are upstream's own and
   are checked with `ALLOW_ANCESTOR=1`.

What went wrong on 2026-10-02: six blocks were merged into fork `develop` pinning pyk ancestors
(`b47769e00` and others) while upstream PR #197 was 33 commits behind the pins and #112 was 10 behind. The
rehearsal was stopped, every block was re-pinned to the two heads, and the gate above was written.

## Traps that have actually bitten

**Branching from the fork's master when targeting upstream.** The fork's master
can be far ahead of upstream's, and a PR based on it carries that entire
divergence as if it were your change -- 33 files instead of 14, including an
unrelated submodule bump. Base on the upstream branch you are targeting.

**Fork-head PRs run the fork's CI.** A PR whose head lives on the fork runs the
fork's CircleCI config, which can be red for reasons unrelated to the change.
Push the branch to the upstream repo and PR from there.

**`--ours` / `--theirs` take the whole file.** They do not merge hunks. Taking a
side to settle one conflict silently reverts every other change in that file.
Re-verify the specific fix afterwards; this reverted a memo-length fix and was
caught only by grepping for it.

**A plain merge keeps non-conflicting hunks from both sides.** When two branches
implement the same thing differently, the result compiles and is wrong. List the
files touched by both, decide per file, then gate.

**Non-forced fetch refspec.** `git fetch <url> 'refs/heads/*:refs/remotes/origin/*'`
without a leading `+` silently skips non-fast-forward updates, so a stale local
branch stays stale and you read the wrong tree.

**Verifying against a ref you just moved.** After pushing a merge to `alpha`,
comparing `origin/alpha` to the merge compares it to itself and reports no
losses. Compare against the fixed pre-merge SHA.

**rerere replaying bad resolutions.** If a previous attempt recorded wrong
resolutions, the next merge reapplies them silently. Check `rerere.enabled` and
clear `.git/rr-cache` before retrying a merge you abandoned.

## Gate every reconcile, in both directions

A one-sided gate is worse than none, because it reads green. The rule that works:

> A symbol defined on the branch being merged INTO may be dropped only if
> nothing in the merged tree still references it.

plus an explicit list of markers from the branch being merged FROM. See
`ALPHA-MERGE-HANDOFF.md` for a working implementation. A hand-written gate that
only checked one direction passed while 95 symbols went missing.
