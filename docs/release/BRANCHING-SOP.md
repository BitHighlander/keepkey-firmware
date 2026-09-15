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

## Freeze the upstream PR topology before auditing

Do this before an Astra or Copilot audit. The object being audited must already
have the same base, head owner, and merge topology that reviewers will approve:

1. Fetch both repositories and record immutable SHAs for fork `develop`,
   upstream `develop`, the release head, and both submodule pins.
2. Require fork `develop` to equal upstream `develop`. If it differs, preserve
   any fork-only commits on a named branch, then synchronize fork `develop`.
3. Base the canonical release branch on upstream `develop`, or merge the exact
   upstream `develop` SHA into an existing audited release head and audit that
   resulting merge commit.
4. Verify the live PR with `gh pr view`: base must be `develop`, the head owner
   must be the intended repository, and the returned `headRefOid` must equal the
   local candidate SHA. Never infer the PR owner from a same-named local ref.
5. Compare the final PR diff with the release ledger. Resolve merge conflicts
   and silent overlapping edits before spending review credits.

Fork and upstream branches with the same name are separate refs. Push using the
remote verified by the live PR's `headRepositoryOwner`, with a lease when a
non-fast-forward update is required. A rejected push is a stop condition: fetch
and inspect the new remote head before writing again.

For release-candidate review rounds, use [ASTRA-AUDIT-SOP.md](ASTRA-AUDIT-SOP.md)
before requesting Copilot or making a release decision.

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

## Traps that have actually bitten

**Branching from the fork's master when targeting upstream.** The fork's master
can be far ahead of upstream's, and a PR based on it carries that entire
divergence as if it were your change -- 33 files instead of 14, including an
unrelated submodule bump. Base on the upstream branch you are targeting.

**Fork-head PRs run the fork's CI.** A PR whose head lives on the fork runs the
fork's CircleCI config, which can be red for reasons unrelated to the change.
Push the branch to the upstream repo and PR from there.

**Auditing before the final develop merge.** Merging `develop` after a clean
review creates a new candidate and can introduce conflict resolutions, workflow
changes, or silent overlap damage that no prior review covered. Establish the
final PR topology first; every exact-head receipt and final review must name the
post-merge SHA.

**Same branch name, wrong repository.** `origin/release/7.15` and
`upstream/release/7.15` may have unrelated histories. Read the live PR's head
owner and OID before pushing. Do not force-update the other repository merely
because its ref has the same name.

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
