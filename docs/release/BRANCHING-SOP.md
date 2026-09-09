# Branch and submodule SOP

## Current release rehearsal authority

For the 7.14.2, 7.14.3 and 7.15 program,
[REHEARSAL-SOP.md](REHEARSAL-SOP.md) governs. The older direct alpha → develop
flow is superseded for this program. Develop remains frozen and unmerged.

| Surface | Purpose | Dependency identity |
| --- | --- | --- |
| alpha | Existing fork integration and source evidence | Record exact source and gitlink SHAs before extraction; do not advance dependencies merely to follow a branch. |
| Canonical fork release branches → fork develop | Cumulative release products | Exact reachable pins, dependency delta review and validated assembly receipts. Fork-only pins are allowed during internal rehearsal. |
| Small fork audit branches → frozen predecessor | Bounded review and remediation | Exact base/head and pins; independent units may target fork develop. |
| Final upstream-shaped fork branches | Later external review and submission preparation | Verify public dependency availability and upstream requirements before submission. |

A git submodule always records a commit. Record its repository and reachable
source ref as provenance; a moving branch name never substitutes for the SHA.
Internal hardening does not require merging dependencies into fork master or
opening upstream dependency PRs. Resolve public dependency requirements during
the final upstream SOP. No upstream push, develop merge or Copilot request is
a prerequisite for internal staging or assembly.

## Traps that have actually bitten

**Branching from the fork's master when targeting upstream.** The fork's master
can be far ahead of upstream's, and a PR based on it carries that entire
divergence as if it were your change -- 33 files instead of 14, including an
unrelated submodule bump. Base on the upstream branch you are targeting.

**CI context matters.** Inspect the workflow, repository, event and exact head
that produced a result. Resolve fork validation problems within the fork staging
program; do not push upstream as a workaround. External CI requirements belong
to the final upstream phase.

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
