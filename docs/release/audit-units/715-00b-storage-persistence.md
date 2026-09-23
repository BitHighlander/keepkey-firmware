# Block 00b storage persistence finding — interim audit note

Status: **fix locally verified; Block 00b audit remains open**. Owner: Codex
`/root`, vault worktree `keepkey-vault-v11-agent-3`. The shared claim is
`docs/release/audit-claims/715-00b/OWNER.md` in the main firmware worktree.

## Identity and scope

- Code-bearing release PR: [#845](https://github.com/BitHighlander/keepkey-firmware/pull/845), `release/715-stack-00b-release-foundation`.
- Recorded adjacent base: `a9173b32eb8515db8130f0bd393bc9b249d83320`.
- Inspected PR head: `4c56e19e3070772a28b2890a4ec862ecf77d5429`.
- Adjacent diff: 104 paths, 16,831 additions and 1,585 deletions. `git diff --check` passed.
- This remediation is based on that head; it does not claim an audit of all 104 paths.

## Finding: serialized wallet lacks its activation marker

At the inspected head, `storage_commit()` called `storage_writeV17()` before
setting `shadow_config.meta.magic` to `STORAGE_MAGIC_STR`. A fresh wallet could
therefore serialize without the `stor` marker that `find_active_storage()`
requires on reboot. The same ordering is present at the adjacent base, so this
is an inherited defect exposed by Block 00b's newly enabled owned-emulator
power-cycle tests, not a defect introduced by the PR diff.

The exact-head [CI run 35685552583](https://github.com/BitHighlander/keepkey-firmware/actions/runs/35685552583)
failed in both full and Bitcoin-only Python integration jobs. Each JUnit
artifact recorded the same five `TestStorageUpgradePreservation` failures:
`no storage sector carries the b'stor' magic after a wallet was created`.
The report generation and both release gates consequently failed. Unit tests,
ARM builds, emulator builds, format, static analysis, and submodule checks
passed on that original head; this is not a green exact-head release run.

The local fix sets the marker in `shadow_config.meta.magic` **before**
`storage_writeV17()` serializes the record. This keeps the marker and its
checksum in the same committed byte sequence.

## Verification and remaining work

- Patched Docker firmware-unit suite: exit 0; 211 firmware, 16 board, and 18 crypto tests passed.
- Patched owned-emulator regression:
  `python3 -m pytest -q tests/test_storage_version_gate.py::TestStorageUpgradePreservation`
  in the pinned `python-keepkey` Docker image: **5 passed**.
- Patched full Python command reached the report-selected screenshot phase and
  stopped with **5 failed, 63 passed, 19 skipped**. Failures included two
  THORChain Ethereum deposit cases, two reset PIN cases, and one Solana token
  transfer case. It did not reach the later full integration phase; those
  failures need separate triage before Block 00b acceptance.
- The Bitcoin-only patched integration variant, exact-head CI, code-review
  checkpoint, physical-device checks, and the rest of the 104-path audit remain
  pending. No Copilot request was made.

The final master audit report and PDF required by the SOP must account for all
Block 00b behavior, tests, pins, skipped checks, and reviewed code-bearing
scope before any completion claim.
