# Block 00b storage persistence finding — interim audit note

Status: **reconciled fix locally verified; Block 00b audit remains open**. Owner: Codex
`/root`, vault worktree `keepkey-vault-v11-agent-3`. The shared claim is
`docs/release/audit-claims/715-00b/OWNER.md` in the main firmware worktree.

## Identity and scope

- Code-bearing release PR: [#845](https://github.com/BitHighlander/keepkey-firmware/pull/845), `release/715-stack-00b-release-foundation`.
- Recorded adjacent base: `a9173b32eb8515db8130f0bd393bc9b249d83320`.
- Inspected PR head: `4c56e19e3070772a28b2890a4ec862ecf77d5429`.
- Adjacent diff: 104 paths, 16,831 additions and 1,585 deletions. `git diff --check` passed.
- The review candidate is being replayed on accepted Block 00a head
  `9cb72384fd14b2a688a70d17711a7923941d2290`. The original #845 base is
  stale. This note does not claim an audit of all 00b paths.

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

The accepted 00a Python pin additionally recognizes an unframed record only
when the eight bytes after its 2572-byte payload remain erased (`0xff`). The
00b writer zero-filled these bytes. On the reconciled candidate, the same five
owned-emulator tests failed despite the marker fix. The candidate now leaves
those eight trailer bytes erased; all five focused tests pass. This preserves
the current unframed V17 format; adding a CRC envelope is separate format work.

## Verification and remaining work

- Patched Docker firmware-unit suite: exit 0; 211 firmware, 16 board, and 18 crypto tests passed.
- Patched owned-emulator regression:
  `python3 -m pytest -q tests/test_storage_version_gate.py::TestStorageUpgradePreservation`
  in the pinned `python-keepkey` Docker image: **5 passed**.
- With the original 00b Python pin and the release capability flags, the
  patched full variant passed 64 screenshot tests (23 skipped) and 559
  integration tests (271 skipped). These are supporting evidence for the old
  base and pin, not a final result for the reconciled candidate.
- The reconciled C-2 candidate passed 217 firmware, 20 board and 19 crypto
  native tests; full OLED 64/23 pass/skip and integration 559/272 pass/skip.
  Bitcoin-only passed 95 firmware, 20 board and 19 crypto native tests; OLED
  25/62 pass/skip and integration 334/497 pass/skip. The focused storage
  power-cycle suite passed all five tests after both storage fixes.
- Exact-head hosted [run 35921519743](https://github.com/BitHighlander/keepkey-firmware/actions/runs/35921519743)
  passed all required jobs on `f7cd316a499fbccdcfbcd0c532bffb6365e19474`.
  The report-only follow-up head still needs its own hosted result. Copilot,
  physical-device and release checkpoints remain pending.

The final master audit report and PDF required by the SOP must account for all
Block 00b behavior, tests, pins, skipped checks, and reviewed code-bearing
scope before any completion claim.

## Additional audit findings on the reconciled candidate

- **Opaque signed metadata display:** `ARG_FORMAT_BYTES` and `ARG_FORMAT_RAW`
  showed only the first 16 bytes followed by an ellipsis, then suppressed raw
  transaction review. The candidate now shows every byte in numbered 16-byte
  pages; both product builds and software matrices pass.
- **Amount formatting failure:** `bn_format()` returns zero and clears its
  output when the amount plus suffix exceeds the supplied buffer. The old
  screens ignored that result and could approve an empty amount. The candidate
  uses a larger buffer and refuses the flow if formatting or final screen
  assembly cannot represent the complete value. Both product builds and
  software matrices pass.
- **Bootloader scope conflict:** Block 00b originally changed the shared
  `signatures_ok()` implementation and Block 00a had directly edited
  `tools/bootloader/usb_flash.c`. The owner retained SRS C-2, “No bootloader
  changes in this release.” The reconciled candidate now restores the
  pre-foundation bootloader source, removes the shared F3 signature change,
  and makes bootloader/updater/bootstrap artifacts opt-in. The default release
  build excludes those artifacts. Both clean ARM builds and CI's artifact gate
  passed.
- **Dependency:** the reconciled crypto pin is
  `74908938c562ec89dcae9fb4e3b05ec3ff17f58b`, the head of upstream
  keepkey/trezor-firmware PR #12. It descends from both foundation pins, but
  upstream publication remains a dependency.
