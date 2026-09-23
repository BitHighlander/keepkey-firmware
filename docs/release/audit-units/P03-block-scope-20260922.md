# P03 Block 3 — frozen scope and completed local evidence (7.15)

Status: local audit evidence completed; this is the finite-batch contract and
local receipt, not final release acceptance. Worktree `audit/715-p03-final-review` begins at
`92f3d00f2b75c1fe02ba3a00a7ea46b4e163c31e`, the reviewed Block 2 head.
Its firmware source is `audit/715-scope-repair` at
`614425a2a14d0113de251e7944118e47f31f5265`. The canonical product
`release/7.15` remains separately at `af979cd5099349ba58ec10d1b7eedeb67662c602`.
These were checked against the fork on 2026-09-22. No product branch is
advanced by this unit.

## Selected behavior and invariant

Review the retained P03 setup authorization, secret cleanup, recovery display,
storage decoding/migration, and emulator erase behavior in the current
candidate. A setup commit must require the live ceremony, public strings must
be bounded and terminated, temporary PIN/wipe-code buffers must be erased,
recovery screens must not reuse previous word text, and migration/rotation
tests must exercise the shipped policy. A historical unit's presence in
ancestry alone is not proof that its behavior survived later changes.

The scope-repair correction is binding: no bootloader change, no persistent
marker redesign, no new storage framing, and no pending-record preservation
replay. The inherited erase-before-replacement power-interruption issue remains
**open and deferred outside this batch** under the release owner's correction.
This audit will not call it fixed, waived, or safe. The separately documented
unknown-version policy is deliberate downgrade erasure, with the Bitcoin-only
band refusal kept distinct.

## Historical unit inventory

Every SHA below is an ancestor of the frozen candidate. Counts are per-commit
`git show --format= --numstat <sha>` additions/deletions, including tests and
submodule pointers, and are not a net candidate diff.

| Unit | Commit | + / - | Current disposition |
| --- | --- | ---: | --- |
| Live setup commit authorization | `8ac4bd9dfd` | 23 / 7 | Retained; inspect later ceremony interactions. |
| Dice backup collector host pin | `2b891ceb8b` | 1 / 1 | Historical pin superseded; verify behavior in current Python pin. |
| Bounded stored public strings | `32df2a9aca` | 22 / 5 | Retained; inspect current/legacy load paths. |
| Emulator erase on sector rotation | `c2197307be` | 25 / 2 | Retained explicitly by scope repair. |
| PIN and wipe-code scratch cleanup | `b73f7a5f75` | 19 / 8 | Retained; inspect all exits. |
| Previous-word display cleanup | `f8c5692b31` | 2 / 1 | Retained; inspect screen lifetime. |
| Setup staging and foreign-commit regressions | `2e1c67e9ec` | 30 / 9 | Retained tests; confirm registration and execution. |
| Recovery backspace display | `1ead40605f` | 19 / 1 | Retained; inspect boundary transitions. |
| Bitcoin-only migration status test | `77f50c0162` | 4 / 2 | Retained; confirm test executes on selected variant. |
| Durable V17 replacement | `b9b88955fa` | 40 / 3 | Withdrawn by `bd5e509cd`; do not replay. |
| CRC-aware framed migration fixture pin | `0307ca0ae7` | 1 / 1 | Historical durability evidence; does not certify current unframed format. |
| Bootloader replay snapshot test | `e8fe34811b` | 17 / 0 | Withdrawn as durability-specific evidence. |
| Incompatible pending-record lock | `06b1d249ad` | 35 / 1 | Withdrawn by scope repair; current unsigned version classification is separate. |

The scope repair `bd5e509cd` reverted the bootloader-coupled storage batch,
while preserving the emulator erase correction and the unsigned `uint32_t`
version classifier with its regression. Later storage and recovery changes in
the candidate must be reviewed as interactions rather than assumed identical
to these historical unit heads.

## Frozen dependency pointers

| Dependency | Candidate pin |
| --- | --- |
| `code-signing-keys` | `a6470bd8598e5e9a7bfc38bf139a5e5a616f05ec` |
| `deps/crypto/trezor-firmware` | `8a392f70a5d5575ece3dfb35f115d4a4b27f497c` |
| `deps/device-protocol` | `27d3fa1f6215139cde6411f9a2882f36bb373fc9` |
| `deps/googletest` | `7888184f28509dba839e3683409443e0b5bb8948` |
| `deps/python-keepkey` | `b76ee610dd18934ee3aeeb36cfc541e8799eb46d` |
| `deps/qrenc/QR-Code-generator` | `6dfbfdad5d9303ed190d1c3cb7bec34b565b6ce8` |
| `deps/sca-hardening/SecAESSTM32` | `71d356a1141624994cf613bd2d2583892e8e6d5a` |

## Acceptance checks before final review

1. Trace each retained behavior and every relevant later edit in the current
   source. Give a stable disposition to any concrete finding. Treat the open
   power-interruption issue as a declared scope exclusion, not a clean result.
2. Verify test registration and actually executed full/Bitcoin-only native,
   board, host storage power-cycle, and migration cases; inspect skips. Check
   the pinned Python companion for the dice and storage fixtures.
3. Run focused controls for any new fix, then full candidate native/host and
   ARM/SRAM checks as required by the rehearsal SOP. The passed run
   [34951131013](https://github.com/BitHighlander/keepkey-firmware/actions/runs/34951131013)
   is earlier firmware-equivalent evidence at `7e091af15`, not an exact-head
   pass for the later CI workflow refactor or this review branch.
4. Produce the SOP audit report and PDF with exact PR diff, per-change line
   counts, plain-language behavior descriptions, finding dispositions, CI
   artifact identities, and remaining physical-device/release gates.
5. Once the report and local checks converge, obtain a Copilot review of the
   frozen final head, resolve actionable findings, and require a new review
   with zero findings and zero unresolved threads before marking that
   checkpoint successful.

This unit makes no firmware change or release promotion. Its Copilot request
and delivered findings are tracked on PR #851; the final checkpoint requires
a fresh clean review of the corrected head.

## Initial evidence check (2026-09-22)

The current source still registers `setup_ceremony.cpp`, `storage.cpp`, and
`storage_passphrase.cpp` in the firmware native target and `board.cpp` in the
board target. The earlier firmware-equivalent CI run 34951131013 produced
`unit-test-results-full` (artifact `10388679573`) and
`unit-test-results-bitcoin-only` (artifact `10389512420`). Their JUnit XML
records, in **both** variants, nine executed `SetupCeremony` cases, the
`VersionedReadersTerminateStoredStrings`,
`FutureBitcoinBandValuesNeverFallThroughToWipe`, and
`StagingIsInertAndForeignCommitAborts` cases, plus the board
`EmulatorEraseClearsOnlyTheSelectedStorageSector` case. This verifies test
execution on that earlier code-equivalent head; it is not an exact-head result
for the current workflow files.

The host `python-test-results` artifact (`10390030970`) records passing cipher
recovery, backspace, reset and dice cases. It also records **five skipped
`TestStorageUpgradePreservation` power-cycle cases**, including wallet
preservation, Bitcoin-only band refusal, V16 upgrades and unknown-version
wiping, because that host image has no emulator binary it owns and can restart.
This is a concrete Block 3 evidence gap, not a pass. The source-only version
gate checks ran, but they do not replace next-boot behavior. The audit must
run an owned-emulator power-cycle suite or carry this as pending before final
Block 3 acceptance.

## Owned-emulator closure and source disposition (2026-09-22)

The five skipped host CI cases above were subsequently run in an emulator image
built from this review worktree with the exact pinned candidate code and
submodules. The full image is `sha256:18f7375986270c6bdcea6155e9fe8382d5a4faca8f0466ff3bf727b759a2e9f3`;
the Bitcoin-only image is `sha256:12d356b3912a0e7f76923db50368ee66e979fed3935174b6084726090a8f99db`.
Both ran `python3 -m pytest -q deps/python-keepkey/tests/test_storage_version_gate.py -k TestStorageUpgradePreservation`
with `KK_EMULATOR_BIN=/kkemu/bin/kkemu`: **5 passed, 11 deselected** per variant.
The five passed cases cover Bitcoin-only band refusal without wiping, reboot
wallet preservation, framed and unframed V16 upgrade without wiping, and
unknown-version wiping. Full and Bitcoin-only JUnit SHA256 values are
`af033f9ec59d0f5cab3404fd41ee3a1c505bc6bc71564a56271dee1c1b8be4d5`
and `ea0d0bf20441dbde6cef95037400de4586aa616b3e9273ed1c7f003c34968eac`.
Thus the earlier **skip is closed by a separate executed result**, while its
historical CI artifact remains accurately described as skipped.

`make xunit` passed inside each image. The full variant passed 573 firmware,
17 board, 18 crypto, and 6 Pallas constant-time tests; Bitcoin-only passed
131 firmware, 17 board, and 18 crypto tests. Complete log SHA256 values are
`5a452156d0b2264f480ac5d640e388e1ea9ab10bf57783751bcde2fbe947459d`
and `4509a2ef1d05d5cdfa21401a6350fd562a48b1b6e69be3dcb14f211ee25ff49e`.
The artifacts are retained locally in `/private/tmp/kk-fw-715-p03-owned-evidence`.

Current-source review traced setup state and commit authorization in
`lib/firmware/reset.c`, temporary secret cleanup in `pin_sm.c`, previous-word
and backspace rendering in `recovery_cipher.c`, unsigned version classification
and bounded stored-string decoding in `storage.c`, and sector-limited emulator
erase in `lib/board/keepkey_flash.c`. The corresponding native tests are
registered and executed in both variants. No new **in-scope** product defect
was identified. The inherited erase-before-replacement power-interruption
risk remains **open and deferred**, not fixed or waived. Physical OLED behavior,
signed hardware upgrade, and exact later CI workflow acceptance remain
release gates beyond this Block 3 receipt.
