# Block 11a: shared board bootstrap in firmware unit tests

Date: 2026-09-28. Auditor: Codex /root. Source worktree: `/private/tmp/kk715-11a`. Target: fork branch `audit/715-stack08-10-agent3-integration` at `3a6f1cc2452c268908871958fe75abc5b3a2d54f` (Block 10, PR #876). Code generation predecessor: `781c75dc34357e4d828ca82c102f3e6f66264141`. The containing report commit and hosted qualification belong in the PR body. Main-worktree master template SHA256: `78d0fefefac9427057dc067cf4872d1240b53a7f5d68fa8c1cca18a1133d2f75`.

## 1. Scope and reconciliation

This is the first bounded consecutive unit after cumulative Block 11 PR #877 exhausted its authorized fourth review. Three cumulative rounds required code changes. The fourth review `5345445076` on `2c53776877d751311850228c59277ab4e6b26ac9` found one confirmed test-harness root in comments `4127698063` and `4127698158`. All five changed source paths here are assigned to 11a by `715-11-split-map-20260928.md` in the cumulative PR. No firmware product source, protocol, build policy or dependency pin changes in this unit. Later units contain Solana runtime, storage, entropy, crypto, Windows and validator behavior.

The predecessor's passphrase fixture calls `timer_init()` directly if the layout canvas is absent. The test board helper already guards a single `kk_board_init()` per binary. Both functions initialize the same static runnable queue; a later board bootstrap can relink those nodes and make the periodic queue walk hang. The unit changes the fixture to call `kk_test_board_init()`, introduces one local declaration header, and uses it in two other changed test translation units. `confirm_test_utils.cpp` retains its existing declaration until its entire response-harness change lands in 11f. The board implementation itself is unchanged.

Direct and nested submodules were initialized at the predecessor pins and checked clean. Direct pins: `code-signing-keys` a6470bd8598e5e9a7bfc38bf139a5e5a616f05ec; `deps/crypto/trezor-firmware` 8a392f70a5d5575ece3dfb35f115d4a4b27f497c; `deps/device-protocol` 5fec9e6906a340be5eb3d795ec746769065b2db8; `deps/googletest` 7888184f28509dba839e3683409443e0b5bb8948; `deps/python-keepkey` 41af909341965c81b8afadd38f299d6f929089af; `deps/qrenc/QR-Code-generator` 6dfbfdad5d9303ed190d1c3cb7bec34b565b6ce8; `deps/sca-hardening/SecAESSTM32` 71d356a1141624994cf613bd2d2583892e8e6d5a.

## 2. Finding and security closure

The sensitive state is the static timer runnable queue in the emulator test process. The observer is any later confirmation or periodic test and the consequence is a blocked test process, rather than a device output. The entry path is `PassphraseTransition::SetUp()` before `AppConfirm` or other board users. Both full and Bitcoin-only native variants execute that fixture and the shared helper. The allowed behavior is one board initialization and completed test execution; the forbidden behavior is direct timer initialization followed by board initialization and a circular runnable queue. No alternate encoding or product-wire output applies to this harness state.

The source negative control at Block 10 base confirms the direct `timer_init()` call. The repaired source removes that call and invokes the guarded helper. An exploratory old-binary shuffled run stalled intermittently, while repeats also passed; it is not represented as a deterministic negative test. The fixed full and Bitcoin-only suites and passphrase-first shuffled tests are executed positive assertions. The two review comments share this root and are not counted as separate defects. The unrelated macro-recursion claim in comment `4127698115` was refuted on the cumulative PR because the macros are undefined before the wrapper definitions; reply `4127753705` and its resolved thread preserve that disposition.

| Contract | Full | Bitcoin-only | Evidence |
| --- | ---: | ---: | --- |
| Native firmware suite | 669 pass, 0 fail/error/skip | 143 pass, 0 fail/error/skip | Raw XML and logs in archive |
| Passphrase then confirmation under Google Test shuffle seed 1 | 2 pass | 2 pass | Shuffled logs in archive |
| Base source negative control | Direct timer call present | Same source | Manifest and predecessor source |
| Fixed source control | Guarded helper used; no direct timer call | Same source | Code predecessor and manifest |

The seven-member archive `715-11a-controls-20260928.tgz` has SHA256 `6549cef4b975cf75f9040faa03b892fde543ca27c8b5268bc20939bb79b0e6da`. Its manifest binds six raw files, the exact base, code commit, outcomes and source control. Full and Bitcoin-only binaries were built independently from the five-file unit checkout using the pinned Linux emulator toolchain. Hosted CI remains a separate exact-head gate; physical device execution is not claimed.

## 3. Local and external checkpoint

Local implementation and targeted/integration verification pass for the bounded harness defect. The source negative control distinguishes the old direct initialization from the fixed guarded path; the historical stall was intermittent and is not overstated. The pre-push `scripts/preflight.sh`, hosted CI, final report/PDF and exact PR head will be recorded after report freeze. No 11a Copilot review has been requested yet; its fresh budget is three rounds. The cumulative review verdict remains Changes recommended and is not relabeled as a pass. No release or physical-device acceptance is claimed.

## 4. Complete adjacent Git inventory

Inventory base: `3a6f1cc2452c268908871958fe75abc5b3a2d54f`. First containing report predecessor: `38a42ea4946dbc81cd902e813c3cb7645bd09bf3`. The final inventory below includes this corrected report and PDF; reproduce from the immutable base to the final head recorded in the PR body with `git diff --numstat 3a6f1cc2452c268908871958fe75abc5b3a2d54f..FINAL_PR_HEAD`. The first report commit's `base..38a42ea4946dbc81cd902e813c3cb7645bd09bf3` inventory was regenerated because the report source grew to include this table. Binary counts use Git's dash.

| Added | Deleted | Path |
| ---: | ---: | --- |
| - | - | `docs/release/audit-units/715-11a-controls-20260928.tgz` |
| 45 | 0 | `docs/release/audit-units/715-11a-test-board-bootstrap-20260928.md` |
| - | - | `docs/release/audit-units/715-11a-test-board-bootstrap-20260928.pdf` |
| 1 | 2 | `unittests/firmware/app_confirm.cpp` |
| 2 | 7 | `unittests/firmware/storage_passphrase.cpp` |
| 4 | 3 | `unittests/firmware/test_board.cpp` |
| 4 | 0 | `unittests/firmware/test_board.h` |
| 2 | 2 | `unittests/firmware/usb_rx.cpp` |
