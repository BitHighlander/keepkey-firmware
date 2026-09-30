# Block 11: runtime Solana signing and complete-block review remediation

## 1. Identity and finite scope

Reviewer: Codex /root in keepkey-vault-v11-agent-1, with parallel implementation and evidence review. Source checkout: /private/tmp/kk715-stack11-run3. Firmware PR: https://github.com/BitHighlander/keepkey-firmware/pull/877. Head branch: audit/715-stack11-agent1-20260927. Target: fork develop, fc1e93746132553ad98ed60f4847c8d770732bf9.

This report records the Block 11 candidate synchronized with Block 10 on 2026-09-28. The cumulative PR targets develop, so predecessor code is visible in that review. Block 10 final head 3a6f1cc2452c268908871958fe75abc5b3a2d54f is integrated by merge 355711281d98313823acbfb99694fd470115cf45. Its three commits after bfe6cb207 change only the Block 10 audit source, PDF and handoff wording. The synchronized head 2c53776877d751311850228c59277ab4e6b26ac9 passed exact-head CI; the fourth review then found an order-dependent unit-test bootstrap defect. The repair changes test fixtures only. Product firmware, protocol definitions, dependency pins and build policy retain their qualified content. The containing head and hosted status are bound in the PR receipt after report freeze.

Scope includes runtime schema v1/v2, eight v2 argument slots, signer-bound token metadata, exact instruction coverage, bounded plain-text raw message signing, AdvancedMode/session trust, ordinary consent, and every finding raised by the complete-block reviews. Certified roots, delegate certificates, LUT proofs and production publication remain outside runtime 7.15 scope. No release or physical-device acceptance is claimed.

The canonical main-worktree SOP and master template were read at intake. Their hashes, exact dependency identities and authorization are recorded in the adjacent review-control archive. Python remains aae89d378d889b3872696469fe363cf570e5ac4c (companion PR #122); it retains the Block 10 Python ancestry. Every direct and nested dependency was restored at its pin and checked clean before qualification.

The owner authorized three review rounds per block and recursive consecutive splits after three rounds requiring code changes, then explicitly authorized one additional cumulative request. All four cumulative requests have been used. Rounds one, two and four required repairs; round three required no code change and was technically declined with evidence. The split trigger is met. The bounded consecutive units and exact path ownership are recorded in `715-11-split-map-20260928.md`. PR #877 remains the cumulative integration view; no fifth request on it is authorized or sent.

## 2. Source reconciliation and review coverage

Historical PR #841 is retained as provenance. Its live historical head/base differ in four files despite an earlier tree-empty retirement note; four core functions and relevant tests were already inherited from the accepted predecessor. This complete-block PR exposes that implementation against develop. The audit does not treat the retirement note or an old receipt-only review as code-review proof.

| Behavior | Code-bearing paths | Property evidence |
| --- | --- | --- |
| Schema v1/v2 parser, typed widths and exact data/account binding | solana.c, solana.h, native Solana tests | Canonical/v2 and all-prefix truncation tests, safe labels, coverage and account mismatch cases |
| Runtime trust and same-signer token mint metadata | fsm_msg_solana.h, signed_metadata.c, pinned Python | Runtime schema/attestation wire cases, valid token review, invalid signer/signature/mint controls |
| Malformed input rejected before schema consent | fsm_msg_solana.h, pinned Python | Original S11-01 baseline reaches consent; repaired trailing/truncated forms reject before buttons/signature |
| Plain-text message and session policy | solana.c, fsm_msg_solana.h, fsm_msg_common.h | Printable/control-byte and key-scan checks, policy/refusal, Initialize and ClearSession contracts |
| Newer-storage creation and persistent-setting refusal | fsm.c, fsm_msg_common.h, storage API comments, fsm.cpp | Actual USB handlers after real future-version flash load, creation/settings/authenticator guards, preserved wipe and continuation behavior |
| Trusted OTP entropy before boot continuation | keepkey_flash.c, hardware-branch board probe | RNG failure, failed/partial programming, readback and lock failure; existing locked entropy and healthy fresh boot controls |
| Identity/cipher secret cleanup before response | fsm_msg_crypto.h, crypto_cleanup.cpp | Real direct and USB handlers, independent signature/ciphertext vectors, signing/derivation failure and cancellation |
| Windows timer and host RNG portability | timer.c, rng.c, Windows DLL target | Boundary arithmetic controls and MinGW compilation of the supported shared-library target |
| Validator platform/headers and file I/O boundary | tools/erc7730-validate, CMake execution registration | Actual CLI valid/malformed/file-error/capacity tests; original-input negative control |
| Earlier review repairs | scanner policy, crypto/emulator/test CMake | Preserved tracked-dependency detection, full/BTC source boundary, libc fallback and 72-case Zcash coverage |
| Updated Block 10 predecessor | ethereum.c, fsm_msg_ethereum.h, stack10 wire module, report generator | Canonical total-length guard; padded-zero consistency; full/BTC required contract cases |

The cumulative inventory includes inherited code, tests, dependency-pointer lines, workflows and evidence. Historical commit counts overlap and are not summed as a net diff. Added tests are registered in CMake or in the required xunit target; no predecessor test or assertion was removed. The hardware entropy probe explicitly compiles the real device branch while replacing only hardware side effects; it is not a physical-device execution.

## 3. Findings and dispositions

Original S11-01 remains fixed: malformed Solana transactions cannot enter runtime-schema consent. The initial five review findings (5333270562 on f388155ce0b8) remain dispositioned with their immutable evidence. The tracked-dependency secret exemption was removed, Pallas/Zcash units were gated by product, fallback libc source paths were corrected and a redundant test target removed while all 72 actual Zcash cases remained in the required full suite. The alleged total absence of those tests and duplicate compiled full objects were not reproduced; their precise outcomes remain recorded in the earlier archive.

Second review 5333740490 on 8cd5561a2 delivered eight inline comments, seven high and one medium, despite inconsistent overview prose. All inline comments and the complete body were read; no extra concrete body-only finding was identified.

| Comment | Disposition and class analysis |
| --- | --- |
| 4118361256 and 4118361320 | Confirmed one storage root cause. Future-format flash resets the RAM shadow while storage_commit refuses writes. The shared guard now refuses creation, persistent settings and authenticator Ping before prompting or staging. Existing Bitcoin-only refusal codes and explicit WipeDevice remain. Tests use real flash loader plus USB decoder, not a forced lock flag. |
| 4118361277 | Confirmed failed first RNG draw could flow into erased OTP consumption. Boot now scrubs and halts before continuation. The adjacent class also verifies programming by readback before permanent locking, verifies the actual lock, and refuses read failures. OTP wrapper success alone is not trusted as proof of successful programming. |
| 4118361337 | Local handler cleanup was missing. Normal USB dispatch already cleared shared scratch afterward, so retention until an unrelated later request was overstated. SignIdentity now clears before success/failure output; CipherKeyValue in the same handler family clears on cancellation and after key use, including derived HMAC/AES material. Established signatures and ciphertext remain unchanged. Independent generic-Ed25519 verification exposed an uninitialized recovery-prefix byte in cryptoMessageSign; it now initializes to zero because Ed25519 does not supply an ECDSA recovery identifier. |
| 4118361301 | The baseline MinGW object compiled because unistd.h was still present; the precise undeclared-usleep claim did not reproduce. The Windows branch now uses explicit Sleep with overflow-safe rounding; POSIX declarations stay on POSIX. The complete DLL build exposed an undeclared BCryptGenRandom/PUCHAR/ULONG path; random32 now delegates to the existing Windows/POSIX host CSPRNG provider, preserving fail-closed behavior. |
| 4118361360 | Baseline native object compilation succeeded through the tracked include/trezor/crypto symlink. The target now also names its crypto include directory explicitly; the tracked symlink remains available. Actual CLI compilation and execution verify the resulting target. |
| 4118361390 | The validator linked the POSIX socket emulator on Windows. It is now excluded there, matching the supported socket-free Windows DLL build; native full firmware still builds and executes the validator. |
| 4118361413 | Confirmed fread/feof boundary error. One-byte lookahead distinguishes exact capacity from oversized input, and ferror is handled separately. Exact-capacity bytes now reach the firmware parser; this does not expand the parser's own program limit. |

Security closure contracts and independent falsification results appear in the next section and adjacent evidence. Technical corrections to review wording do not erase the delivered Changes recommended verdict.

Third review 5344049267 on 12f1047da347fec09a700de0154aa88d7352977f reported Changes recommended with one P1 (comment 4126567194): Bitcoin-only allegedly compiles ethereum_tokens.c with TOKENS_COUNT=0. The premise is false: lib/firmware/CMakeLists.txt includes that source only inside if(NOT ${KK_BITCOIN_ONLY}); both product variants passed hosted qualification. Technical reply 4126576636 documents the source and build evidence. The 14 threads through round three were resolved; the verdict remains preserved.

Fourth review 5345445076 on 2c53776877d751311850228c59277ab4e6b26ac9 reported Changes recommended with three inline comments. Two comments (4127698063 and 4127698158) identify one confirmed root: a passphrase fixture called timer_init() directly, bypassing guarded board setup and allowing order-dependent double initialization. The repair uses kk_test_board_init() and a shared declaration. Comment 4127698115 is refuted by the probe's macro undef boundary before the wrapper bodies; technical reply 4127753705 is posted and its thread resolved. The two repair threads remain open until pushed qualification and replies. All three comments and the generic overview are dispositioned in `715-11-round4-20260928.md`. No additional concrete body-only finding was identified.

## 4. Security contracts and falsification

| Sensitive state/origin and observer | Allowed / forbidden behavior | Executed paths and counterexamples |
| --- | --- | --- |
| Future-version stored wallet; host and user; both products at boot/setup | Preserve flash; no staged replacement, prompt or success implying persistence. Explicit confirmed wipe may clear it. | Normal future versions, 9999, incompatible BTC versions and UINT32_MAX; Load/Reset/Recovery, settings, authenticator prefixes, stale continuations, read-only calls, cancelled wipe, confirmed wipe and persistent restart. Original guard overlay must fail relevant refusal cases. |
| Hardware RNG and OTP bytes; boot/DRBG/storage; both product macros | Only verified fresh bytes or readable previously locked bytes reach initialization. Failure must halt without consuming erased/partial bytes. | Actual device branch with mocked registers/OTP/RNG/halt: RNG, write, partial write, read, lock failures and valid neighbors. Baseline source overlay must violate the failed-draw/readback contracts. Physical fault injection remains unexecuted. |
| Derived identity/cipher node and key schedule; host response and handler return; both products | Emit the requested valid signature/ciphertext only after consent; scrub confidential scratch before response and on all post-derivation exits. | Direct and USB entry, HTTPS/SSH/GPG vectors, invalid digest lengths, derivation error, cancellation, encryption/decryption and same-session continuation. Baseline handler overlay distinguishes local cleanup from the existing dispatch backstop. |
| Host program bytes/file errors; CLI consumer; native full | Correct file-boundary classification, explicit I/O error, actual firmware parser refusal for invalid programs. | Valid independent fixture, truncation, trailing bytes, bad magic, empty/missing files, directory read error, capacity minus/at/plus one and far oversized. Baseline exact-capacity test fails. |
| Windows delay input and host entropy; emulator process | No arithmetic overflow or unsupported POSIX RNG/socket dependency in the supported DLL. | Zero/submillisecond/millisecond/UINT32_MAX delays with intercepted Sleep; delay callbacks and actual cross compilation. This does not claim Windows scheduler timing or physical-device entropy equivalence. |

Crypto runtime assertions inspect shared HDNode scratch at handler return and verify emitted values. Cleanup before response and HMAC/AES stack wiping are established by source-path review; those transient stack bytes and the instant before msg_write are not instrumented. The separate remediation review checks failure ordering, equivalent encodings, caller defaults, release variants and preservation of previous guards. Closure depends on asserted properties and baseline controls; totals and hashes alone do not prove them.

## 5. Verification and remaining gates

| Check | Result and scope |
| --- | --- |
| Full native, clean runtime directory | 706 firmware + 26 board + 18 crypto = 750 pass, zero failures/errors/skips; includes 30 future-storage cases, 7 crypto cleanup cases, 7 hardware-entropy cases and all 72 Zcash cases. |
| Bitcoin-only native, clean runtime directory | 174 firmware + 26 board + 18 crypto = 218 pass, zero failures/errors/skips; includes 24 future-storage cases and the same 7 crypto/7 entropy cases. |
| Full focused host/wire | 64 pass, 14 explicit feature skips; runtime Solana, identity/cipher and Block 9/10 contracts. All nine updated Block 10 cases pass. |
| Bitcoin-only focused host/wire | 7 pass, 71 explicit product/feature skips; identity/cipher and authenticator remain available; Solana/EVM excluded. |
| Storage negative controls | Original guard overlay fails 9/30 full and 8/24 BTC cases; fixed/restored 30/30 and 24/24 pass. An initial stale-object attempt was rejected as evidence; effective controls force/recheck FSM recompilation. |
| Entropy negative controls | Seven fixed cases pass in each product macro; original source fails five of seven. Real device entropy branch, mocked peripheral/OTP/halt operations. |
| Crypto negative controls | Seven fixed cases pass; original handler overlay fails five cleanup cases; poisoned recovery identifier fails the independent generic-Ed25519 prefix assertion. Direct and USB output vectors are verified. |
| Validator file/CLI | 12 actual-CLI tests pass via custom target and CTest; original main fails exact-capacity/read-error cases while ten neighboring cases pass. |
| Windows portability | Supported DLL cross-build passes; original validator target fails on BSD socket headers, original RNG branch fails declaration compilation. Timer boundaries and runnable/callback controls pass; original branch fails the Sleep expectation. No Windows runtime execution is claimed. |
| Report/preflight regression units | 30 pass. Disposable test commit/tag signing disabled only in process environment to avoid local GPG side effects; actual candidate commits remain signed. |

Local binaries were compiled from the material source content frozen as 36d9f32f0daac85d3baa68996e0c59112dffbf74. Build-time Git labels can name its f0977b81d generation predecessor; code/pin content and source snapshots are recorded separately. These local results are not labeled as hosted exact-head execution. Full raw results, skipped identities and baseline failures are preserved in the adjacent evidence archive.

Archive: `715-11-review2-controls-20260928.tgz`; SHA256 `43db28ac4e82946c80f89172e1268cfa971c833047866f7ad411ab5b572a3317`. Every archived member is hash-verified.


Manual CI 36473918905 passed on 12f1047da347fec09a700de0154aa88d7352977f: full aggregate 1565 pass, 84 declared skips, zero failures/errors, with both native products, wire contracts and ARM/resource gates verified. Independent run metadata, source and Python pin, all eight contract inputs, JUnit/PDF, OLED and ARM receipts were checked; nine tampering controls rejected. The synchronized head 2c53776877d751311850228c59277ab4e6b26ac9 passed exact-head manual CI 36490566360 with the same aggregate and all required jobs. After the fourth review's test-fixture repair, local full and Bitcoin-only firmware suites passed 706 and 174 tests respectively, with zero failures/errors/skips. Their raw XML/logs and hash manifest are in `715-11-round4-controls-20260928.tgz`. Exact-head manual CI 36495672196 passed on code repair 95d8460f49e548f614665dea13d6a7aee9924ccb, and CI 36497414699 passed on documentation head 96771bc4b0d548b37960fb83041bdb92adab62ed. Each had 1,565 pass, 84 declared skips and zero failures/errors; downloaded source, Python pin, JUnit/PDF, OLED and both ARM receipts independently verified, with nine tampering controls rejected. Both pre-push preflights passed. A later split-map-only containing head may carry this code evidence with its empty code/pin/configuration diff and a new post-edit preflight; the PR receipt records its exact identity.

The ordinary develop-based PR event has an incompatible absent capability ledger. The previously owner-approved manual authority remains accepted-7b authority commit 2483977523d9b6beab52a69429ace9aeefd00f76. Manual qualification uses that authority with publishing disabled and retains the negative control rejecting waiver expansion. No repository setting or candidate waiver was broadened in this round.

Physical buttons/OLED, actual power interruption, signed-device upgrade, assembled-release integration, merge and publication remain separate gates. Unit and emulator evidence is explicitly labeled. Later 7.16 certified Solana tests retain their named exclusions; runtime 7.15 owned behavior is executed rather than hidden by a later-capability skip.

## 6. Report and review checkpoint

The source/PDF inventory is generated from an immutable explicit range. Every final path and addition/deletion count is checked against Git; binary PDF/archive counts are shown as Git's dash. The PDF is rendered from this source and visually inspected. The adjacent archive preserves commands, source hashes, positive and negative results and review baseline, with a manifest verifying every member.

The post-edit scripts/preflight.sh passed on the repaired code and first split-map correction. Local native, host and report checks preceded the hosted matrix. A report-only containing commit may carry code evidence forward only with a proven empty code/pin/configuration diff. Final source/CI status is reported independently from Copilot freshness.

Review snapshot: four cumulative requests delivered (5333270562, 5333740490, 5344049267, 5345445076), three code-change failures, zero open threads after repair replies and hosted qualification. No clean Copilot verdict is claimed. The owner-authorized split assigns each changed path and finding to one bounded unit with a fresh three-round budget; an additional two-path CI prerequisite 11p now precedes firmware-test unit 11a. The initial 11a manual run 36498543553 exposed inherited no-git scanner and report-event test prerequisites before builds. Those exact paths are extracted unchanged from this cumulative tree into PR #880; its old/fixed controls and local preflight pass. Historical reviews used Lite; no setting change is claimed. Current CI and review outcomes belong in the PR receipt and main audit ledger with exact SHAs.

The prior readiness sign-off applied to the pre-review head. The fourth review reopened one test-bootstrap issue, now repaired and qualified on the cumulative head. Block 10 ancestry, product source, build configuration and dependency pins remain qualified. Local cumulative acceptance is recorded separately from Copilot: the fourth verdict is Changes recommended and triggered the consecutive split. Each bounded split unit requires its own review checkpoint before the full Block 11 external review contract is complete.

## 7. Complete cumulative Git inventory

Inventory base: fc1e93746132553ad98ed60f4847c8d770732bf9. Integration anchor: 355711281d98313823acbfb99694fd470115cf45. Final material source: 36d9f32f0daac85d3baa68996e0c59112dffbf74.

This inventory describes the containing report tree, including its own final line count; the containing SHA is recorded in the PR receipt. Reproduce with `git diff --numstat fc1e93746132553ad98ed60f4847c8d770732bf9..FINAL_HEAD`. Product firmware, protocol definitions, dependency pins and build policy remain identical to qualified head 2c53776877d751311850228c59277ab4e6b26ac9; the test fixtures contain the fourth-review repair.

| Added | Deleted | Path |
| ---: | ---: | --- |
| 1 | 2 | `.gitattributes` |
| 755 | 587 | `.github/workflows/ci.yml` |
| 8 | 8 | `.github/workflows/mirror-base-image.yml` |
| 275 | 69 | `.github/workflows/release.yml` |
| 6 | 0 | `.gitignore` |
| 20 | 0 | `.gitleaks.toml` |
| 9 | 0 | `.gitleaksignore` |
| 3 | 3 | `.gitmodules` |
| 65 | 4 | `CMakeLists.txt` |
| 1 | 0 | `cmake/caches/device.cmake` |
| 40 | 0 | `cmake/toolchains/mingw-w64-x86_64.cmake` |
| 13 | 0 | `deps/crypto/CMakeLists.txt` |
| 1 | 1 | `deps/crypto/trezor-firmware` |
| 1 | 1 | `deps/device-protocol` |
| 1 | 1 | `deps/python-keepkey` |
| 192 | 0 | `docs/DiceEntropy.md` |
| 154 | 0 | `docs/dice-vs-coldcard.md` |
| 94 | 0 | `docs/firmware/reviews/7.15.0-review-round2-remediation.md` |
| 124 | 0 | `docs/release/7.14.3-COMBINED-CANDIDATE.md` |
| 230 | 0 | `docs/release/REHEARSAL-SOP.md` |
| 148 | 0 | `docs/release/RELEASE-PROGRAM.md` |
| 63 | 0 | `docs/release/audit-units/715-04-review-20260923.md` |
| - | - | `docs/release/audit-units/715-04-review-20260923.pdf` |
| 61 | 0 | `docs/release/audit-units/715-05-review-20260924.md` |
| - | - | `docs/release/audit-units/715-05-review-20260924.pdf` |
| 678 | 0 | `docs/release/audit-units/715-05-skips-20260924.tsv` |
| 20 | 0 | `docs/release/audit-units/715-06-evidence-sha256-20260924.txt` |
| 82 | 0 | `docs/release/audit-units/715-06-history-20260924.tsv` |
| - | - | `docs/release/audit-units/715-06-intake-evidence-20260924.tgz` |
| 140 | 0 | `docs/release/audit-units/715-06-reconciliation-20260924.md` |
| 185 | 0 | `docs/release/audit-units/715-06-review-20260924.md` |
| - | - | `docs/release/audit-units/715-06-review-20260924.pdf` |
| 663 | 0 | `docs/release/audit-units/715-06-skips-20260924.tsv` |
| - | - | `docs/release/audit-units/715-06-validation-20260924.tgz` |
| 1086 | 0 | `docs/release/audit-units/715-06-validation-sha256-20260924.txt` |
| 144 | 0 | `docs/release/audit-units/715-07-first-copilot-retrospective-20260924.md` |
| - | - | `docs/release/audit-units/715-07-first-copilot-retrospective-20260924.pdf` |
| 81 | 0 | `docs/release/audit-units/715-07-full-audit-remediation-20260924.md` |
| - | - | `docs/release/audit-units/715-07-full-audit-remediation-20260924.pdf` |
| 112 | 0 | `docs/release/audit-units/715-07-history-20260924.tsv` |
| 62 | 0 | `docs/release/audit-units/715-07-intake-20260924.md` |
| 141 | 0 | `docs/release/audit-units/715-07-review-20260924.md` |
| - | - | `docs/release/audit-units/715-07-review-20260924.pdf` |
| 577 | 0 | `docs/release/audit-units/715-07-skips-20260924.tsv` |
| - | - | `docs/release/audit-units/715-07-validation-20260924.tgz` |
| 112 | 0 | `docs/release/audit-units/715-07-validation-sha256-20260924.txt` |
| 42 | 0 | `docs/release/audit-units/715-07b-d-resplit-mapping-20260927.md` |
| 35 | 0 | `docs/release/audit-units/715-07b-resplit-checks-20260927.json` |
| 74 | 0 | `docs/release/audit-units/715-07b-resplit-receipt-20260927.md` |
| 128 | 0 | `docs/release/audit-units/715-07b1-formatters-audit-20260926.md` |
| - | - | `docs/release/audit-units/715-07b1-formatters-audit-20260926.pdf` |
| 119 | 0 | `docs/release/audit-units/715-07b2a-groups-audit-20260927.md` |
| - | - | `docs/release/audit-units/715-07b2a-groups-audit-20260927.pdf` |
| 121 | 0 | `docs/release/audit-units/715-07b2b-iteration-audit-20260927.md` |
| - | - | `docs/release/audit-units/715-07b2b-iteration-audit-20260927.pdf` |
| 136 | 0 | `docs/release/audit-units/715-07b3r-embedded-audit-20260927.md` |
| - | - | `docs/release/audit-units/715-07b3r-embedded-audit-20260927.pdf` |
| 203 | 0 | `docs/release/audit-units/715-08-10-integration-20260927.md` |
| - | - | `docs/release/audit-units/715-08-10-integration-20260927.pdf` |
| - | - | `docs/release/audit-units/715-08-10-local-evidence-20260927.tgz` |
| 110 | 0 | `docs/release/audit-units/715-08-audit-20260927.md` |
| - | - | `docs/release/audit-units/715-08-audit-20260927.pdf` |
| 86 | 0 | `docs/release/audit-units/715-08-consolidated-audit-20260927.md` |
| - | - | `docs/release/audit-units/715-08-consolidated-audit-20260927.pdf` |
| - | - | `docs/release/audit-units/715-08-local-evidence-20260927.tgz` |
| 175 | 0 | `docs/release/audit-units/715-08-reconciliation-20260927.json` |
| 80 | 0 | `docs/release/audit-units/715-08B-audit-20260927.md` |
| - | - | `docs/release/audit-units/715-08B-audit-20260927.pdf` |
| 114 | 0 | `docs/release/audit-units/715-09-audit-20260927.md` |
| - | - | `docs/release/audit-units/715-09-audit-20260927.pdf` |
| - | - | `docs/release/audit-units/715-09-local-evidence-20260927.tgz` |
| 145 | 0 | `docs/release/audit-units/715-09-reconciliation-20260927.json` |
| 163 | 0 | `docs/release/audit-units/715-10-audit-20260927.md` |
| - | - | `docs/release/audit-units/715-10-audit-20260927.pdf` |
| 31 | 0 | `docs/release/audit-units/715-10-completion-plan-20260927.md` |
| 125 | 0 | `docs/release/audit-units/715-10-final-audit-20260928.md` |
| - | - | `docs/release/audit-units/715-10-final-audit-20260928.pdf` |
| - | - | `docs/release/audit-units/715-10-final-audit-20260928.tgz` |
| - | - | `docs/release/audit-units/715-10-final-readiness-evidence-20260927.tgz` |
| 73 | 0 | `docs/release/audit-units/715-10-intake-20260927.md` |
| 48 | 0 | `docs/release/audit-units/715-10-reconciliation-20260927.json` |
| 495 | 0 | `docs/release/audit-units/715-11-complete-block-audit-20260927.md` |
| - | - | `docs/release/audit-units/715-11-complete-block-audit-20260927.pdf` |
| 200 | 0 | `docs/release/audit-units/715-11-intake-20260927.json` |
| 36 | 0 | `docs/release/audit-units/715-11-intake-20260927.md` |
| - | - | `docs/release/audit-units/715-11-local-evidence-20260927.tgz` |
| 82 | 0 | `docs/release/audit-units/715-11-malformed-schema.md` |
| - | - | `docs/release/audit-units/715-11-manual-ci-controls-20260927.tgz` |
| - | - | `docs/release/audit-units/715-11-review1-controls-20260927.tgz` |
| - | - | `docs/release/audit-units/715-11-review2-controls-20260928.tgz` |
| 27 | 0 | `docs/release/audit-units/715-11-round4-20260928.md` |
| - | - | `docs/release/audit-units/715-11-round4-controls-20260928.tgz` |
| 120 | 0 | `docs/release/audit-units/715-11-split-map-20260928.md` |
| 26 | 0 | `docs/release/audit-units/P01-002-artifact-routing.md` |
| 27 | 0 | `docs/release/audit-units/P01-003-firmware-packaging.md` |
| 12 | 0 | `docs/release/audit-units/P01-004-report-inputs.md` |
| 16 | 0 | `docs/release/audit-units/P01-008-compose-variant.md` |
| 27 | 0 | `docs/release/audit-units/P02-001-tiny-lifetime.md` |
| 14 | 0 | `docs/release/audit-units/P02-003-packet-lifetime.md` |
| 18 | 0 | `docs/release/audit-units/P06-002-ripple-display-response.md` |
| 15 | 0 | `docs/release/audit-units/P06-003-ripple-display-test.md` |
| 21 | 0 | `docs/release/audit-units/P06-005-ripple-unsupported-memo.md` |
| 12 | 0 | `docs/release/audit-units/P06-006-ripple-memo-rejection-test.md` |
| 23 | 0 | `docs/release/audit-units/decode-boundaries.md` |
| 15 | 0 | `docs/release/audit-units/eos-authorization.md` |
| 87 | 0 | `docs/release/audit-units/full-diff-audit-20260912.md` |
| 14 | 0 | `docs/release/audit-units/passphrase-transition.md` |
| 32 | 0 | `docs/release/audit-units/scope-repair.md` |
| 14 | 0 | `docs/release/audit-units/source-storage-policy.md` |
| 21 | 0 | `docs/release/audit-units/storage-capacities.md` |
| 11 | 0 | `docs/release/audit-units/storage-cipher-cleanup.md` |
| 11 | 0 | `docs/release/audit-units/storage-revocation.md` |
| 6 | 0 | `docs/release/audit-units/token-build-dependencies.md` |
| 170 | 0 | `docs/security/7.14.3-bitcoin-only-dice-audit-sop.md` |
| 235 | 0 | `docs/security/HANDOFF-ERC7730-715-FORMATTERS.md` |
| 295 | 0 | `docs/security/HANDOFF-ERC7730-ALPHA.md` |
| 209 | 0 | `docs/security/HANDOFF-ERC7730-PHASE-E.md` |
| - | - | `docs/security/evidence/rom-printf-integer-percent/01-thorchain-withdraw-25.05pct.png` |
| - | - | `docs/security/evidence/rom-printf-integer-percent/02-thorchain-sending-eth.png` |
| 17 | 0 | `docs/security/evidence/rom-printf-integer-percent/README.md` |
| 28 | 0 | `include/keepkey/board/bsd_compat.h` |
| 67 | 1 | `include/keepkey/board/confirm_sm.h` |
| 35 | 0 | `include/keepkey/board/draw.h` |
| 16 | 0 | `include/keepkey/board/keepkey_display.h` |
| 21 | 0 | `include/keepkey/board/layout.h` |
| 57 | 24 | `include/keepkey/board/messages.h` |
| 5 | 0 | `include/keepkey/board/usb.h` |
| 61 | 17 | `include/keepkey/emulator/libkkemu.h` |
| 43 | 1 | `include/keepkey/firmware/app_confirm.h` |
| 9 | 1 | `include/keepkey/firmware/app_layout.h` |
| 11 | 1 | `include/keepkey/firmware/authenticator.h` |
| 12 | 0 | `include/keepkey/firmware/binance.h` |
| 22 | 0 | `include/keepkey/firmware/bip85.h` |
| 2 | 0 | `include/keepkey/firmware/coins.def` |
| 3 | 1 | `include/keepkey/firmware/coins.h` |
| 72 | 0 | `include/keepkey/firmware/dice_input.h` |
| 11 | 4 | `include/keepkey/firmware/eip712.h` |
| 227 | 0 | `include/keepkey/firmware/eip712_stream.h` |
| 4 | 0 | `include/keepkey/firmware/eos.h` |
| 80 | 0 | `include/keepkey/firmware/erc7730_abi.h` |
| 90 | 0 | `include/keepkey/firmware/erc7730_abi_stream.h` |
| 111 | 0 | `include/keepkey/firmware/erc7730_capabilities.h` |
| 241 | 0 | `include/keepkey/firmware/erc7730_catalog.h` |
| 20 | 0 | `include/keepkey/firmware/erc7730_condition.h` |
| 69 | 0 | `include/keepkey/firmware/erc7730_field.h` |
| 38 | 0 | `include/keepkey/firmware/erc7730_format.h` |
| 311 | 0 | `include/keepkey/firmware/erc7730_program.h` |
| 26 | 0 | `include/keepkey/firmware/erc7730_tx.h` |
| 277 | 0 | `include/keepkey/firmware/erc7730_workflow.h` |
| 20 | 2 | `include/keepkey/firmware/ethereum.h` |
| 34 | 0 | `include/keepkey/firmware/ethereum_contracts.h` |
| 3 | 0 | `include/keepkey/firmware/ethereum_contracts/saproxy.h` |
| 27 | 1 | `include/keepkey/firmware/ethereum_contracts/thortx.h` |
| 3 | 0 | `include/keepkey/firmware/ethereum_contracts/zxliquidtx.h` |
| 14 | 3 | `include/keepkey/firmware/ethereum_tokens.h` |
| 38 | 0 | `include/keepkey/firmware/fsm.h` |
| 98 | 0 | `include/keepkey/firmware/hive.h` |
| 2 | 0 | `include/keepkey/firmware/home_sm.h` |
| 54 | 4 | `include/keepkey/firmware/mayachain.h` |
| 36 | 1 | `include/keepkey/firmware/osmosis.h` |
| 7 | 0 | `include/keepkey/firmware/pin_sm.h` |
| 9 | 0 | `include/keepkey/firmware/recovery_cipher.h` |
| 65 | 4 | `include/keepkey/firmware/reset.h` |
| 28 | 2 | `include/keepkey/firmware/ripple.h` |
| 242 | 0 | `include/keepkey/firmware/signed_metadata.h` |
| 21 | 1 | `include/keepkey/firmware/signing.h` |
| 16 | 3 | `include/keepkey/firmware/signtx_tendermint.h` |
| 148 | 0 | `include/keepkey/firmware/solana.h` |
| 46 | 1 | `include/keepkey/firmware/storage.h` |
| 30 | 0 | `include/keepkey/firmware/tendermint.h` |
| 50 | 5 | `include/keepkey/firmware/thorchain.h` |
| 4 | 1 | `include/keepkey/firmware/tiny-json.h` |
| 0 | 7 | `include/keepkey/firmware/tokens.def` |
| 10 | 1 | `include/keepkey/firmware/transaction.h` |
| 56 | 0 | `include/keepkey/firmware/tron.h` |
| 3 | 1 | `include/keepkey/firmware/txin_check.h` |
| 431 | 0 | `include/keepkey/firmware/zcash.h` |
| 19 | 0 | `include/keepkey/rand/rng.h` |
| 143 | 0 | `include/keepkey/rand/rng_health.h` |
| 2 | 0 | `include/keepkey/transport/interface.h` |
| 27 | 0 | `include/keepkey/transport/messages-ethereum.options` |
| 56 | 0 | `include/keepkey/transport/messages-hive.options` |
| 0 | 1 | `include/keepkey/transport/messages-osmosis.options` |
| 2 | 0 | `include/keepkey/transport/messages-ripple.options` |
| 12 | 0 | `include/keepkey/transport/messages-solana.options` |
| 1 | 0 | `include/keepkey/transport/messages-thorchain.options` |
| 54 | 0 | `include/keepkey/transport/messages-zcash.options` |
| 16 | 0 | `include/keepkey/transport/messages.options` |
| 222 | 113 | `include/pb.h` |
| 512 | 30 | `lib/board/confirm_sm.c` |
| 163 | 16 | `lib/board/draw.c` |
| 4 | 1 | `lib/board/font.c` |
| 13 | 10 | `lib/board/keepkey_board.c` |
| 36 | 9 | `lib/board/keepkey_flash.c` |
| 152 | 9 | `lib/board/layout.c` |
| 162 | 68 | `lib/board/messages.c` |
| 39 | 9 | `lib/board/signatures.c` |
| 32 | 2 | `lib/board/timer.c` |
| 3 | 0 | `lib/board/udp.c` |
| 50 | 23 | `lib/board/usb.c` |
| 48 | 16 | `lib/board/util.c` |
| 11 | 4 | `lib/emulator/CMakeLists.txt` |
| 302 | 35 | `lib/emulator/libkkemu.c` |
| 45 | 5 | `lib/emulator/setup.c` |
| 8 | 2 | `lib/emulator/udp.c` |
| 56 | 27 | `lib/firmware/CMakeLists.txt` |
| 281 | 44 | `lib/firmware/app_confirm.c` |
| 117 | 4 | `lib/firmware/app_layout.c` |
| 240 | 131 | `lib/firmware/authenticator.c` |
| 141 | 14 | `lib/firmware/binance.c` |
| 105 | 0 | `lib/firmware/bip85.c` |
| 19 | 1 | `lib/firmware/coins.c` |
| 2 | 1 | `lib/firmware/crypto.c` |
| 448 | 0 | `lib/firmware/dice_input.c` |
| 460 | 255 | `lib/firmware/eip712.c` |
| 1456 | 0 | `lib/firmware/eip712_stream.c` |
| 21 | 8 | `lib/firmware/eos-contracts/eosio.system.c` |
| 117 | 13 | `lib/firmware/eos.c` |
| 472 | 0 | `lib/firmware/erc7730_abi.c` |
| 463 | 0 | `lib/firmware/erc7730_abi_stream.c` |
| 243 | 0 | `lib/firmware/erc7730_capabilities.c` |
| 1652 | 0 | `lib/firmware/erc7730_catalog.c` |
| 109 | 0 | `lib/firmware/erc7730_condition.c` |
| 297 | 0 | `lib/firmware/erc7730_field.c` |
| 233 | 0 | `lib/firmware/erc7730_format.c` |
| 877 | 0 | `lib/firmware/erc7730_program.c` |
| 46 | 0 | `lib/firmware/erc7730_tx.c` |
| 1097 | 0 | `lib/firmware/erc7730_workflow.c` |
| 669 | 120 | `lib/firmware/ethereum.c` |
| 51 | 11 | `lib/firmware/ethereum_contracts.c` |
| 36 | 24 | `lib/firmware/ethereum_contracts/makerdao.c` |
| 52 | 13 | `lib/firmware/ethereum_contracts/saproxy.c` |
| 189 | 47 | `lib/firmware/ethereum_contracts/thortx.c` |
| 113 | 83 | `lib/firmware/ethereum_contracts/zxappliquid.c` |
| 154 | 111 | `lib/firmware/ethereum_contracts/zxliquidtx.c` |
| 201 | 36 | `lib/firmware/ethereum_contracts/zxswap.c` |
| 80 | 16 | `lib/firmware/ethereum_contracts/zxtransERC20.c` |
| 21 | 13 | `lib/firmware/ethereum_tokens.c` |
| 403 | 14 | `lib/firmware/fsm.c` |
| 58 | 17 | `lib/firmware/fsm_msg_binance.h` |
| 143 | 0 | `lib/firmware/fsm_msg_bip85.h` |
| 52 | 9 | `lib/firmware/fsm_msg_coin.h` |
| 145 | 35 | `lib/firmware/fsm_msg_common.h` |
| 118 | 23 | `lib/firmware/fsm_msg_cosmos.h` |
| 39 | 16 | `lib/firmware/fsm_msg_crypto.h` |
| 24 | 7 | `lib/firmware/fsm_msg_debug.h` |
| 22 | 3 | `lib/firmware/fsm_msg_eos.h` |
| 2244 | 142 | `lib/firmware/fsm_msg_ethereum.h` |
| 491 | 0 | `lib/firmware/fsm_msg_hive.h` |
| 162 | 30 | `lib/firmware/fsm_msg_mayachain.h` |
| 210 | 113 | `lib/firmware/fsm_msg_osmosis.h` |
| 81 | 9 | `lib/firmware/fsm_msg_ripple.h` |
| 814 | 153 | `lib/firmware/fsm_msg_solana.h` |
| 125 | 23 | `lib/firmware/fsm_msg_tendermint.h` |
| 136 | 29 | `lib/firmware/fsm_msg_thorchain.h` |
| 37 | 55 | `lib/firmware/fsm_msg_ton.h` |
| 111 | 15 | `lib/firmware/fsm_msg_tron.h` |
| 1699 | 0 | `lib/firmware/fsm_msg_zcash.h` |
| 439 | 0 | `lib/firmware/hive.c` |
| 46 | 8 | `lib/firmware/home_sm.c` |
| 389 | 97 | `lib/firmware/mayachain.c` |
| 54 | 0 | `lib/firmware/messagemap.def` |
| 5 | 2 | `lib/firmware/nano.c` |
| 270 | 37 | `lib/firmware/osmosis.c` |
| 77 | 6 | `lib/firmware/passphrase_sm.c` |
| 47 | 21 | `lib/firmware/pin_sm.c` |
| 213 | 90 | `lib/firmware/recovery_cipher.c` |
| 482 | 96 | `lib/firmware/reset.c` |
| 65 | 10 | `lib/firmware/ripple.c` |
| 1046 | 0 | `lib/firmware/signed_metadata.c` |
| 549 | 59 | `lib/firmware/signing.c` |
| 193 | 65 | `lib/firmware/signtx_tendermint.c` |
| 538 | 41 | `lib/firmware/solana.c` |
| 306 | 42 | `lib/firmware/storage.c` |
| 8 | 0 | `lib/firmware/storage.h` |
| 180 | 4 | `lib/firmware/tendermint.c` |
| 318 | 46 | `lib/firmware/thorchain.c` |
| 5 | 3 | `lib/firmware/tiny-json.c` |
| 5 | 3 | `lib/firmware/ton.c` |
| 180 | 18 | `lib/firmware/transaction.c` |
| 364 | 1 | `lib/firmware/tron.c` |
| 14 | 7 | `lib/firmware/txin_check.c` |
| 11 | 2 | `lib/firmware/u2f.c` |
| 1237 | 0 | `lib/firmware/zcash.c` |
| 2 | 1 | `lib/rand/CMakeLists.txt` |
| 87 | 13 | `lib/rand/rng.c` |
| 348 | 0 | `lib/rand/rng_health.c` |
| 18 | 0 | `lib/transport/CMakeLists.txt` |
| 2 | 1 | `lib/transport/pb_decode.c` |
| 1 | 1 | `scripts/build/docker/device/debug.sh` |
| 7 | 2 | `scripts/build/docker/device/release.sh` |
| 1 | 1 | `scripts/build/docker/emulator/debug.sh` |
| 1 | 0 | `scripts/cppcheck-version` |
| 32 | 0 | `scripts/cppcheck.sh` |
| 10 | 2 | `scripts/emulator/Dockerfile` |
| 111 | 0 | `scripts/emulator/capture-dice-flow.py` |
| 99 | 0 | `scripts/emulator/capture-thor-percent.py` |
| 12 | 0 | `scripts/emulator/docker-compose.bitcoin-only.yml` |
| 14 | 0 | `scripts/emulator/docker-compose.yml` |
| 19 | 1 | `scripts/emulator/firmware-unit.sh` |
| 87 | 65 | `scripts/emulator/python-keepkey-tests.sh` |
| 1 | 1 | `scripts/emulator/python-keepkey.Dockerfile` |
| 443 | 0 | `scripts/emulator/test_stack07_regressions.py` |
| 36 | 0 | `scripts/emulator/test_stack09_integration.py` |
| 201 | 0 | `scripts/emulator/test_stack10_regressions.py` |
| 648 | 68 | `scripts/generate-test-report.py` |
| 103 | 0 | `scripts/preflight.sh` |
| 92 | 0 | `scripts/preflight_checks.py` |
| 249 | 0 | `scripts/test_generate_test_report.py` |
| 124 | 0 | `scripts/test_preflight_checks.py` |
| 91 | 0 | `scripts/test_preflight_cppcheck.py` |
| 85 | 0 | `scripts/tests/test_usb_receive_callbacks.py` |
| 36 | 0 | `scripts/verify-token-def.py` |
| 1 | 0 | `tools/CMakeLists.txt` |
| 124 | 0 | `tools/check_sram_budget.py` |
| 33 | 11 | `tools/emulator/CMakeLists.txt` |
| 28 | 0 | `tools/erc7730-validate/CMakeLists.txt` |
| 82 | 0 | `tools/erc7730-validate/main.c` |
| 110 | 0 | `tools/erc7730-validate/test_cli.py` |
| 3 | 1 | `tools/firmware/CMakeLists.txt` |
| 10 | 0 | `tools/firmware/keepkey.ld` |
| 14 | 9 | `tools/firmware/keepkey_main.c` |
| 10 | 0 | `tools/sram-budgets.json` |
| 251 | 0 | `tools/verify_dice_seed.py` |
| 7 | 1 | `unittests/board/CMakeLists.txt` |
| 490 | 2 | `unittests/board/board.cpp` |
| 5 | 0 | `unittests/board/hardware_stubs/libopencm3/stm32/desig.h` |
| 9 | 0 | `unittests/board/hardware_stubs/libopencm3/stm32/flash.h` |
| 104 | 0 | `unittests/board/hw_entropy.cpp` |
| 154 | 0 | `unittests/board/hw_entropy_probe.c` |
| 25 | 0 | `unittests/board/hw_entropy_probe.h` |
| 6 | 2 | `unittests/crypto/CMakeLists.txt` |
| 500 | 0 | `unittests/crypto/bip340.cpp` |
| 56 | 7 | `unittests/firmware/CMakeLists.txt` |
| 47 | 0 | `unittests/firmware/app_confirm.cpp` |
| 302 | 0 | `unittests/firmware/authenticator.cpp` |
| 151 | 0 | `unittests/firmware/binance.cpp` |
| 28 | 2 | `unittests/firmware/coins.cpp` |
| 189 | 0 | `unittests/firmware/confirm_test_utils.cpp` |
| 166 | 8 | `unittests/firmware/cosmos.cpp` |
| 339 | 0 | `unittests/firmware/crypto_cleanup.cpp` |
| 116 | 0 | `unittests/firmware/dice.cpp` |
| 194 | 0 | `unittests/firmware/eip712.cpp` |
| 1076 | 0 | `unittests/firmware/eip712_stream.cpp` |
| 90 | 3 | `unittests/firmware/eos.cpp` |
| 50 | 0 | `unittests/firmware/eos_authorization.cpp` |
| 16 | 0 | `unittests/firmware/eos_authorization_probe.c` |
| 174 | 0 | `unittests/firmware/erc7730_abi.cpp` |
| 371 | 0 | `unittests/firmware/erc7730_abi_stream.cpp` |
| 1901 | 0 | `unittests/firmware/erc7730_catalog.cpp` |
| 105 | 0 | `unittests/firmware/erc7730_condition.cpp` |
| 304 | 0 | `unittests/firmware/erc7730_field.cpp` |
| 224 | 0 | `unittests/firmware/erc7730_format.cpp` |
| 411 | 0 | `unittests/firmware/erc7730_program.cpp` |
| 74 | 0 | `unittests/firmware/erc7730_tx.cpp` |
| 207 | 0 | `unittests/firmware/erc7730_workflow.cpp` |
| 709 | 1 | `unittests/firmware/ethereum.cpp` |
| 1464 | 0 | `unittests/firmware/fsm.cpp` |
| 783 | 0 | `unittests/firmware/hive.cpp` |
| 20 | 0 | `unittests/firmware/kkconfirm_driver.h` |
| 54 | 0 | `unittests/firmware/liquidity_key_probe.c` |
| 390 | 7 | `unittests/firmware/mayachain.cpp` |
| 11 | 0 | `unittests/firmware/messages_probe.c` |
| 35 | 0 | `unittests/firmware/nanopb_bounds.cpp` |
| 153 | 0 | `unittests/firmware/osmosis.cpp` |
| 46 | 0 | `unittests/firmware/recovery.cpp` |
| 37 | 0 | `unittests/firmware/ripple.cpp` |
| 297 | 0 | `unittests/firmware/rng_health.cpp` |
| 193 | 0 | `unittests/firmware/setup_ceremony.cpp` |
| 1804 | 0 | `unittests/firmware/signed_metadata.cpp` |
| 143 | 0 | `unittests/firmware/signing.cpp` |
| 969 | 15 | `unittests/firmware/solana.cpp` |
| 316 | 29 | `unittests/firmware/storage.cpp` |
| 129 | 0 | `unittests/firmware/storage_cipher_probe.c` |
| 24 | 0 | `unittests/firmware/storage_cipher_probe.h` |
| 135 | 0 | `unittests/firmware/storage_passphrase.cpp` |
| 29 | 0 | `unittests/firmware/test_board.cpp` |
| 4 | 0 | `unittests/firmware/test_board.h` |
| 350 | 21 | `unittests/firmware/thorchain.cpp` |
| 173 | 0 | `unittests/firmware/transaction.cpp` |
| 604 | 0 | `unittests/firmware/tron.cpp` |
| 169 | 0 | `unittests/firmware/usb_rx.cpp` |
| 2204 | 0 | `unittests/firmware/zcash.cpp` |
