# Block 11: complete runtime Solana schema v2 and bounded message signing

## 1. Identity and frozen scope

Owner: Codex /root, agent-1. Restored worktree: /private/tmp/kk715-stack11-resume.
Branch: audit/715-stack11-agent1-20260927. Target: BitHighlander/keepkey-firmware develop.
Firmware PR: https://github.com/BitHighlander/keepkey-firmware/pull/877.
Develop base: fc1e93746132553ad98ed60f4847c8d770732bf9. Report generation predecessor: 3b1d75f0b21623892670be966671be5550669dea.
Reviewed and last hosted-qualified head: f388155ce0b8e8fba1a91e37fe18afaa8f5e2be0.
Earlier local behavior-qualification head: e631449c18f0f26755dc79f59ffea1d6863e8219. Completed block10 predecessor: 476afea2ce9906caaac67bfffa900b6a961fa6c4.
Python pin: aae89d378d889b3872696469fe363cf570e5ac4c; companion PR: https://github.com/BitHighlander/python-keepkey/pull/122.
Main master-template SHA256 recorded at intake: 4df8723670dbd7266ed8d8756b790725fb4f0f5886d36fe2f9b7c3aece2d64e0.
Main SOP SHA256 recorded at intake: cd2c546d41f0a723f6ce84199a3fb03661f79ab3f49fbafca08de96a7c309e89.

This revision records remediation of review 5333270562 in commit 71e5ea8defa967fc78888c7777749f54906992e4.
Local native and forced-fallback dylib qualification passed after these repairs.
The inventory/PDF are refreshed for this revision; final containing head, final
preflight and new hosted results are recorded in the PR receipt after this freeze.

The owner requires the ENTIRE BLOCK PR against fork develop, superseding the
older stacked-target instruction for this PR. Develop is an ancestor, so this
cumulative integration diff contains accepted predecessor blocks and all block11
source. Their prior audits retain their original scope and limitations. This
review also covers the inherited build and scanner defects exposed by that diff.
No merge, assembled-release acceptance or publication is requested.

Block11 includes schema versions 1/2, eight v2 argument slots, token-amount and
duration display, same-runtime-signer token metadata, exact instruction coverage,
companion restrictions, bounded plain-text raw message signing, AdvancedMode and
session trust, and ordinary consent. Certified roots, delegate certificates, LUT
proofs and production publication are excluded from runtime 7.15 scope.

Historical PR841 head e97ecd49d03e49536a0fe690bea1319879db022b and base
58526221f47a06d44ef49c9a0642136423f6556f differ in four files despite the retirement
comment saying tree-empty. Four core functions are retained from that head in the
accepted predecessor; the intake JSON records exact comparisons. The full block's
code is visible against develop, including its retained native tests. PR841 is
historical; its retirement is not evidence of an empty diff.

## 2. Git inventory and behavior coverage

Net target inventory command: git diff --numstat fc1e93746132553ad98ed60f4847c8d770732bf9 3b1d75f0b21623892670be966671be5550669dea.
Section 7 lists the complete target inventory from that immutable predecessor.
Counts include code, tests, dependency pointers, workflows, receipts and this
report. Historical counts overlap; do not sum them. The remediation removes an
unused helper that had been added relative to develop; it is therefore absent
from the net target diff. Its test-preservation proof is recorded below.

| Behavior | Code-bearing paths in the develop-target PR | Evidence |
| --- | --- | --- |
| Schema v1/v2 bounded parser and widths | include/keepkey/firmware/solana.h; lib/firmware/solana.c; unittests/firmware/solana.cpp | Canonical/v2, unsafe-label, trailing-byte and all-prefix truncation assertions; named native cases pass in f388 CI |
| Exact program/discriminator/data/account binding | lib/firmware/solana.c; unittests/firmware/solana.cpp | Coverage/mismatch/index tests and transfer-companion wire refusal with valid control |
| Runtime-only trust, token mint and same signer | lib/firmware/fsm_msg_solana.h; lib/firmware/signed_metadata.c; deps/python-keepkey | Runtime token display control and eight invalid-attestation cases; named runtime-attestation test passes in f388 CI |
| Session reset and policy | lib/firmware/fsm_msg_common.h; lib/firmware/storage.c; deps/python-keepkey | Initialize/ClearSession/policy tests; Solana Initialize refusal |
| Plain-text predicate and exact message consent | lib/firmware/solana.c; lib/firmware/fsm_msg_solana.h; unittests/firmware/solana.cpp; deps/python-keepkey | Printable/control-byte/key-scan native tests and message-policy wire tests |
| Malformed input cannot reach schema consent | lib/firmware/fsm_msg_solana.h; deps/python-keepkey | Three malformed forms with/without schema; baseline rejection-order evidence and named runtime-schema regression pass in f388 CI |
| Transport bounds and host consumer | include/keepkey/transport/messages-solana.options; deps/python-keepkey | raw_tx 2048, schema 256, signature 64, raw message 1024; client/protobuf consumer inspected |
| Secret detection for tracked dependency paths | .gitleaks.toml | Old configuration misses a tracked-file credential canary; fixed configuration detects it; pinned scanner snapshot/history checks pass |
| Full/BTC crypto source and test boundaries | deps/crypto/CMakeLists.txt; unittests/crypto/CMakeLists.txt; standalone helper removed from review-head delta | Actual CMake source/command inventories; retained firmware-unit/xunit path; 72 historical passing Zcash cases |
| Dylib libc fallbacks | lib/emulator/CMakeLists.txt | Forced-missing-libc configure fails before repair and passes after repair; full Linux shared library build/load and string-boundary checks pass |
| Accepted predecessor stack | Remaining cumulative paths in section 7 | Existing accepted reports retained; not attributed to S11-01 |

Original unit inventories:

Commit a1b63ac5e75c6792f15f8d439e452eca2f2ecb45:

```
13	7	include/keepkey/firmware/solana.h
93	12	lib/firmware/fsm_msg_solana.h
32	7	lib/firmware/solana.c
36	0	unittests/firmware/solana.cpp
```

Commit a7daa79ded5c38afef37c23d02aea6fa671f28a9:

```
6	0	include/keepkey/firmware/solana.h
32	25	lib/firmware/fsm_msg_solana.h
13	0	lib/firmware/solana.c
58	0	unittests/firmware/solana.cpp
```

Dependency pins at qualification:

```
a6470bd8598e5e9a7bfc38bf139a5e5a616f05ec code-signing-keys (heads/master)
 8a392f70a5d5575ece3dfb35f115d4a4b27f497c deps/crypto/trezor-firmware (8a392f70a)
 5fec9e6906a340be5eb3d795ec746769065b2db8 deps/device-protocol (dice-entropy-v1-83-g5fec9e6)
 7888184f28509dba839e3683409443e0b5bb8948 deps/googletest (release-1.8.0-755-g7888184f)
 aae89d378d889b3872696469fe363cf570e5ac4c deps/python-keepkey (v6.0.3-958-gaae89d3)
 6dfbfdad5d9303ed190d1c3cb7bec34b565b6ce8 deps/qrenc/QR-Code-generator (v1.4.0-11-g6dfbfda)
 71d356a1141624994cf613bd2d2583892e8e6d5a deps/sca-hardening/SecAESSTM32 (heads/keepkey)
```

## 3. Current-source reconciliation and findings

S11-01 FIXED: SolanaSignTx formerly evaluated a valid runtime schema after
solana_inspectTx returned MALFORMED with partially populated instructions. That
branch preceded the final malformed rejection and skipped signer validation.
The early error now zeroes the derived node and returns SyntaxError before schema
evaluation. Baseline emulator tests reached confirmation on all three
schema-bearing cases; rejecting the prompt produced ActionCancelled. The fixed
handler returns the malformed error without confirmation for all six cases.
The baseline test did not approve a signature; signing reachability is source
tracing, not a captured baseline signature or a claim of network acceptance.

Security closure: the sensitive operation is Ed25519 signing with the device's
derived private key; host input is raw_tx plus a runtime-signed schema. The host
observes protocol responses and confirmation requests. Full firmware is affected;
BTC does not dispatch Solana. Malformed input must yield no signing consent or
signature during parsing/schema selection. Positive controls are valid runtime
schema signing and token metadata review. Negative controls are legacy trailing
bytes, missing v0 lookup count and a truncated lookup entry, with/without schema.
Baseline failures falsify the old guard order; fixed results prove early rejection.
The adjacent evidence archive and malformed-schema receipt retain those controls.

Current-source review covers parser exhaustion, safe labels, typed argument
bounds and exact byte coverage. Runtime signer ID checks precede narrowing;
signatures require exactly 64 bytes and AdvancedMode. Token display requires a
matching mint, bounded decimals, valid symbol/signature and the same signer slot
as the schema; otherwise it displays base units and mint. Companions cannot
silently transfer value; priority fees remain disclosed. Raw printable text
rejects the actual signer key at every byte offset and retains message-byte
consent. Other message formats retain AdvancedMode.

Review 5333270562, delivered 2026-09-28T02:07:05Z on f388155ce0b8e8fba1a91e37fe18afaa8f5e2be0,
reported five findings. Both its overview and all five inline comments were read.
The following dispositions describe committed, locally validated changes. Final
preflight/hosted CI and published thread dispositions are recorded after freeze.

| Finding/comment | Confirmed behavior and local repair | Evidence and qualification |
| --- | --- | --- |
| CR11-01 / 4117950392 | The inherited ^deps/ scanner exemption hid first-party tracked files as well as dependencies. Removed that exemption and corrected its description; specific public U2F exceptions remain. | Pinned Gitleaks 8.30.1 missed a synthetic credential appended to tracked deps/sca-hardening/aes128_cbc.c with the old configuration and detected it with the fix. A CI-equivalent tracked snapshot and the 219-commit develop..f388 PR range scan clean with the fixed configuration. No new ignore entry was added for this finding. |
| CR11-02 / 4117950427 | Six Pallas/Zcash files were unconditional and five appeared again under KK_ZCASH_PRIVACY. All six, including pallas_ct.c, now belong only to that conditional. | Real CMake evaluation now gives exactly six full-product source entries/compile commands and zero in BTC. The review's duplicate-object consequence was not reproduced: the baseline generator deduplicated 11 entries into six commands. The confirmed defect is the product/source boundary. |
| CR11-03 / 4117950439 | The dylib fallback named strlcpy.c and strlcat.c relative to lib/emulator although they live in lib/board. Both now use explicit board-source paths, with direct CMake boolean checks. | Forcing both KK_HAVE_STRLCPY and KK_HAVE_STRLCAT false made the baseline configure fail with a missing source; repaired host and Linux configurations succeed. Complete GCC Linux dylib build/load and bounded copy/append checks pass with both fallback flags forced false. |
| CR11-04 / 4117950452 | The separate zcash-crypto-unit target existed in BTC builds and relied on the unconditional crypto sources. Removed that redundant target and its now-unreferenced deterministic RNG helper. | CMake inventories confirm no standalone target in either product, retained conditional firmware-unit Zcash coverage in full, and no Zcash implementation source in BTC (shared generated protocol metadata remains). No unique test implementation was removed. |
| CR11-05 / 4117950469 | The standalone target was absent from xunit, but the assertion that these tests never ran is refuted. The same firmware/zcash.cpp suite already belongs to firmware-unit and runs through xunit/CTest. Removed the redundant target and documented the existing registration. | Exact reviewed-head CI contains 72 passing Zcash cases in full firmware.xml and zero in BTC. The repaired source registration retains that suite. The repaired full xunit run again passes all 72 Zcash cases; BTC passes 180 native tests with none of these cases. |

The underlying classes are broad path-based scanner exemptions, product flags
applied inconsistently across library/test targets, and optional host branches
whose relative source paths were never exercised. Controls inspect a real tracked
path, generated source/compile inventories and forced capability-false configure
branches. Test preservation is established from actual JUnit and the existing
required execution target, rather than executable names alone.

These controls and the complete review are preserved in the adjacent
715-11-review1-controls-20260927.tgz archive with a verified SHA256 manifest.
Local disposition records are /private/tmp/kk715-stack11-review-crypto/disposition.json
(with before.json and after.json), /private/tmp/kk715-stack11-review-fixes/secret-scan/result.json,
and the baseline-host.log, fixed-host.log and fixed-linux-configure.log files in
/private/tmp/kk715-stack11-review-fixes/dylib. Review body/comments are retained in
/private/tmp/kk715-stack11-evidence-resume/reviews-final.json and review-inline-final.json.
The extra initialized-submodule scanner diagnostic reports 72 fixture/public-
material matches across 23 third-party files. They were classified separately;
that diagnostic is not a passing qualification scan and no exemption was added.
CI's scanner checkout does not initialize those gitlinks.

CI-TARGET-01: the develop-based PR event still fails closed because develop has
no KK_RELEASE_MISSING_CAPABILITIES ledger. The owner approved the independent
manual authority KK_ACCEPTED_WAIVER_SHA=2483977523d9b6beab52a69429ace9aeefd00f76;
its seven-capability ledger contains the candidate's five waivers. That repository
setting remains active. Manual run 36363905103 qualified f388 with publishing
disabled, without changing runtime authority selection or waiving the PR check.
A new manual run is required for the current build/scanner remediation.

CI-MANUAL-02 FIXED: run 36363232771 failed because a PR-authority test inherited
workflow_dispatch and the approved variable. The fixture explicitly sets
pull_request; the old control fails and the fixed report-gate suite passes in
that environment. CI-MANUAL-03 FIXED: two public dependency SHA lines in a block09
receipt needed exact no-git path/rule/line fingerprints in addition to existing
commit-scoped fingerprints. git ls-tree proves their gitlink identities; a
same-file credential canary still triggers the pinned scanner. Both repairs were
included in successful f388 CI. They are distinct from CR11-01's inherited broad
exemption, which is now removed locally.

## 4. Verification and artifact identity

The following hosted results are exact for the reviewed head f388155ce0b8e8fba1a91e37fe18afaa8f5e2be0,
not the current post-review remediation. Run https://github.com/BitHighlander/keepkey-firmware/actions/runs/36363905103
completed successfully, including the release-evidence gate; publishing was skipped.

| Evidence | Verified result on f388 |
| --- | --- |
| Combined authoritative report | 1,521 pass, 84 skip, zero fail/error; 1,605 total |
| Full native | firmware 669, board 19, crypto 18 pass; includes 72 Zcash cases |
| Full Python integration | 811 pass, 84 skip; both new runtime-schema regression methods pass |
| Dylib integration | 4 pass |
| BTC native | firmware 143, board 19, crypto 18 pass; Solana/Zcash suites excluded |
| BTC Python integration | 347 pass, 548 skip; new Solana methods explicitly skip because full firmware is required |
| Dedicated contracts, full | Stack06 13 pass/3 skip; Stack07 21 pass; Stack09 1 pass; Stack10 7 pass |
| OLED evidence | 1,347 frame hashes and 194 sequence manifests verified; screenshot selection 194 pass/24 skip |
| ARM variants | Full and BTC manifests, firmware/Python identities and all 23 listed binary/ELF hashes per variant verified |
| SRAM gates | Full reserve 17,800 B; BTC 39,136 B; largest frame 7,664 B in each; both pass |

The combined count excludes BTC and repeated contract/capture runs. Named passing
cases are Solana.SchemaParsesCanonicalPayload,
Solana.SchemaV2ParsesTokenDurationAndEightArgs,
tests.test_msg_solana_schema_v2.TestSolanaSchemaRuntime.test_runtime_schema_cannot_rescue_malformed_transaction,
and tests.test_msg_solana_schema_v2.TestSolanaSchemaRuntime.test_runtime_schema_requires_complete_valid_runtime_attestation.
Their JUnit identities and statuses were checked directly.

Report artifact 10946638964; full ARM artifact 10946334201; BTC ARM artifact 10947200608.
Report PDF SHA256: 3166384b3568ef0b3716c825a531a35b853c3708c0f23d2110b1c16effdd2165.
Report manifest SHA256: 5bbdb05076248c6586d5a008d56a1696209167b886c3a8f5080616c89fd56827.
Merged JUnit SHA256: 7cd8e675ba9777d6042ab68f0f738e9b2e13fc029e148b84869e31d0ec8d85c7.
All nine JUnit input hashes, generator hashes, ARM hashes and OLED hashes agree.
The manual event intentionally has an empty firmware_pr metadata field; the
receipt binds PR877 to the exact head/run. Python metadata names PR122 and pin
aae89d378d889b3872696469fe363cf570e5ac4c. Independent verification files are retained
under /private/tmp/kk715-stack11-ci-verification, including final-verified.json,
run-final.json, jobs-final.json and test-report/test-report-manifest.json.

Earlier local evidence on e631449c remains historical: 669 firmware-unit passes;
39 Solana/runtime/session wire passes plus 14 passing subtests and three skips.
The S11-01 baseline and fixed controls remain in the adjacent evidence archive.
Restoration of the unavailable original temporary worktree verified all 11
archived artifact hashes before publishing the reviewed candidate.

Material skips remain explicit: certified/attestor tests require firmware 7.16;
LUT proofs are outside runtime 7.15 scope. The two session power-cycle tests skip
because the harness does not own the UDP emulator process (hosted run port 11044;
earlier local run port 12144). Actual power cycles, physical-device/OLED behavior
and release promotion remain separate gates. The complete 84-skip ledger is in
the verified report manifest; none is represented as a passing test.

Current remediation qualification on 71e5ea8defa967fc78888c7777749f54906992e4:
full native xunit passes 706 tests (669 firmware, 19 board, 18 crypto), including
all 72 Zcash cases; BTC xunit passes 180 tests with no Zcash implementation units
or symbols in the tested archives/binaries. Both have zero failures/skips.
Forced-libc Linux dylib configure/build/load and truncation/zero-capacity copy
and append checks pass using pinned CMake 3.31.6 and GCC 6.4.0 in image7438e53933d4.
The old bundled Clang lacks stdatomic.h; that unsuccessful optional-dylib attempt
is preserved alongside the successful GCC build. Missing nested token data was
initialized at its pinned commit before both successful native builds.
Final preflight, new exact-head hosted CI and artifact verification are recorded
in the PR receipt after this report freeze; f388 results remain historical.

## 5. Report render and local preflight

This source and its PDF reconcile the delivered review and repair validation.
Section 7 uses the explicit immutable base-to-predecessor inventory. Final Git
path/count equality, PDF legibility and post-edit preflight are verified before
push; their receipt identifies the resulting containing head. The earlier
report/PDF and preflight remain evidence of the reviewed checkpoint only.

The entire develop-target diff is code-bearing, with block11 behavior mapped
above and a pinned Python companion. The pre-push gate must account for removal
of the unused standalone RNG helper while proving retained Zcash registration.
Record the final containing head, complete validation results and all published
finding dispositions in the PR receipt without rewriting historical evidence.

## 6. Copilot checkpoint and completion

Owner authorization: exactly one request. Requests used: 1/1. Timeline event
31957245566 registered that request at 2026-09-28T01:58:42Z. Review 5333270562
was delivered at 2026-09-28T02:07:05Z against f388155ce0b8e8fba1a91e37fe18afaa8f5e2be0,
with Lite effort and five findings (overview: four high, one medium). Its verdict
is Changes recommended, not approval. It has been fully inspected; the five
local dispositions are recorded in section 3.

After the remediation commit, that review remains historical and does not cover
the new head. Local fixes, verification, publication and addressed-thread closure
can proceed within the authorized work; no second Copilot request is authorized.
Published replies and thread resolution are pending this final validation/push.
Do not report Copilot-clean status or block11 completion from a stale review or
from test totals. Predecessor decisions, outstanding release gates and the
separate develop-event authority incompatibility retain their stated status.

## 7. Complete target diff inventory

| Added | Deleted | Path |
| ---: | ---: | --- |
| 1 | 2 | .gitattributes |
| 755 | 587 | .github/workflows/ci.yml |
| 8 | 8 | .github/workflows/mirror-base-image.yml |
| 275 | 69 | .github/workflows/release.yml |
| 6 | 0 | .gitignore |
| 20 | 0 | .gitleaks.toml |
| 9 | 0 | .gitleaksignore |
| 3 | 3 | .gitmodules |
| 58 | 4 | CMakeLists.txt |
| 1 | 0 | cmake/caches/device.cmake |
| 40 | 0 | cmake/toolchains/mingw-w64-x86_64.cmake |
| 13 | 0 | deps/crypto/CMakeLists.txt |
| 1 | 1 | deps/crypto/trezor-firmware |
| 1 | 1 | deps/device-protocol |
| 1 | 1 | deps/python-keepkey |
| 192 | 0 | docs/DiceEntropy.md |
| 154 | 0 | docs/dice-vs-coldcard.md |
| 94 | 0 | docs/firmware/reviews/7.15.0-review-round2-remediation.md |
| 124 | 0 | docs/release/7.14.3-COMBINED-CANDIDATE.md |
| 230 | 0 | docs/release/REHEARSAL-SOP.md |
| 148 | 0 | docs/release/RELEASE-PROGRAM.md |
| 63 | 0 | docs/release/audit-units/715-04-review-20260923.md |
| - | - | docs/release/audit-units/715-04-review-20260923.pdf |
| 61 | 0 | docs/release/audit-units/715-05-review-20260924.md |
| - | - | docs/release/audit-units/715-05-review-20260924.pdf |
| 678 | 0 | docs/release/audit-units/715-05-skips-20260924.tsv |
| 20 | 0 | docs/release/audit-units/715-06-evidence-sha256-20260924.txt |
| 82 | 0 | docs/release/audit-units/715-06-history-20260924.tsv |
| - | - | docs/release/audit-units/715-06-intake-evidence-20260924.tgz |
| 140 | 0 | docs/release/audit-units/715-06-reconciliation-20260924.md |
| 185 | 0 | docs/release/audit-units/715-06-review-20260924.md |
| - | - | docs/release/audit-units/715-06-review-20260924.pdf |
| 663 | 0 | docs/release/audit-units/715-06-skips-20260924.tsv |
| - | - | docs/release/audit-units/715-06-validation-20260924.tgz |
| 1086 | 0 | docs/release/audit-units/715-06-validation-sha256-20260924.txt |
| 144 | 0 | docs/release/audit-units/715-07-first-copilot-retrospective-20260924.md |
| - | - | docs/release/audit-units/715-07-first-copilot-retrospective-20260924.pdf |
| 81 | 0 | docs/release/audit-units/715-07-full-audit-remediation-20260924.md |
| - | - | docs/release/audit-units/715-07-full-audit-remediation-20260924.pdf |
| 112 | 0 | docs/release/audit-units/715-07-history-20260924.tsv |
| 62 | 0 | docs/release/audit-units/715-07-intake-20260924.md |
| 141 | 0 | docs/release/audit-units/715-07-review-20260924.md |
| - | - | docs/release/audit-units/715-07-review-20260924.pdf |
| 577 | 0 | docs/release/audit-units/715-07-skips-20260924.tsv |
| - | - | docs/release/audit-units/715-07-validation-20260924.tgz |
| 112 | 0 | docs/release/audit-units/715-07-validation-sha256-20260924.txt |
| 42 | 0 | docs/release/audit-units/715-07b-d-resplit-mapping-20260927.md |
| 35 | 0 | docs/release/audit-units/715-07b-resplit-checks-20260927.json |
| 74 | 0 | docs/release/audit-units/715-07b-resplit-receipt-20260927.md |
| 128 | 0 | docs/release/audit-units/715-07b1-formatters-audit-20260926.md |
| - | - | docs/release/audit-units/715-07b1-formatters-audit-20260926.pdf |
| 119 | 0 | docs/release/audit-units/715-07b2a-groups-audit-20260927.md |
| - | - | docs/release/audit-units/715-07b2a-groups-audit-20260927.pdf |
| 121 | 0 | docs/release/audit-units/715-07b2b-iteration-audit-20260927.md |
| - | - | docs/release/audit-units/715-07b2b-iteration-audit-20260927.pdf |
| 136 | 0 | docs/release/audit-units/715-07b3r-embedded-audit-20260927.md |
| - | - | docs/release/audit-units/715-07b3r-embedded-audit-20260927.pdf |
| 203 | 0 | docs/release/audit-units/715-08-10-integration-20260927.md |
| - | - | docs/release/audit-units/715-08-10-integration-20260927.pdf |
| - | - | docs/release/audit-units/715-08-10-local-evidence-20260927.tgz |
| 110 | 0 | docs/release/audit-units/715-08-audit-20260927.md |
| - | - | docs/release/audit-units/715-08-audit-20260927.pdf |
| 86 | 0 | docs/release/audit-units/715-08-consolidated-audit-20260927.md |
| - | - | docs/release/audit-units/715-08-consolidated-audit-20260927.pdf |
| - | - | docs/release/audit-units/715-08-local-evidence-20260927.tgz |
| 175 | 0 | docs/release/audit-units/715-08-reconciliation-20260927.json |
| 80 | 0 | docs/release/audit-units/715-08B-audit-20260927.md |
| - | - | docs/release/audit-units/715-08B-audit-20260927.pdf |
| 114 | 0 | docs/release/audit-units/715-09-audit-20260927.md |
| - | - | docs/release/audit-units/715-09-audit-20260927.pdf |
| - | - | docs/release/audit-units/715-09-local-evidence-20260927.tgz |
| 145 | 0 | docs/release/audit-units/715-09-reconciliation-20260927.json |
| 163 | 0 | docs/release/audit-units/715-10-audit-20260927.md |
| - | - | docs/release/audit-units/715-10-audit-20260927.pdf |
| 31 | 0 | docs/release/audit-units/715-10-completion-plan-20260927.md |
| - | - | docs/release/audit-units/715-10-final-readiness-evidence-20260927.tgz |
| 73 | 0 | docs/release/audit-units/715-10-intake-20260927.md |
| 48 | 0 | docs/release/audit-units/715-10-reconciliation-20260927.json |
| 639 | 0 | docs/release/audit-units/715-11-complete-block-audit-20260927.md |
| - | - | docs/release/audit-units/715-11-complete-block-audit-20260927.pdf |
| 200 | 0 | docs/release/audit-units/715-11-intake-20260927.json |
| 36 | 0 | docs/release/audit-units/715-11-intake-20260927.md |
| - | - | docs/release/audit-units/715-11-local-evidence-20260927.tgz |
| 82 | 0 | docs/release/audit-units/715-11-malformed-schema.md |
| - | - | docs/release/audit-units/715-11-manual-ci-controls-20260927.tgz |
| - | - | docs/release/audit-units/715-11-review1-controls-20260927.tgz |
| 26 | 0 | docs/release/audit-units/P01-002-artifact-routing.md |
| 27 | 0 | docs/release/audit-units/P01-003-firmware-packaging.md |
| 12 | 0 | docs/release/audit-units/P01-004-report-inputs.md |
| 16 | 0 | docs/release/audit-units/P01-008-compose-variant.md |
| 27 | 0 | docs/release/audit-units/P02-001-tiny-lifetime.md |
| 14 | 0 | docs/release/audit-units/P02-003-packet-lifetime.md |
| 18 | 0 | docs/release/audit-units/P06-002-ripple-display-response.md |
| 15 | 0 | docs/release/audit-units/P06-003-ripple-display-test.md |
| 21 | 0 | docs/release/audit-units/P06-005-ripple-unsupported-memo.md |
| 12 | 0 | docs/release/audit-units/P06-006-ripple-memo-rejection-test.md |
| 23 | 0 | docs/release/audit-units/decode-boundaries.md |
| 15 | 0 | docs/release/audit-units/eos-authorization.md |
| 87 | 0 | docs/release/audit-units/full-diff-audit-20260912.md |
| 14 | 0 | docs/release/audit-units/passphrase-transition.md |
| 32 | 0 | docs/release/audit-units/scope-repair.md |
| 14 | 0 | docs/release/audit-units/source-storage-policy.md |
| 21 | 0 | docs/release/audit-units/storage-capacities.md |
| 11 | 0 | docs/release/audit-units/storage-cipher-cleanup.md |
| 11 | 0 | docs/release/audit-units/storage-revocation.md |
| 6 | 0 | docs/release/audit-units/token-build-dependencies.md |
| 170 | 0 | docs/security/7.14.3-bitcoin-only-dice-audit-sop.md |
| 235 | 0 | docs/security/HANDOFF-ERC7730-715-FORMATTERS.md |
| 295 | 0 | docs/security/HANDOFF-ERC7730-ALPHA.md |
| 209 | 0 | docs/security/HANDOFF-ERC7730-PHASE-E.md |
| - | - | docs/security/evidence/rom-printf-integer-percent/01-thorchain-withdraw-25.05pct.png |
| - | - | docs/security/evidence/rom-printf-integer-percent/02-thorchain-sending-eth.png |
| 17 | 0 | docs/security/evidence/rom-printf-integer-percent/README.md |
| 28 | 0 | include/keepkey/board/bsd_compat.h |
| 67 | 1 | include/keepkey/board/confirm_sm.h |
| 35 | 0 | include/keepkey/board/draw.h |
| 16 | 0 | include/keepkey/board/keepkey_display.h |
| 21 | 0 | include/keepkey/board/layout.h |
| 57 | 24 | include/keepkey/board/messages.h |
| 5 | 0 | include/keepkey/board/usb.h |
| 61 | 17 | include/keepkey/emulator/libkkemu.h |
| 43 | 1 | include/keepkey/firmware/app_confirm.h |
| 9 | 1 | include/keepkey/firmware/app_layout.h |
| 11 | 1 | include/keepkey/firmware/authenticator.h |
| 12 | 0 | include/keepkey/firmware/binance.h |
| 22 | 0 | include/keepkey/firmware/bip85.h |
| 2 | 0 | include/keepkey/firmware/coins.def |
| 3 | 1 | include/keepkey/firmware/coins.h |
| 72 | 0 | include/keepkey/firmware/dice_input.h |
| 11 | 4 | include/keepkey/firmware/eip712.h |
| 227 | 0 | include/keepkey/firmware/eip712_stream.h |
| 4 | 0 | include/keepkey/firmware/eos.h |
| 80 | 0 | include/keepkey/firmware/erc7730_abi.h |
| 90 | 0 | include/keepkey/firmware/erc7730_abi_stream.h |
| 111 | 0 | include/keepkey/firmware/erc7730_capabilities.h |
| 241 | 0 | include/keepkey/firmware/erc7730_catalog.h |
| 20 | 0 | include/keepkey/firmware/erc7730_condition.h |
| 69 | 0 | include/keepkey/firmware/erc7730_field.h |
| 38 | 0 | include/keepkey/firmware/erc7730_format.h |
| 311 | 0 | include/keepkey/firmware/erc7730_program.h |
| 26 | 0 | include/keepkey/firmware/erc7730_tx.h |
| 277 | 0 | include/keepkey/firmware/erc7730_workflow.h |
| 20 | 2 | include/keepkey/firmware/ethereum.h |
| 34 | 0 | include/keepkey/firmware/ethereum_contracts.h |
| 3 | 0 | include/keepkey/firmware/ethereum_contracts/saproxy.h |
| 27 | 1 | include/keepkey/firmware/ethereum_contracts/thortx.h |
| 3 | 0 | include/keepkey/firmware/ethereum_contracts/zxliquidtx.h |
| 14 | 3 | include/keepkey/firmware/ethereum_tokens.h |
| 38 | 0 | include/keepkey/firmware/fsm.h |
| 98 | 0 | include/keepkey/firmware/hive.h |
| 2 | 0 | include/keepkey/firmware/home_sm.h |
| 54 | 4 | include/keepkey/firmware/mayachain.h |
| 36 | 1 | include/keepkey/firmware/osmosis.h |
| 7 | 0 | include/keepkey/firmware/pin_sm.h |
| 9 | 0 | include/keepkey/firmware/recovery_cipher.h |
| 65 | 4 | include/keepkey/firmware/reset.h |
| 28 | 2 | include/keepkey/firmware/ripple.h |
| 242 | 0 | include/keepkey/firmware/signed_metadata.h |
| 21 | 1 | include/keepkey/firmware/signing.h |
| 16 | 3 | include/keepkey/firmware/signtx_tendermint.h |
| 148 | 0 | include/keepkey/firmware/solana.h |
| 45 | 1 | include/keepkey/firmware/storage.h |
| 30 | 0 | include/keepkey/firmware/tendermint.h |
| 50 | 5 | include/keepkey/firmware/thorchain.h |
| 4 | 1 | include/keepkey/firmware/tiny-json.h |
| 0 | 7 | include/keepkey/firmware/tokens.def |
| 10 | 1 | include/keepkey/firmware/transaction.h |
| 56 | 0 | include/keepkey/firmware/tron.h |
| 3 | 1 | include/keepkey/firmware/txin_check.h |
| 431 | 0 | include/keepkey/firmware/zcash.h |
| 19 | 0 | include/keepkey/rand/rng.h |
| 143 | 0 | include/keepkey/rand/rng_health.h |
| 2 | 0 | include/keepkey/transport/interface.h |
| 27 | 0 | include/keepkey/transport/messages-ethereum.options |
| 56 | 0 | include/keepkey/transport/messages-hive.options |
| 0 | 1 | include/keepkey/transport/messages-osmosis.options |
| 2 | 0 | include/keepkey/transport/messages-ripple.options |
| 12 | 0 | include/keepkey/transport/messages-solana.options |
| 1 | 0 | include/keepkey/transport/messages-thorchain.options |
| 54 | 0 | include/keepkey/transport/messages-zcash.options |
| 16 | 0 | include/keepkey/transport/messages.options |
| 222 | 113 | include/pb.h |
| 512 | 30 | lib/board/confirm_sm.c |
| 163 | 16 | lib/board/draw.c |
| 4 | 1 | lib/board/font.c |
| 13 | 10 | lib/board/keepkey_board.c |
| 16 | 6 | lib/board/keepkey_flash.c |
| 152 | 9 | lib/board/layout.c |
| 162 | 68 | lib/board/messages.c |
| 39 | 9 | lib/board/signatures.c |
| 28 | 2 | lib/board/timer.c |
| 3 | 0 | lib/board/udp.c |
| 50 | 23 | lib/board/usb.c |
| 48 | 16 | lib/board/util.c |
| 11 | 4 | lib/emulator/CMakeLists.txt |
| 302 | 35 | lib/emulator/libkkemu.c |
| 45 | 5 | lib/emulator/setup.c |
| 8 | 2 | lib/emulator/udp.c |
| 56 | 27 | lib/firmware/CMakeLists.txt |
| 281 | 44 | lib/firmware/app_confirm.c |
| 117 | 4 | lib/firmware/app_layout.c |
| 240 | 131 | lib/firmware/authenticator.c |
| 141 | 14 | lib/firmware/binance.c |
| 105 | 0 | lib/firmware/bip85.c |
| 19 | 1 | lib/firmware/coins.c |
| 448 | 0 | lib/firmware/dice_input.c |
| 460 | 255 | lib/firmware/eip712.c |
| 1456 | 0 | lib/firmware/eip712_stream.c |
| 21 | 8 | lib/firmware/eos-contracts/eosio.system.c |
| 117 | 13 | lib/firmware/eos.c |
| 472 | 0 | lib/firmware/erc7730_abi.c |
| 463 | 0 | lib/firmware/erc7730_abi_stream.c |
| 243 | 0 | lib/firmware/erc7730_capabilities.c |
| 1652 | 0 | lib/firmware/erc7730_catalog.c |
| 109 | 0 | lib/firmware/erc7730_condition.c |
| 297 | 0 | lib/firmware/erc7730_field.c |
| 233 | 0 | lib/firmware/erc7730_format.c |
| 877 | 0 | lib/firmware/erc7730_program.c |
| 46 | 0 | lib/firmware/erc7730_tx.c |
| 1097 | 0 | lib/firmware/erc7730_workflow.c |
| 659 | 119 | lib/firmware/ethereum.c |
| 51 | 11 | lib/firmware/ethereum_contracts.c |
| 36 | 24 | lib/firmware/ethereum_contracts/makerdao.c |
| 52 | 13 | lib/firmware/ethereum_contracts/saproxy.c |
| 189 | 47 | lib/firmware/ethereum_contracts/thortx.c |
| 113 | 83 | lib/firmware/ethereum_contracts/zxappliquid.c |
| 154 | 111 | lib/firmware/ethereum_contracts/zxliquidtx.c |
| 201 | 36 | lib/firmware/ethereum_contracts/zxswap.c |
| 80 | 16 | lib/firmware/ethereum_contracts/zxtransERC20.c |
| 21 | 13 | lib/firmware/ethereum_tokens.c |
| 416 | 19 | lib/firmware/fsm.c |
| 58 | 17 | lib/firmware/fsm_msg_binance.h |
| 143 | 0 | lib/firmware/fsm_msg_bip85.h |
| 52 | 9 | lib/firmware/fsm_msg_coin.h |
| 143 | 35 | lib/firmware/fsm_msg_common.h |
| 118 | 23 | lib/firmware/fsm_msg_cosmos.h |
| 27 | 14 | lib/firmware/fsm_msg_crypto.h |
| 24 | 7 | lib/firmware/fsm_msg_debug.h |
| 22 | 3 | lib/firmware/fsm_msg_eos.h |
| 2239 | 141 | lib/firmware/fsm_msg_ethereum.h |
| 491 | 0 | lib/firmware/fsm_msg_hive.h |
| 162 | 30 | lib/firmware/fsm_msg_mayachain.h |
| 210 | 113 | lib/firmware/fsm_msg_osmosis.h |
| 81 | 9 | lib/firmware/fsm_msg_ripple.h |
| 814 | 153 | lib/firmware/fsm_msg_solana.h |
| 125 | 23 | lib/firmware/fsm_msg_tendermint.h |
| 136 | 29 | lib/firmware/fsm_msg_thorchain.h |
| 37 | 55 | lib/firmware/fsm_msg_ton.h |
| 111 | 15 | lib/firmware/fsm_msg_tron.h |
| 1699 | 0 | lib/firmware/fsm_msg_zcash.h |
| 439 | 0 | lib/firmware/hive.c |
| 46 | 8 | lib/firmware/home_sm.c |
| 389 | 97 | lib/firmware/mayachain.c |
| 54 | 0 | lib/firmware/messagemap.def |
| 5 | 2 | lib/firmware/nano.c |
| 270 | 37 | lib/firmware/osmosis.c |
| 77 | 6 | lib/firmware/passphrase_sm.c |
| 47 | 21 | lib/firmware/pin_sm.c |
| 213 | 90 | lib/firmware/recovery_cipher.c |
| 482 | 96 | lib/firmware/reset.c |
| 65 | 10 | lib/firmware/ripple.c |
| 1046 | 0 | lib/firmware/signed_metadata.c |
| 549 | 59 | lib/firmware/signing.c |
| 193 | 65 | lib/firmware/signtx_tendermint.c |
| 538 | 41 | lib/firmware/solana.c |
| 306 | 42 | lib/firmware/storage.c |
| 8 | 0 | lib/firmware/storage.h |
| 180 | 4 | lib/firmware/tendermint.c |
| 318 | 46 | lib/firmware/thorchain.c |
| 5 | 3 | lib/firmware/tiny-json.c |
| 5 | 3 | lib/firmware/ton.c |
| 180 | 18 | lib/firmware/transaction.c |
| 364 | 1 | lib/firmware/tron.c |
| 14 | 7 | lib/firmware/txin_check.c |
| 11 | 2 | lib/firmware/u2f.c |
| 1237 | 0 | lib/firmware/zcash.c |
| 2 | 1 | lib/rand/CMakeLists.txt |
| 97 | 13 | lib/rand/rng.c |
| 348 | 0 | lib/rand/rng_health.c |
| 18 | 0 | lib/transport/CMakeLists.txt |
| 2 | 1 | lib/transport/pb_decode.c |
| 1 | 1 | scripts/build/docker/device/debug.sh |
| 7 | 2 | scripts/build/docker/device/release.sh |
| 1 | 1 | scripts/build/docker/emulator/debug.sh |
| 1 | 0 | scripts/cppcheck-version |
| 32 | 0 | scripts/cppcheck.sh |
| 10 | 2 | scripts/emulator/Dockerfile |
| 111 | 0 | scripts/emulator/capture-dice-flow.py |
| 99 | 0 | scripts/emulator/capture-thor-percent.py |
| 12 | 0 | scripts/emulator/docker-compose.bitcoin-only.yml |
| 14 | 0 | scripts/emulator/docker-compose.yml |
| 19 | 1 | scripts/emulator/firmware-unit.sh |
| 87 | 65 | scripts/emulator/python-keepkey-tests.sh |
| 1 | 1 | scripts/emulator/python-keepkey.Dockerfile |
| 443 | 0 | scripts/emulator/test_stack07_regressions.py |
| 36 | 0 | scripts/emulator/test_stack09_integration.py |
| 141 | 0 | scripts/emulator/test_stack10_regressions.py |
| 623 | 68 | scripts/generate-test-report.py |
| 103 | 0 | scripts/preflight.sh |
| 92 | 0 | scripts/preflight_checks.py |
| 249 | 0 | scripts/test_generate_test_report.py |
| 124 | 0 | scripts/test_preflight_checks.py |
| 91 | 0 | scripts/test_preflight_cppcheck.py |
| 85 | 0 | scripts/tests/test_usb_receive_callbacks.py |
| 36 | 0 | scripts/verify-token-def.py |
| 1 | 0 | tools/CMakeLists.txt |
| 124 | 0 | tools/check_sram_budget.py |
| 33 | 11 | tools/emulator/CMakeLists.txt |
| 20 | 0 | tools/erc7730-validate/CMakeLists.txt |
| 76 | 0 | tools/erc7730-validate/main.c |
| 3 | 1 | tools/firmware/CMakeLists.txt |
| 10 | 0 | tools/firmware/keepkey.ld |
| 14 | 9 | tools/firmware/keepkey_main.c |
| 10 | 0 | tools/sram-budgets.json |
| 251 | 0 | tools/verify_dice_seed.py |
| 1 | 1 | unittests/board/CMakeLists.txt |
| 490 | 2 | unittests/board/board.cpp |
| 6 | 2 | unittests/crypto/CMakeLists.txt |
| 500 | 0 | unittests/crypto/bip340.cpp |
| 55 | 7 | unittests/firmware/CMakeLists.txt |
| 48 | 0 | unittests/firmware/app_confirm.cpp |
| 302 | 0 | unittests/firmware/authenticator.cpp |
| 151 | 0 | unittests/firmware/binance.cpp |
| 28 | 2 | unittests/firmware/coins.cpp |
| 141 | 0 | unittests/firmware/confirm_test_utils.cpp |
| 166 | 8 | unittests/firmware/cosmos.cpp |
| 116 | 0 | unittests/firmware/dice.cpp |
| 194 | 0 | unittests/firmware/eip712.cpp |
| 1076 | 0 | unittests/firmware/eip712_stream.cpp |
| 90 | 3 | unittests/firmware/eos.cpp |
| 50 | 0 | unittests/firmware/eos_authorization.cpp |
| 16 | 0 | unittests/firmware/eos_authorization_probe.c |
| 174 | 0 | unittests/firmware/erc7730_abi.cpp |
| 371 | 0 | unittests/firmware/erc7730_abi_stream.cpp |
| 1901 | 0 | unittests/firmware/erc7730_catalog.cpp |
| 105 | 0 | unittests/firmware/erc7730_condition.cpp |
| 304 | 0 | unittests/firmware/erc7730_field.cpp |
| 224 | 0 | unittests/firmware/erc7730_format.cpp |
| 411 | 0 | unittests/firmware/erc7730_program.cpp |
| 74 | 0 | unittests/firmware/erc7730_tx.cpp |
| 207 | 0 | unittests/firmware/erc7730_workflow.cpp |
| 709 | 1 | unittests/firmware/ethereum.cpp |
| 1204 | 0 | unittests/firmware/fsm.cpp |
| 783 | 0 | unittests/firmware/hive.cpp |
| 20 | 0 | unittests/firmware/kkconfirm_driver.h |
| 54 | 0 | unittests/firmware/liquidity_key_probe.c |
| 390 | 7 | unittests/firmware/mayachain.cpp |
| 11 | 0 | unittests/firmware/messages_probe.c |
| 35 | 0 | unittests/firmware/nanopb_bounds.cpp |
| 153 | 0 | unittests/firmware/osmosis.cpp |
| 46 | 0 | unittests/firmware/recovery.cpp |
| 37 | 0 | unittests/firmware/ripple.cpp |
| 297 | 0 | unittests/firmware/rng_health.cpp |
| 193 | 0 | unittests/firmware/setup_ceremony.cpp |
| 1804 | 0 | unittests/firmware/signed_metadata.cpp |
| 143 | 0 | unittests/firmware/signing.cpp |
| 969 | 15 | unittests/firmware/solana.cpp |
| 316 | 29 | unittests/firmware/storage.cpp |
| 129 | 0 | unittests/firmware/storage_cipher_probe.c |
| 24 | 0 | unittests/firmware/storage_cipher_probe.h |
| 140 | 0 | unittests/firmware/storage_passphrase.cpp |
| 28 | 0 | unittests/firmware/test_board.cpp |
| 350 | 21 | unittests/firmware/thorchain.cpp |
| 173 | 0 | unittests/firmware/transaction.cpp |
| 604 | 0 | unittests/firmware/tron.cpp |
| 169 | 0 | unittests/firmware/usb_rx.cpp |
| 2204 | 0 | unittests/firmware/zcash.cpp |
