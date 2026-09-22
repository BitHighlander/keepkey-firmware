# 7.15 block 00a release-foundation receipt

Status: `REVIEW` (Copilot follow-up and current-head hosted qualification pending)

## Immutable review boundary

- Pull request: `BitHighlander/keepkey-firmware#844`
- Adjacent base: `fc1e93746132553ad98ed60f4847c8d770732bf9`
- Prior PR head: `f099dfcd8de99567cece5e11646921eb61569ec2`
- Local implementation head: `7c4dceb530e45c5cabb7a377c102ee052dd6cfd0`
- Local implementation tree: `600d2ddea00c01c3eea3e79204cf5ffa08d10ebd`
- Firmware commits: 35, excluding merge commits from the count used by the audit
- Implementation diff: 193 files, 17,107 additions, 2,844 deletions, 19,951 changed lines
- python-keepkey: `c1b136a751038064c29bdf4c25d5a9bf5f8ca8aa`
- device-protocol: `8545cd5b615f5832374afbf06387a3f28869285e`
- trezor-firmware/crypto: `e8ce42f873dbdae16017122bb4fe8a949f825fc0` ([dependency PR #12](https://github.com/keepkey/trezor-firmware/pull/12))

The companion commit has canonical `reconcile/upstream-sync` ancestry and pins
device-protocol `dd9c85dc747cf965fb0e7bf49615dc9e7568ee65`. A fresh detached
worktree reproduced the exact implementation head, all direct firmware pins and
both nested companion pins without a dirty file. The canonical companion pin
is remotely reachable. Any later implementation, test, dependency or workflow
change applies the SOP invalidation matrix.

The current `a763f5f91` fresh checkout is clean with every direct pin and both
python-keepkey nested pins initialized. Trezor's nested vendor/test trees are
excluded: active firmware CMake and Docker paths consume its `crypto/` sources,
not `vendor/`, `common/defs/` or `crypto/tests/`. Both product builds pass from
the pinned source. Full deep recursion reaches unrelated Micropython/TinyUSB
hardware repositories and is not the block's reproducibility boundary.

## Block contract

Block 00a establishes the audited 7.14.x carry-forward and the release/build
foundation needed by later 7.15 blocks. It owns:

- preservation and provenance of accepted 7.14.x signing, display, storage,
  recovery, entropy and authorization hardening;
- regular and bitcoin-only build boundaries at this stack edge;
- deterministic host, emulator and ARM build/test orchestration;
- SRAM, artifact, test-report and release-evidence gates used by later blocks.

It does not own ERC-7730/runtime-provider behavior or later 7.15 chain features.
Those may not be pulled into this block merely to resolve a later-stack failure.

## Security invariants

- Every signed field introduced or modified by this block is disclosed or signing
  refuses; display state cannot be reused across transactions or authorization loss.
- Secret, recovery, authentication and scratch state is cleared on every terminal
  success, failure, cancellation and initialization boundary owned by this block.
- Storage decoders reject invalid bounds and unsupported versions without partial
  mutation; passphrase changes invalidate derived wallet state.
- Regular and bitcoin-only products contain only their declared handlers and data.
- Randomness health checks, entropy collection and firmware signing verification
  fail closed and remain within the recorded MCU resource budget.
- Release artifacts and reports identify the exact product, firmware SHA and pins.

## Required local evidence

- Adjacent-diff provenance accounting, including all merge-carried and generated files.
- Formatter, static analysis, submodule/pin and secret checks.
- Focused regressions for each block-owned security invariant.
- Pinned Docker build and native unit tests for regular and bitcoin-only products.
- Pinned Docker python integration and strict OLED evidence for both products.
- ARM builds, SRAM budget and artifact-manifest validation for both products.
- Actual pass/fail/skip totals and every expected skip disposition.
- Clean build/test dependency-graph checkout with no uncommitted pin change.

## Hosted evidence

The prior `f099dfcd8` head has one successful pull-request run:
`https://github.com/BitHighlander/keepkey-firmware/actions/runs/35629160260`.
It is supporting evidence until the local audit and Docker contract pass. Do not
rerun it if the candidate remains unchanged. The changed implementation head
requires one new hosted run after local qualification.

## Acceptance scorecard

| Measure | Limit | Current |
| --- | ---: | ---: |
| Unresolved critical/high/release-blocking findings | 0 | 3 pending reviewer disposition |
| Unresolved block-owned findings | 0 | 3 pending reviewer disposition |
| Unexplained test failures | 0 | 0 |
| Unreviewed required-test skips | 0 | 0 (ledger below) |
| Flaky retries counted as evidence | 0 | 0 |
| Stale, moving or unreachable pins | 0 | 0; companion candidate remotely fetchable by SHA |
| Adjacent changed lines | < 20,000 | 19,981 including this receipt |
| Declared capability profiles lacking Docker evidence | 0 | 0 |
| Active hosted runs for this PR/head | <= 1 | 0 |

The block becomes `ACCEPTED` only after every pending entry is replaced by a
measured result within its limit and all findings have explicit dispositions.

## Local Docker evidence

The emulator binaries were built once per profile and reused by native and
companion tests. No hosted run was requested during mutable work.

| Profile | Native | Integration | OLED audit | Evidence |
| --- | ---: | ---: | ---: | --- |
| regular | 193 firmware + 16 board + 19 crypto pass | 559 pass, 272 skip | 64 pass, 23 skip; 359 PNGs / 64 sequences | exit 0 |
| bitcoin-only | 93 firmware + 16 board + 19 crypto pass | 334 pass, 497 skip | 25 pass, 62 skip; 169 PNGs / 25 sequences | exit 0 |

Both pinned ARM builds pass. SRAM evidence records 21,312 bytes of regular and
28,268 bytes of bitcoin-only reserve against the 16,384-byte requirement; the
largest measured frame is 12,416 bytes and the required remaining margin is
4,096 bytes. Cppcheck covered 109 files with zero findings. Actionlint,
`git diff --check`, compose rendering, secret scan and the required-command shell
failure probes pass. The canonical companion deterministic gate passes 41 tests.
An initial local run omitted the declared release capability mask and failed two
later-slice reset cases; it was discarded and rerun correctly with the mask.

The skip ledger is intentional: later 7.15 capabilities are named by
`KK_RELEASE_MISSING_CAPABILITIES`; product-inapplicable cases are variant-gated;
7.15/7.16 tests remain version-gated on this 7.14.3 foundation; dylib-only cases
run in the dedicated dylib job; registry cases require the external official
registry; one PIN-timeout emulator defect and one empty burned-version set have
explicit alternate coverage. In particular, seven applicable Osmosis tests pass
and only the later `osmosis-wire-guards` overflow test skips. All five storage
upgrade/boot preservation tests execute and pass in both profiles.

## Findings

### `715-00A-001` — PR concurrency protection was removed

- Severity: operational/release-blocking for this block.
- Evidence: the adjacent diff deletes the existing workflow-level concurrency
  group, allowing superseded runs for the same PR to consume the full matrix.
- Remediation: restore PR-number-scoped concurrency with cancellation limited to
  pull-request events. Long-lived branch pushes are not cancelled.
- Validation: workflow syntax review plus one eventual frozen-head hosted run;
  no hosted run is requested during mutable local work.

### `715-00A-002` — cppcheck diagnostics abort under `bash -e`

- Severity: validation integrity/block-owned.
- Evidence: `cppcheck ...; CPPCHECK_RC=$?` exits the GitHub step immediately when
  `--error-exitcode=1` reports a finding, so annotations and the severity summary
  below it never execute. The predecessor used an OR-list for this reason.
- Remediation: initialize `CPPCHECK_RC` and capture failure with
  `cppcheck ... || CPPCHECK_RC=$?`.
- Validation: shell semantics review, local cppcheck clean-path execution and the
  eventual frozen-head hosted run. A controlled nonzero probe must also prove
  post-command diagnostics remain reachable.

### `715-00A-003` — integration jobs rebuild and retest the emulator

- Severity: operational/block-owned.
- Evidence: each product integration job rebuilt the complete emulator and reran
  firmware-unit after `build-emulator` and `unit-tests` had already built and
  exercised that product. Integration was not tied to the uploaded emulator image.
- Remediation: make integration depend on `build-emulator`, download and retag its
  exact product image, build only the companion image, and run only Python/OLED
  integration. The dedicated unit-test matrix remains authoritative.
- Validation: local compose tests for both products, workflow structure inspection,
  action syntax validation and one eventual frozen-head hosted run.

### `715-00A-004` — optional ARM outputs can mask a failed build

- Severity: release-blocking validation integrity.
- Evidence: the ARM command joins required configure/build/copy operations to
  optional map/size operations with `|| true &&`. POSIX shell list precedence can
  recover from a failed required command at that OR-list and continue successfully.
- Remediation: run the container shell with `-e`, separate required commands with
  explicit statements, and guard only the genuinely optional map/size outputs.
- Validation: action syntax, both local ARM product builds, SRAM checks and a
  controlled failing-command probe that must propagate nonzero.

### `715-00A-005` — release workflow builds an undeclared third product profile

- Severity: release-policy and resource-budget violation.
- Evidence: tag-release tests include `zcash-privacy` although the release contract
  declares only regular and bitcoin-only products.
- Remediation: remove the undeclared matrix leg. Zcash remains included in the
  regular product; there is no separately shipped privacy variant. Remove the
  stale third-product release notes and correct the regular artifact filename.
- Validation: workflow matrix inspection and both declared product qualifications.

### `715-00A-006` — alternate nanopb descriptors omit the new capacity field

- Severity: decoder integrity/block-owned.
- Evidence: `pb_field_t` gained `bytes_capacity`, but fixed-count and oneof
  initializer macros still supplied the old number of fields. Current generated
  schemas do not instantiate those paths, so ordinary builds did not expose it.
- Remediation: initialize exact byte capacity, array size and pointer positions for
  fixed-count, named-oneof and anonymous-oneof descriptor macros.
- Regression: construct fixed-count and oneof byte descriptors and assert capacity,
  stride, array count and pointer fields independently.

### `715-00A-007` — boot-time storage-version tests are silently unproven

- Severity: release-blocking validation integrity.
- Evidence: both Docker integration profiles skip four storage-version tests with
  an explicit `UNPROVEN` reason because the companion image has no `kkemu`
  executable to restart. A green aggregate therefore did not exercise the
  boot-time version gate owned by this block.
- Remediation: copy `kkemu` from the exact already-built product image into the
  companion test image as a Docker stage. Parameterize that stage per product;
  do not rebuild firmware in the companion image.
- Validation: rerun both Docker profiles and require the four boot-gate tests to
  execute rather than skip, with no new unexplained skips.

### `715-00A-008` — canonical companion coverage was pinned behind the block

- Severity: release-blocking validation integrity.
- Evidence: the firmware pinned an ancestor of the canonical companion branch,
  hiding current cross-release tests. On the canonical head, seven applicable
  Osmosis signing controls were unnecessarily version-skipped, including the
  regression proving a denomination change changes the signature. Later-stack
  capabilities also ran without the staged capability exclusions.
- Remediation: advance the gitlink on canonical ancestry, lower only the seven
  backported Osmosis controls to 7.14.2, retain the 7.15-only overflow policy,
  and declare the exact capabilities intentionally owned by later stack blocks.
- Validation: the focused Osmosis class passes seven tests with only the 7.15
  overflow-policy case skipped; rerun both complete product profiles against
  the canonical companion candidate.

### `715-00A-009` — rebuilt stack omitted audited RNG draw-time fault checks

- Severity: release-blocking, block-owned entropy integrity.
- Evidence: comparison with `audit/715-scope-repair` found that a hardware fault
  arising during the boot sample or checked draw was observed only on the next
  call, after bytes from the failed draw could escape. The persistent-error
  reset path also lacked its register-independent regression seam.
- Remediation: restore the exact audited draw-completion checks, wipe/refuse the
  affected bytes, latch before hardware reset and restore the focused tests.
- Validation: both Docker native profiles, integrations, ARM builds and SRAM
  gates must be rerun because this changes shared RNG runtime code.

### `715-00A-010` — Copilot: unit runner masked report-copy failure

- Severity: high; review `5283084230` on prior head `f099dfcd8`.
- Fix: preserve the xunit result and separately propagate status/copy failures.
- Validation: both Docker native profiles pass on implementation `7c4dceb53`.

### `715-00A-011` — Copilot: SRAM gate accepted unbounded dynamic frames

- Severity: high; the previous ARM archives contained nine unbounded frames.
- Fix: reject those records; bound Base58/Base32 arrays in firmware and crypto
  dependency PR #12; add parser and Base58 boundary regressions.
- Validation: both rebuilt ARM profiles pass the SRAM gate with no dynamic
  unbounded records and 21,312/28,268-byte reserves.

### `715-00A-012` — Copilot: storage fixture could double-initialize timers

- Severity: high; review `5283084230` on prior head `f099dfcd8`.
- Fix: use the shared `kk_test_board_init()` fixture; both native suites pass.
