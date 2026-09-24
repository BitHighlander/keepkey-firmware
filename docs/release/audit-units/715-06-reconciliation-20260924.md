# Stack 06 predecessor reconciliation and behavior matrix

Status: provisional intake, not an accepted candidate. Owner: Codex `/root`, vault agent 1. Claim: canonical `audit-claims/715-06/OWNER.md`.

## Identity and dependency gate

Published code-bearing PR #836: `b771669ba842d83790a69b6132f63cea82e5a861`, original Stack 05 base `dc644600361da15a123f0d50605220cccadd8de3`. Original adjacent diff: 26 files, 1501 additions, 1006 deletions. Runtime provider loading is inherited; the direct diff primarily changes EIP-712, liquidity contracts, transport and display. Structured EIP-712 remains disabled.

Stack 05 audit PR #858 at `41de705c9c16da65bb3c390ab8dc1136b462803c` is the provisional base, NOT an accepted Stack 05 head. Its owner retains the claim and acceptance work. Original Stack 06 replayed without conflict as `8c9a0f488`. Do not update PR #836 or request external review until the predecessor is accepted and the candidate requalified. Stack 04 itself still awaits propagation of accepted Stack 03; no full accepted-foundation ancestry claim is made.

Canonical untracked release evidence was copied to `/private/tmp/kk715-stack06-intake-evidence/canonical-release` with SHA256SUMS before relying on it. Main worktree conflict files were left intact. Master snapshot SHA256: `6b8fe1a948d62ae34a51371610dac03e02cb921ccb3a7547d50eb5a35eb71fea`.

## Predecessor refresh

During intake, Stack 05 moved to `5c3f2d927f56a8646178d00c0abc9ed01c427393` (report-gate repair `86ecb29ec` and report refresh). PR #858 has no delivered review and CI is in progress. Acceptance remains pending. The provisional branch was rebased cleanly to that head; code head is `b55063ff5e8d3f2e96ffb2275be3cc24161531d0`. Original replay is now `2ec1e4d6d`; historical fix replays are `c2ba4e60c`, `f8091221f`, `b55063ff5`.

`git diff be99d50ca..b55063ff5 -- lib include unittests deps CMakeLists.txt cmake` is empty. The tests below therefore carry forward as firmware-equivalent local evidence. They are not exact-head hosted CI for the updated workflow/report generator.

## Finite batch and historical reconciliation

Scope: original Stack 06 delta, requalification of its prior fixes, and falsification of inherited transport, Ripple, policy and workflow contracts. No new chain support, release publication, predecessor claim takeover, or structured EIP-712 enablement. Missing predecessor fixes receive named dispositions; historical fixes are not automatically accepted.

| ID / behavior | Value, origin, observer, variants and phase | Allowed / forbidden behavior | Actual path and planned falsification | Initial disposition |
| --- | --- | --- | --- | --- |
| B06-001 liquidity derivation scratch | Seed-derived HDNode, RAM observer, full, failed derivation | Successful derivation only; forbid residual root/partial private key after failure | `zx_getDerivedNode`; root-load and CKD failures, subsequent call; Bitcoin-only excludes liquidity | Historical `e5bd8499b` applicable and missing; replay then test |
| B06-002 tiny receive rejection and wipe | Host credential ack and device workflow state, host/RAM observer, both variants | One failure and handler unwind; forbid hang or retained credential bytes | `tiny_msg_poll_and_buffer`, actual UDP/main/debug callbacks; malformed, valid, short, no-data/error inputs | Original Stack 06 removes predecessor safeguards; `2263bdce0` applicable and missing |
| B06-003 additive metadata | Host-supplied runtime annotations, user observing signing screens, full | Extra explanation allowed; suppressing baseline amount/calldata/fee review forbidden | `ethereum_signing_init`; v1/v2 metadata, all runtime slots, reject and hash mismatch; Bitcoin-only excludes EVM | `c20dab14d` applicable and missing |
| B06-004 session trust | AdvancedMode and provider keys, flash/session origin, host and device observer, full; policy both variants | Session-authorized use only; forbid flash resurrection and use after lock | storage read/write, clear/lock/Initialize; explicitly distinguish soft Initialize policy from lock | Inherited open prerequisite; historical `c2ddc0656` to compare, no blind replay |
| B06-005 Ripple memo | Host memo, display and signed wire bytes, full | Complete memo review and correct serialization; forbid hidden suffix or wrong 192-byte prefix | Ripple handler, 191/192/193/199-byte independent vectors and host field 0x7D | Historical `4bed97271` to compare; BTC excludes Ripple |
| B06-006 workflow deadlines | Authorized signing/setup state, host observer, both variants | Accepted progress renews deadline; polling, invalid input and empty continuation do not | Ping, dispatch, Bitcoin TxAck, recovery edits, EVM/EOS continuations; explicit diagnostic compile guards | Historical `ba52d68b6`, `2831f91b5`, `ae4061a6f` to compare; inherited pending |
| B06-007 approval and Hive failures | Host transaction content, user display/signature observer, full | Current release policy governs approval limits and exact Hive bytes | Padded zero/unlimited approval, liquidity bypass, HIVE/STEEM symbol and memo max | Prior failures need reproduction and root-cause disposition |
| B06-008 EIP-712 parser and display | Host typed JSON, user/display/hash observer, full | Disabled structured signing stays rejected; parser helpers must remain bounded | Native parser vectors and real handler refusal; compile registration inventory | Direct Stack 06 scope; pending |

## Verification and completion states

Implementation: original replay only at intake. Targeted verification, full/BTC integration, adversarial verification, ARM/resource, exact-head CI and external code review: pending. No Stack 05 acceptance, Stack 06 acceptance or release acceptance. Prior test totals are supporting historical evidence only. Do not dispatch full hosted CI while known local failures remain.

Required before review: accepted predecessor reconciliation; source-to-test and skip/guard inventory; independent negative controls; complete adjacent path/count report including final report files; PDF render inspection; exact-head validation; live target recheck. Physical device/OLED and signed upgrade remain release gates.

## Original replay path inventory

```text
-	-	docs/security/evidence/rom-printf-integer-percent/01-thorchain-withdraw-25.05pct.png
-	-	docs/security/evidence/rom-printf-integer-percent/02-thorchain-sending-eth.png
17	0	docs/security/evidence/rom-printf-integer-percent/README.md
8	5	include/keepkey/firmware/eip712.h
1	0	include/keepkey/firmware/ethereum.h
13	11	include/keepkey/firmware/ethereum_contracts/thortx.h
4	4	include/keepkey/firmware/ethereum_contracts/zxliquidtx.h
2	6	include/keepkey/firmware/thorchain.h
0	6	include/keepkey/firmware/tiny-json.h
1	1	include/keepkey/transport/messages.options
1	1	lib/board/draw.c
1	13	lib/board/messages.c
0	1	lib/firmware/CMakeLists.txt
392	328	lib/firmware/eip712.c
4	0	lib/firmware/ethereum.c
1	1	lib/firmware/ethereum_contracts.c
110	96	lib/firmware/ethereum_contracts/zxappliquid.c
155	192	lib/firmware/ethereum_contracts/zxliquidtx.c
99	0	scripts/emulator/capture-thor-percent.py
1	0	unittests/firmware/CMakeLists.txt
42	0	unittests/firmware/app_confirm.cpp
108	0	unittests/firmware/eip712.cpp
173	334	unittests/firmware/ethereum.cpp
90	0	unittests/firmware/kkconfirm_driver.cpp
20	0	unittests/firmware/kkconfirm_driver.h
258	7	unittests/firmware/signed_metadata.cpp
```

## Executed intake evidence

Tests ran against code `be99d50ca` before the report-only predecessor refresh. Full image: `sha256:a6b779e7e265579cf47ce8f2fe0cebb82ceed87d9ad0f9626334214d0160614b`; Bitcoin-only: `sha256:b06ba1a0893a1660289259449e4d10da507e954d882a7a22174e82dc1b1d9253`. Both use the pinned builder digest in `scripts/emulator/Dockerfile`. Exact top-level submodule trees were exported from the pinned commits, plus Python Ethereum list `89a64f717e1690bb31adb3e4c38e23640357333c`; unused nested upstream crypto submodules were not initialized. No dependency pointer changed.

| Check | Outcome | Scope / limits |
| --- | --- | --- |
| Full native `make xunit` | PASS: 445 firmware, 19 board, 18 crypto | Ordinary compile guards; does not establish hidden workflow contracts or separate Zcash crypto suite |
| Bitcoin-only native `make xunit` | PASS: 122 firmware, 19 board, 18 crypto | Altcoin suites excluded by product configuration |
| Guarded full diagnostic | FAIL: 10 / 35 Fsm/AutoLockProgress tests | Explicit `-DKK_FINAL_POLICY_TESTS`; separate diagnostic container, no candidate macro change |
| Guarded Bitcoin-only diagnostic | FAIL: 6 / 26 tests | Same explicit diagnostic flag |
| Additive metadata host module | PASS: 5 / 5, none skipped | v1, v2, all runtime slots, absent signer and bad signature |
| Session-trust + Ripple host modules | FAIL: 5, PASS: 2, SKIP: 3 | Four session failures, one Ripple memo failure; two power-cycle checks lacked owned emulator binary; pre-7.15 memo-refusal test excluded by version |
| Tiny rejection negative control | Expected FAIL: 1 / 1 in each variant | Remove rejection exit/Cancel-buffer clearing in disposable container; positive test passed ordinary native runs |
| Adjacent whitespace check | PASS | `git diff --check 5c3f2d927..b55063ff5` |

Host tests used the exact pinned Python source mounted read-only in `kk715-stack05-python:latest` (reused dependency environment), isolated Docker network and candidate full emulator. No staged-capability skip list was supplied for the focused tests. Initial tool invocations with explicit platform metadata and an incorrect Ripple test filename did not run tests; corrected invocations above are the evidence. All failure counts are assertions, not independently proven root-cause counts.

### Executed diagnostic failures

**full**

- `Fsm.DispatchScrubsDerivedKeyScratchAfterHandler`
- `Fsm.CrossWorkflowAcknowledgementsTerminateTheActiveSigner`
- `Fsm.PaddedZeroUnlimitedApprovalReachesTheGlobalRefusal`
- `AutoLockProgress.FeaturePollingCannotKeepStalledSigningUnlocked`
- `AutoLockProgress.ValidBitcoinStreamProgressRenewsTheIdleDeadline`
- `AutoLockProgress.ProtectedPingCannotSuspendAnOlderSigningSession`
- `AutoLockProgress.TopLevelConfirmationEndsAnOlderSigningSession`
- `AutoLockProgress.RecoveryEditsRenewButPollingAndEmptyDeleteDoNot`
- `AutoLockProgress.EthereumChunksRenewButFeaturePollingDoesNot`
- `AutoLockProgress.EosDataProgressRenewsButEmptyChunksDoNot`

**btc**

- `Fsm.DispatchScrubsDerivedKeyScratchAfterHandler`
- `AutoLockProgress.FeaturePollingCannotKeepStalledSigningUnlocked`
- `AutoLockProgress.ValidBitcoinStreamProgressRenewsTheIdleDeadline`
- `AutoLockProgress.ProtectedPingCannotSuspendAnOlderSigningSession`
- `AutoLockProgress.TopLevelConfirmationEndsAnOlderSigningSession`
- `AutoLockProgress.RecoveryEditsRenewButPollingAndEmptyDeleteDoNot`

### Disposition update and remaining contract gaps

- B06-001: fix replayed; ordinary suite passes. Explicit injected root-load/CKD failure with RAM observation is still missing; do not close on source inspection alone.
- B06-002: fix replayed; actual UDP malformed-ack assertion passes in both builds and its negative control fails. Blocking wait, debug callback, short/no-data/error paths and direct post-copy tiny-storage inspection still need coverage before full security closure.
- B06-003: fix replayed; five pinned host assertions pass. Software targeted verification only; independent mutation and full integration remain pending.
- B06-004: inherited defect reproduced. ClearSession leaves AdvancedMode armed; disabling AdvancedMode does not revoke signer; ClearSession and Initialize preserve signer trust. Power-cycle cases remain unexecuted here. Historical storage fix alone must be checked against the distinct soft-Initialize policy and signer contracts.
- B06-005: inherited memo refusal reproduced on declared 7.15; 192-byte serializer boundary still uses `< 192`. Host boundary fix requires its own pin/publication reconciliation. No Ripple support change was silently added to Stack 06.
- B06-006: guarded diagnostics reproduce missing predecessor workflow contracts in both variants. Historical dispatch/progress fixes remain proposed evidence, not accepted upstream content. Ordinary green results cannot waive these failures.
- B06-007: padded-zero/unlimited-approval refusal fails in the full diagnostic. Hive and other approval host failures remain pending reproduction.
- B06-008: parser tests execute in ordinary full build; structured signing remains disabled. This is not authorization to enable it.
- **B06-009, new verification gap:** original Stack 06 adds `unittests/firmware/app_confirm.cpp` and `kkconfirm_driver.cpp`, but neither is registered in firmware CMake. The AppConfirm file calls `confirm_bytes_is_text`, which has no declaration or implementation in this candidate. The existing compiled `confirm_test_utils.cpp` already supplies driver functions. Do not count these orphan files as test coverage or register the duplicate driver blindly. Resolve their source provenance and intended text/hex policy before closing the display review.

The shared staged-capability list explicitly excludes Ripple memo, session trust and workflow unwind checks. That explains how broad hosted checks can pass while these product contracts fail; it does not close them. The next required dependency is acceptance/reconciliation of Stack 05 and propagation of the accepted predecessor security contracts, followed by the remaining Stack 06 property checks, full/BTC host suites, ARM/resource and exact-head CI. No code-review readiness, PDF preflight, external review or release acceptance is claimed.

## Evidence bundle

`715-06-intake-evidence-20260924.tgz` preserves native/diagnostic/host logs, XML, mutation scripts and original replay inventory. Each included file is hashed in the accompanying manifest. Canonical untracked evidence snapshot remains separately preserved at the absolute path above; it is not represented as a committed predecessor handoff.

## Remediation continuation after Stack 05 completion

The owner confirmed Stack 05 is complete and directed completion of Stack 06. Accepted audit predecessor remains `5c3f2d927`; prior intake statements calling that checkpoint pending are historical. Release integration and physical gates remain separate.

The finite Stack 06 batch now explicitly includes the inherited security interactions reproduced at intake: protected Ping, Bitcoin/EVM/EOS/recovery progress, dispatch authorization/scratch cleanup, session-only AdvancedMode and signer revocation, complete Ripple memo review/serialization, and unlimited-approval refusal. These repairs are carried in this unit without rewriting the other agents' completed branches. Historical fixes were rechecked against current source and replayed as `818ce54ab`, `7ea2ef731`, `b16e76e11`, `0583984dc`, and `e57fc1384`.

Additional remediation revokes runtime signers on Initialize and when AdvancedMode is disabled; moves the unlimited-approval check ahead of specialized contract confirmation; replaces orphan display tests with registered tests of exact escaped bytes and pagination; removes the unused duplicate confirmation driver implementation while retaining its used header; adds a test-only fault injection probe for liquidity root/partial-key cleanup. The ordinary workflow suite now compiles the previously hidden assertions. CI no longer skips session-trust-lifetime, prompt-workflow-unwind or ripple-memo-policy.

**Verification is blocked, not complete.** The host data volume reached 100% capacity (172 MiB available at failure), and Docker's containerd metadata filesystem became read-only. The first remediated full build found the removed confirmation-driver header was still included; the header was restored. The first remediated Bitcoin-only build completed, but its native test container could not start. Subsequent source/test additions have not built. Neither the earlier intake passes nor the incomplete builds validate this repaired candidate.

Local `actionlint .github/workflows/ci.yml`, six Python report-variant validator tests, and adjacent whitespace checks pass. Remaining: restore Docker after freeing disk space; build/run full and Bitcoin-only native and guarded/property tests; injected key-failure and transport falsification; complete host/OLED, owned power-cycle, ARM/resource and report gates; publish/verify fetchability of host dependency `b745562be6a13cc83b2a547d7ef86637f4556dbb` (currently retained in the main submodule object store) and reconcile its submodule URL before hosted CI; final adjacent report/PDF, exact-head CI and authorized review. No Copilot request, PR update or release acceptance occurred during this continuation.
