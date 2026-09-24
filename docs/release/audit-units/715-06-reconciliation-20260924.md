# Stack 06 predecessor reconciliation and behavior matrix

Status: provisional intake, not an accepted candidate. Owner: Codex `/root`, vault agent 1. Claim: canonical `audit-claims/715-06/OWNER.md`.

## Identity and dependency gate

Published code-bearing PR #836: `b771669ba842d83790a69b6132f63cea82e5a861`, original Stack 05 base `dc644600361da15a123f0d50605220cccadd8de3`. Original adjacent diff: 26 files, 1501 additions, 1006 deletions. Runtime provider loading is inherited; the direct diff primarily changes EIP-712, liquidity contracts, transport and display. Structured EIP-712 remains disabled.

Stack 05 audit PR #858 at `41de705c9c16da65bb3c390ab8dc1136b462803c` is the provisional base, NOT an accepted Stack 05 head. Its owner retains the claim and acceptance work. Original Stack 06 replayed without conflict as `8c9a0f488`. Do not update PR #836 or request external review until the predecessor is accepted and the candidate requalified. Stack 04 itself still awaits propagation of accepted Stack 03; no full accepted-foundation ancestry claim is made.

Canonical untracked release evidence was copied to `/private/tmp/kk715-stack06-intake-evidence/canonical-release` with SHA256SUMS before relying on it. Main worktree conflict files were left intact. Master snapshot SHA256: `6b8fe1a948d62ae34a51371610dac03e02cb921ccb3a7547d50eb5a35eb71fea`.

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
