# P02 per-commit line inventory

Immutable range: `51411c4a7c96137bc80f8b99fa1690c4e385f7fd..947f5c29ab0b9a94baa44b33507bddcb0e13e449`.

Historical report commits are included as evidence-only changes; their line totals do not sum to the net review diff. New findings and behavior/test mappings are in P02-INTERNAL-ROUND2-20260923.md.

## 5e0151438c69 — docs(audit): start 7.15 stack 01 review intake

| Added | Deleted | Path |
| ---: | ---: | --- |
| 70 | 0 | docs/release/audit-units/715-01-review-20260923.md |

## cbc725dc6653 — fix(emulator): keep progress animation active during host polling

| Added | Deleted | Path |
| ---: | ---: | --- |
| 11 | 0 | docs/release/audit-units/715-01-review-20260923.md |
| 2 | 0 | lib/board/udp.c |

## 6925437743d9 — test(emulator): verify host-wait progress polling

| Added | Deleted | Path |
| ---: | ---: | --- |
| 10 | 3 | docs/release/audit-units/715-01-review-20260923.md |
| 15 | 0 | unittests/board/board.cpp |

## 4f3daef3096d — docs(audit): record complete local suite results

| Added | Deleted | Path |
| ---: | ---: | --- |
| 4 | 2 | docs/release/audit-units/715-01-review-20260923.md |

## 199e491e9dc9 — fix(session): count accepted workflow progress for auto-lock

| Added | Deleted | Path |
| ---: | ---: | --- |
| 4 | 0 | include/keepkey/board/messages.h |
| 7 | 0 | lib/board/usb.c |
| 26 | 9 | lib/firmware/fsm.c |
| 7 | 7 | lib/firmware/home_sm.c |
| 42 | 11 | unittests/firmware/fsm.cpp |

## a4c4d96f2bc7 — docs(audit): record Stack 01 findings and evidence

| Added | Deleted | Path |
| ---: | ---: | --- |
| 239 | 24 | docs/release/audit-units/715-01-review-20260923.md |
| - | - | docs/release/audit-units/715-01-review-20260923.pdf |

## cec3cac24873 — docs(audit): freeze complete Stack 01 PR inventory

| Added | Deleted | Path |
| ---: | ---: | --- |
| 108 | 0 | docs/release/audit-units/715-01-review-20260923.md |
| - | - | docs/release/audit-units/715-01-review-20260923.pdf |

## 5e20b18c1da4 — fix(p02): enforce signing boundaries at dispatch and protected Ping

| Added | Deleted | Path |
| ---: | ---: | --- |
| 19 | 0 | lib/board/messages.c |
| 10 | 0 | lib/firmware/fsm_msg_common.h |
| 0 | 8 | unittests/firmware/fsm.cpp |
| 38 | 0 | unittests/firmware/usb_rx.cpp |

## 7388977fe585 — fix(p02): terminate foreign acknowledgements in credential and button waits

| Added | Deleted | Path |
| ---: | ---: | --- |
| 2 | 0 | include/keepkey/board/messages.h |
| 5 | 1 | lib/board/confirm_sm.c |
| 5 | 0 | lib/board/messages.c |
| 8 | 0 | lib/firmware/passphrase_sm.c |
| 3 | 0 | lib/firmware/pin_sm.c |
| 62 | 0 | unittests/firmware/usb_rx.cpp |

## a6827b7d8c07 — test(p02): check soft Initialize authorization in both variants

| Added | Deleted | Path |
| ---: | ---: | --- |
| 21 | 0 | unittests/firmware/storage_passphrase.cpp |

## 0cf8a82b42c5 — test(p02): include C++ headers before firmware character macros

| Added | Deleted | Path |
| ---: | ---: | --- |
| 2 | 1 | unittests/firmware/usb_rx.cpp |

## 87447127e071 — test(p02): verify terminal tiny failures over the host transport

| Added | Deleted | Path |
| ---: | ---: | --- |
| 38 | 0 | unittests/host/test_p02_transport.py |

## 2b1143768b1b — fix(p02): terminate tiny waits on short receive packets

| Added | Deleted | Path |
| ---: | ---: | --- |
| 2 | 0 | include/keepkey/board/messages.h |
| 11 | 1 | lib/board/messages.c |
| 8 | 2 | lib/board/usb.c |
| 11 | 3 | unittests/firmware/usb_rx.cpp |

## 3ade61348773 — test(p02): check short-packet rejection over the host transport

| Added | Deleted | Path |
| ---: | ---: | --- |
| 10 | 0 | unittests/host/test_p02_transport.py |

## 173752ec4af4 — docs(p02): record local fixes, exact checks and pending integration gates

| Added | Deleted | Path |
| ---: | ---: | --- |
| 36 | 0 | docs/release/audit-units/P02-requalification-20260923-artifacts.json |
| 227 | 0 | docs/release/audit-units/P02-requalification-20260923.md |
| - | - | docs/release/audit-units/P02-requalification-20260923.pdf |

## 07e9389692eb — docs(p02): inventory the complete local candidate including evidence

| Added | Deleted | Path |
| ---: | ---: | --- |
| 20 | 1 | docs/release/audit-units/P02-requalification-20260923.md |
| - | - | docs/release/audit-units/P02-requalification-20260923.pdf |

## a6a8b6d73a29 — docs(p02): freeze the verified predecessor-range report

| Added | Deleted | Path |
| ---: | ---: | --- |
| 2 | 2 | docs/release/audit-units/P02-requalification-20260923.md |
| - | - | docs/release/audit-units/P02-requalification-20260923.pdf |

## b786ec9918c7 — docs(p02): define the final-review readiness batch

| Added | Deleted | Path |
| ---: | ---: | --- |
| 26 | 0 | docs/release/audit-units/P02-readiness-manifest-20260923.md |

## 2b7054cbb1d4 — fix(signing): renew idle deadline on accepted Bitcoin stages

| Added | Deleted | Path |
| ---: | ---: | --- |
| 19 | 13 | lib/firmware/signing.c |
| 0 | 2 | unittests/firmware/fsm.cpp |

## 4ae9f84ef368 — fix(fsm): renew idle deadline for validated workflow progress

| Added | Deleted | Path |
| ---: | ---: | --- |
| 2 | 0 | lib/firmware/ethereum.c |
| 6 | 0 | lib/firmware/fsm_msg_eos.h |
| 2 | 0 | lib/firmware/recovery_cipher.c |
| 0 | 8 | unittests/firmware/fsm.cpp |

## 89ea303cc531 — test(recovery): reset RAM storage after erasing test flash

| Added | Deleted | Path |
| ---: | ---: | --- |
| 8 | 0 | unittests/firmware/recovery.cpp |

## 518608729fe7 — fix(ethereum): restore unlimited approval refusal for padded zero value

| Added | Deleted | Path |
| ---: | ---: | --- |
| 6 | 0 | docs/release/audit-units/P02-readiness-manifest-20260923.md |
| 21 | 0 | lib/firmware/ethereum.c |
| 0 | 2 | unittests/firmware/fsm.cpp |

## 0646ae6eb307 — merge: reconcile Stack 01 validated progress with P02 transport fixes

| Added | Deleted | Path |
| ---: | ---: | --- |
| 413 | 0 | docs/release/audit-units/715-01-review-20260923.md |
| - | - | docs/release/audit-units/715-01-review-20260923.pdf |
| 6 | 0 | docs/release/audit-units/P02-readiness-manifest-20260923.md |
| 4 | 0 | include/keepkey/board/messages.h |
| 2 | 0 | lib/board/udp.c |
| 7 | 0 | lib/board/usb.c |
| 2 | 0 | lib/firmware/fsm_msg_binance.h |
| 2 | 0 | lib/firmware/fsm_msg_cosmos.h |
| 2 | 0 | lib/firmware/fsm_msg_mayachain.h |
| 2 | 0 | lib/firmware/fsm_msg_osmosis.h |
| 2 | 0 | lib/firmware/fsm_msg_tendermint.h |
| 2 | 0 | lib/firmware/fsm_msg_thorchain.h |
| 1 | 0 | lib/firmware/reset.c |
| 15 | 0 | unittests/board/board.cpp |
| 48 | 0 | unittests/firmware/fsm.cpp |

## c0b3250fece0 — ci: enforce P02 transport regressions and prompt unwind capability

| Added | Deleted | Path |
| ---: | ---: | --- |
| 1 | 1 | .github/workflows/ci.yml |
| 2 | 1 | scripts/emulator/python-keepkey-tests.sh |

## 959a6eea09d8 — audit: remediate Copilot findings and record review retrospective

| Added | Deleted | Path |
| ---: | ---: | --- |
| 33 | 1 | docs/release/audit-units/715-01-review-20260923.md |
| - | - | docs/release/audit-units/715-01-review-20260923.pdf |
| 1 | 1 | docs/security/7.14.3-bitcoin-only-dice-audit-sop.md |
| 6 | 1 | lib/board/messages.c |
| 1 | 1 | lib/firmware/fsm_msg_debug.h |
| 19 | 4 | lib/firmware/fsm_msg_zcash.h |
| 6 | 1 | lib/firmware/reset.c |
| 47 | 0 | unittests/firmware/usb_rx.cpp |

## cee6beacabf4 — docs(p02): freeze reconciled local readiness evidence

| Added | Deleted | Path |
| ---: | ---: | --- |
| 728 | 0 | docs/release/audit-units/P02-readiness-20260923-artifacts.json |
| 3033 | 0 | docs/release/audit-units/P02-readiness-20260923-skips.json |
| 198 | 0 | docs/release/audit-units/P02-readiness-20260923.md |
| - | - | docs/release/audit-units/P02-readiness-20260923.pdf |

## fa9bb4f5915e — docs(p02): include readiness artifacts in final adjacent inventory

| Added | Deleted | Path |
| ---: | ---: | --- |
| 6 | 2 | docs/release/audit-units/P02-readiness-20260923.md |
| - | - | docs/release/audit-units/P02-readiness-20260923.pdf |

## 139c546796fb — docs(p02): seal stable readiness inventory

| Added | Deleted | Path |
| ---: | ---: | --- |
| 3 | 3 | docs/release/audit-units/P02-readiness-20260923.md |
| - | - | docs/release/audit-units/P02-readiness-20260923.pdf |

## 23b3c16b1b43 — style: format Copilot remediation for CI

| Added | Deleted | Path |
| ---: | ---: | --- |
| 2 | 1 | lib/firmware/fsm_msg_zcash.h |
| 4 | 4 | lib/firmware/reset.c |

## cfaa4d282f42 — ci: recognize two recorded P02 ELF hashes as evidence checksums

| Added | Deleted | Path |
| ---: | ---: | --- |
| 8 | 0 | .gitleaks.toml |

## 38ae657b097c — docs(p02): record CI checksum false-positive disposition

| Added | Deleted | Path |
| ---: | ---: | --- |
| 2 | 0 | docs/release/audit-units/P02-readiness-20260923-artifacts.json |
| 41 | 3 | docs/release/audit-units/P02-readiness-20260923.md |
| - | - | docs/release/audit-units/P02-readiness-20260923.pdf |

## 095abe7fd221 — docs(p02): refresh corrected CI candidate inventory

| Added | Deleted | Path |
| ---: | ---: | --- |
| 4 | 4 | docs/release/audit-units/P02-readiness-20260923.md |
| - | - | docs/release/audit-units/P02-readiness-20260923.pdf |

## ecd5705e4255 — docs(p02): seal corrected CI candidate receipt

| Added | Deleted | Path |
| ---: | ---: | --- |
| 2 | 2 | docs/release/audit-units/P02-readiness-20260923.md |
| - | - | docs/release/audit-units/P02-readiness-20260923.pdf |

## f5a6fe70c6cf — merge: retain Stack 01 review fixes across P02 transport and dice waits

| Added | Deleted | Path |
| ---: | ---: | --- |
| 33 | 1 | docs/release/audit-units/715-01-review-20260923.md |
| - | - | docs/release/audit-units/715-01-review-20260923.pdf |
| 6 | 0 | docs/release/audit-units/P02-readiness-manifest-20260923.md |
| 1 | 1 | docs/security/7.14.3-bitcoin-only-dice-audit-sop.md |
| 1 | 0 | lib/board/messages.c |
| 1 | 1 | lib/firmware/fsm_msg_debug.h |
| 6 | 1 | lib/firmware/reset.c |
| 48 | 0 | unittests/firmware/usb_rx.cpp |
| 26 | 0 | unittests/host/test_p02_transport.py |

## 381e0296ef7d — docs(p02): record proposed code-bearing review preflight and entry gates

| Added | Deleted | Path |
| ---: | ---: | --- |
| 42 | 0 | docs/release/audit-units/P02-PR-PREFLIGHT-20260923.md |

## 5b7668f8cade — docs(p02): freeze current predecessor integration evidence

| Added | Deleted | Path |
| ---: | ---: | --- |
| 722 | 674 | docs/release/audit-units/P02-readiness-20260923-artifacts.json |
| 4 | 4 | docs/release/audit-units/P02-readiness-20260923-skips.json |
| 66 | 16 | docs/release/audit-units/P02-readiness-20260923.md |
| - | - | docs/release/audit-units/P02-readiness-20260923.pdf |

## e19343102de5 — docs(p02): refresh current integration final inventory

| Added | Deleted | Path |
| ---: | ---: | --- |
| 2 | 0 | docs/release/audit-units/P02-readiness-20260923-artifacts.json |
| 4 | 4 | docs/release/audit-units/P02-readiness-20260923.md |
| - | - | docs/release/audit-units/P02-readiness-20260923.pdf |

## 5a59d8a5edcf — docs(p02): seal current predecessor receipt

| Added | Deleted | Path |
| ---: | ---: | --- |
| 3 | 3 | docs/release/audit-units/P02-readiness-20260923.md |
| - | - | docs/release/audit-units/P02-readiness-20260923.pdf |

## 84483458cb31 — docs(audit): require property and phase evidence before security closure

| Added | Deleted | Path |
| ---: | ---: | --- |
| 39 | 0 | docs/release/REHEARSAL-SOP.md |

## 4b00c41479de — fix(p02): close dice debug disclosures and verify workflow boundaries

| Added | Deleted | Path |
| ---: | ---: | --- |
| 1 | 0 | .github/workflows/ci.yml |
| 1 | 1 | deps/python-keepkey |
| 49 | 0 | docs/release/audit-units/P02-INTERNAL-ROUND2-20260923.md |
| 5 | 0 | docs/release/audit-units/P02-readiness-20260923.md |
| 5 | 0 | docs/release/audit-units/P02-requalification-20260923.md |
| 20 | 11 | docs/security/7.14.3-bitcoin-only-dice-audit-sop.md |
| 3 | 1 | include/keepkey/firmware/reset.h |
| 3 | 1 | lib/board/messages.c |
| 1 | 53 | lib/board/usb.c |
| 56 | 0 | lib/board/usb_rx_callbacks.h |
| 15 | 0 | lib/firmware/fsm_msg_debug.h |
| 22 | 18 | lib/firmware/reset.c |
| 3 | 0 | scripts/emulator/python-keepkey-tests.sh |
| 2 | 0 | unittests/firmware/CMakeLists.txt |
| 697 | 5 | unittests/firmware/fsm.cpp |
| 97 | 0 | unittests/firmware/reset_policy_probe.c |
| 72 | 0 | unittests/firmware/usb_callbacks.cpp |
| 34 | 15 | unittests/firmware/usb_rx.cpp |
| 23 | 2 | unittests/host/test_p02_transport.py |

## 413790faf767 — fix(p02): reconcile latest predecessor guards and enforce audit evidence

| Added | Deleted | Path |
| ---: | ---: | --- |
| 10 | 3 | .github/workflows/ci.yml |
| 13 | 3 | CMakeLists.txt |
| 12 | 1 | docs/DiceEntropy.md |
| 21 | 0 | docs/release/audit-units/P02-INTERNAL-ROUND2-20260923.md |
| 2 | 0 | include/keepkey/rand/rng_health.h |
| 0 | 2 | lib/firmware/CMakeLists.txt |
| 5 | 4 | lib/firmware/ethereum.c |
| 34 | 13 | lib/firmware/fsm.c |
| 9 | 0 | lib/firmware/reset.c |
| 2 | 0 | lib/firmware/signed_metadata.c |
| 5 | 0 | lib/rand/rng_health.c |
| 10 | 1 | scripts/generate-test-report.py |
| 73 | 0 | unittests/firmware/fsm.cpp |
| 2 | 3 | unittests/firmware/rng_health.cpp |
| 20 | 6 | unittests/firmware/signed_metadata.cpp |

## 4982da03d04e — test(p02): assert the existing storage-lock dispatch refusal code

| Added | Deleted | Path |
| ---: | ---: | --- |
| 1 | 2 | unittests/firmware/fsm.cpp |

## 175edb7d3fe6 — test(p02): bind dormant Tendermint disposition to the message map

| Added | Deleted | Path |
| ---: | ---: | --- |
| 10 | 0 | unittests/firmware/fsm.cpp |

## 947f5c29ab0b — style(p02): normalize the session regression declaration

| Added | Deleted | Path |
| ---: | ---: | --- |
| 2 | 1 | unittests/firmware/storage_passphrase.cpp |

