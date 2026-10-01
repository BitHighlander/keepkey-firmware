# 7b replacement stack receipt — 2026-09-27

Owner authorized a two-part D split and carrying E onto that stack. Existing
firmware PRs #863, #866, #867 and Python PRs #115/#116 remain unchanged by
this extraction. No force-push, closure, merge or product promotion.

| Unit | Firmware base/head at report freeze | Python |
| --- | --- | --- |
| D-G groups/visibility | PR #868, 5c0090e03 → 93d8fb6c2 | PR #117, 345cf97 |
| D-I iteration | PR #869, 93d8fb6c2 → 0ed026c4b | PR #118, dd7649b |
| E-R embedded calls | 0ed026c4b → report predecessor 886ce42c; final head in PR | 5c2dd4d |

The D mapping receipt accounts for all 14 original D paths and later review
findings. Additional original clusters D10 parallel arrays, D11 iteration
limits, D14 numbered titles, D18 absent indices, and original Copilot scalar
reuse belong to D-I. The original frame scratch finding belongs to D-G.
A–C retains D1/D3/D4/D5/D6/D7/D8/D12/D16, the non-iteration D11 limits,
NUL refusal and native-alias disclosure. E-R retains D2 embedded intent,
D9 callee binding, D17 refused inner definitions, D15 pager handling,
embedded D11 limits, depth/call/amount binding and E report-count fixes.
The original D13/D19 rows were never retained and remain an evidence gap.

## Historical E path mapping

Original adjacent range `26ae09fe3..ed18a68e1`, all 29 paths listed below.
Historical reports are supporting evidence on their frozen old branches;
new child reports describe their own final adjacent diffs.

| Historical E path | E-R placement |
| --- | --- |
| `.github/workflows/ci.yml` | E-R adjacent diff |
| `deps/python-keepkey` | E-R companion PR and pinned gitlink |
| `docs/release/audit-units/715-07b-formatters-audit-20260925.md` | New E-R audit/report and mapping; old receipt preserved on PR #867 |
| `docs/release/audit-units/715-07b-formatters-audit-20260925.pdf` | New E-R audit/report and mapping; old receipt preserved on PR #867 |
| `docs/release/audit-units/715-07b-reaudit-20260927-checks.json` | New E-R audit/report and mapping; old receipt preserved on PR #867 |
| `docs/release/audit-units/715-07b-reaudit-20260927.md` | New E-R audit/report and mapping; old receipt preserved on PR #867 |
| `docs/release/audit-units/715-07b-reaudit-20260927.pdf` | New E-R audit/report and mapping; old receipt preserved on PR #867 |
| `docs/release/audit-units/715-07b-split-receipt-20260926.md` | New E-R audit/report and mapping; old receipt preserved on PR #867 |
| `docs/release/audit-units/715-07b-split-receipt-20260926.pdf` | New E-R audit/report and mapping; old receipt preserved on PR #867 |
| `docs/release/audit-units/715-07b3-embedded-audit-20260926.md` | New E-R audit/report and mapping; old receipt preserved on PR #867 |
| `docs/release/audit-units/715-07b3-embedded-audit-20260926.pdf` | New E-R audit/report and mapping; old receipt preserved on PR #867 |
| `docs/security/HANDOFF-ERC7730-715-FORMATTERS.md` | E-R adjacent diff |
| `docs/security/HANDOFF-ERC7730-PHASE-E.md` | E-R adjacent diff |
| `include/keepkey/firmware/erc7730_abi_stream.h` | E-R adjacent diff |
| `include/keepkey/firmware/erc7730_capabilities.h` | E-R adjacent diff |
| `include/keepkey/firmware/erc7730_catalog.h` | E-R adjacent diff |
| `include/keepkey/firmware/erc7730_field.h` | E-R adjacent diff |
| `include/keepkey/firmware/erc7730_workflow.h` | E-R adjacent diff |
| `lib/firmware/erc7730_abi_stream.c` | E-R adjacent diff |
| `lib/firmware/erc7730_capabilities.c` | E-R adjacent diff |
| `lib/firmware/erc7730_catalog.c` | E-R adjacent diff |
| `lib/firmware/erc7730_field.c` | E-R adjacent diff |
| `lib/firmware/erc7730_workflow.c` | E-R adjacent diff |
| `lib/firmware/fsm.c` | E-R adjacent diff |
| `lib/firmware/fsm_msg_ethereum.h` | E-R adjacent diff |
| `scripts/emulator/test_stack07_regressions.py` | E-R adjacent diff; runtime relocation retained |
| `unittests/firmware/erc7730_catalog.cpp` | E-R adjacent diff |
| `unittests/firmware/erc7730_field.cpp` | E-R adjacent diff |
| `unittests/firmware/erc7730_workflow.cpp` | E-R adjacent diff |

## Recombination checks

E-R production include/lib trees equal old validated E `ed18a68e1`; Python
keepkeylib equals `fb94c5c`. D-I production equals repaired D `26ae09fe3`.
The new group native test survives both children. E-R retains the constant
intent regression and all 18 relocated D-I wire methods, including one
previously reviewed native-alias rename. Removing the group runtime method
makes the relocation coverage check fail. Raw check output is adjacent JSON.
EX39 now declares the retained group screenshots; EX16/EX33 corrections stay.

CircleCI fork checkout is repaired in D-G and inherited. Each unit gets three
review attempts; zero used at freeze. Exact-head CI and current review status
are recorded in each live PR. Successful local tests do not accept predecessor
reviews, the whole 7b stack, physical hardware or the release product.
