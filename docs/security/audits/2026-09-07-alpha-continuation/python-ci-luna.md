> Root correction: the protocol ancestry discussion below reversed the comparison. `bee6cdd...f54f0a7` is `5 0`: bee contains f54 plus five metadata commits, with no proto/options changes. No f54 merge is required. See python-reconcile-review-sol.md for corrected evidence.

# python-keepkey alpha companion audit

Date: 2026-09-07

## Scope and source evidence

- Firmware checkout: `/Users/highlander/WebstormProjects/keepkey-stack/projects/keepkey-firmware-alphafix`
- Firmware gitlink before and after this work: `2ed835472cb9c2308a729e7ff8ccfb050fa16312`
- Companion source path: `deps/python-keepkey`
- Isolated worktree: `/private/tmp/python-keepkey-alpha-ci`
- Isolated branch: `fix/alpha-hive-wire-symbols`
- Fix commit: `d0b6669c1aa2a25298ebe786ea081f5702d3b866`
- Fix parent: `2ed835472cb9c2308a729e7ff8ccfb050fa16312`
- Firmware checkout remained dirty with pre-existing work; no firmware file or gitlink was edited by this audit.

The required release documents were read in full:

- `docs/release/BRANCHING-SOP.md`
- `docs/release/ALPHA-MERGE-HANDOFF.md`

The SOP requires alpha to pin fork masters and requires a companion change to be landed on the fork master before alpha is repinned. The handoff warns that symbol gates can miss equivalent-file swaps and dropped static helpers, and specifically requires directional review of contested files.

## Minimal Hive fix

`tests/test_msg_hive.py` already maps display names to legacy wire names with:

```python
_WIRE_SYMBOL = {"HIVE": "STEEM", "HBD": "SBD"}
```

`_Reader.asset()` returns the seven-byte symbol exactly as present on the serialized wire. The two stale expectations were corrected:

- line 356 transfer asset: `(1000, 3, "HIVE")` -> `(1000, 3, "STEEM")`
- line 402 account-create fee: `(3000, 3, "HIVE")` -> `(3000, 3, "STEEM")`

No firmware/protobuf serialization code was changed.

## Validation

From `/private/tmp/python-keepkey-alpha-ci`:

- `git diff --check`: passed before commit.
- `python3 -m py_compile tests/test_msg_hive.py`: passed.
- A source-derived helper validation executed `_asset()` and `_Reader.asset()` directly for amounts 1000 and 3000; both parsed as `(amount, 3, "STEEM")`, and the HIVE/HBD wire map remained `STEEM`/`SBD`: passed.
- `PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python PYTHONPATH=tests python3 -m unittest test_msg_hive`: collected 38 tests but all 38 failed while opening HID with `TypeError: expected bytes, NoneType found`; no HID device path is configured in this environment. The default backend cannot collect because the installed protobuf runtime rejects this repository's legacy generated bindings (`Descriptors cannot be created directly`).
- A fresh probe clone at fork `master` `999e776a6e9eb2c21df796609bea3626d45f6aa7` accepted `git diff d0b6669^ d0b6669 | git apply --check`: passed. The Hive test file is byte-identical at `999e776` and pinned `2ed8354`, so the two-line fix has clean cherry-pick context.

## Ancestry and reconciliation findings

Reference tips:

| ref | commit | subject |
|---|---|---|
| fork `master` | `999e776a6e9eb2c21df796609bea3626d45f6aa7` | Merge PR #54, atlas storage gate names |
| pinned companion | `2ed835472cb9c2308a729e7ff8ccfb050fa16312` | test unified firmware roll-up |
| alpha companion | `ff3496846a301838874feb0d62dc96191aa82636` | reconcile Zcash shielding coverage |

Measured with `git rev-list --left-right --count`:

- `999e776...2ed8354`: `191 83` (191 commits only on fork master; 83 only on pinned).
- `ff349684...2ed8354`: `28 15` (28 only on alpha tip; 15 only on pinned).
- `999e776...ff349684`: `191 96`.

Merge bases:

- fork master vs pinned: `075a719eb377beee0f0247bf56947de65ce87a89`
- alpha vs pinned: `75028c4cbd3ddac272c50b55be75bc54511248d3`

`git merge-tree --name-only --no-messages 999e776 2ed8354` reports 38 content-conflict paths, including `device-protocol`, `keepkeylib/client.py`, `keepkeylib/eip712_stream.py`, `keepkeylib/messages_solana_pb2.py`, and the EIP-712, Solana, Ethereum, Maya, Osmosis, Thorchain, TON, storage, and CI tests. A merge-tree probe of `ff349684` with `2ed8354` produced no conflict paths.

The alpha tip is newer in its hermetic test work but must not be used as a blind replacement for the pinned tree. Relative to pinned `2ed8354`, alpha `ff349684`:

- deletes `tests/test_msg_solana_display_disclosure.py` (145 lines); this coverage originated in `4ab0d91` and exercises signed-byte-to-OLED binding.
- reduces `tests/test_msg_eip712_streaming.py` by 77 net lines (`12` added, `89` deleted), dropping the duplicate/overlong/malformed canonical-identifier checks and the realistic Permit2 nested-batch test, and changes the structured endpoint test from AdvancedMode-off success to an AdvancedMode gate.
- lacks pinned commits `901a774` (structured EIP-712 without Advanced Mode), `f15e7d0` (canonical identifier binding), and `0f02409` (Permit2 batch shape).

These are coverage losses, so `ff349684` must not be repinned over the pinned tree without an explicit reconciliation that restores or adjudicates each test.

## Safe integration plan

1. Review merge candidate `eaae16db64ae02d2f84c15bd65bb1276f0d7d8d6` from `/private/tmp/python-keepkey-reconcile`. Its first parent is fork master `999e776`; its second parent is fixed pinned tip `d0b6669`; its tree preserves the pinned security/test content and the two-line Hive correction.
2. Land device-protocol `f54f0a7dabb2d38c6f423bf6b6a68e8f979b1b53` on `BitHighlander/device-protocol` master, then land the reconciled Python merge into `BitHighlander/python-keepkey` master. Do not merge the full pinned tip through a blind reset; the histories diverge by 191/83 commits and the deliberate merge had 38 conflict paths.
3. After the companion master contains the merge and device-protocol pin is resolvable from its master, update firmware alpha's gitlink to the resulting Python fork-master commit and run the firmware gates and companion CI. Keep `2ed8354` as the audit baseline until both companion landings are complete.
4. Separately reconcile any alpha hermetic fixture/report commits against this preserved tree. Start with directional file review, preserve the EIP-712 identifier and Permit2 tests and the Solana OLED disclosure test, and adjudicate generated protobuf changes explicitly. Do not reset or blindly repin to `ff349684`.

The initial minimal-fix branch was intentionally kept separate while the 38-path master/pinned merge was assessed. The alpha tip demonstrably drops strengthened coverage, so the follow-up section records the preserved local reconciliation rather than a blind repin.

## Reconciled fork-master candidate

That initial plan was superseded by a local reconciliation so the pinned security tree is not dropped. The isolated checkout `/private/tmp/python-keepkey-reconcile` contains:

- branch `reconcile/master-pinned-hive`
- merge commit `eaae16db64ae02d2f84c15bd65bb1276f0d7d8d6`
- first parent fork master `999e776a6e9eb2c21df796609bea3626d45f6aa7`
- second parent fixed pinned tip `d0b6669c1aa2a25298ebe786ea081f5702d3b866`
- working tree clean; no push performed

The resulting tree is byte-identical to `d0b6669` (`git diff eaae16d d0b6669` is empty). This is deliberate: the directional review found the pinned tree to contain the master test names plus the newer security and hermetic additions, while the broad master/pinned conflict was caused by parallel backport histories. The merge commit preserves fork-master ancestry for review without dropping the pinned tree.

The 38 conflicted paths were reviewed and resolved to the pinned security version where it was the superset:

```text
.github/workflows/ci.yml
device-protocol
keepkeylib/clearsign_abi.py
keepkeylib/clearsign_catalog.py
keepkeylib/client.py
keepkeylib/eip712_stream.py
keepkeylib/eth/ethereum_tokens.py
keepkeylib/eth/token_policy.py
keepkeylib/eth/uniswap_tokens.py
keepkeylib/messages_solana_pb2.py
keepkeylib/signed_metadata.py
keepkeylib/transport_udp.py
scripts/generate-test-report.py
tests/common.py
tests/test_message_signing_protocol_bindings.py
tests/test_msg_bitcoin_only_variant.py
tests/test_msg_display_disclosure.py
tests/test_msg_eip712_streaming.py
tests/test_msg_ethereum_clear_signing.py
tests/test_msg_ethereum_clearsign_additive.py
tests/test_msg_ethereum_erc20_0x_signtx.py
tests/test_msg_ethereum_erc20_uniswap_liquidity.py
tests/test_msg_ethereum_signing_guards.py
tests/test_msg_ethereum_signtx.py
tests/test_msg_ethereum_thorchain_deposit.py
tests/test_msg_hive.py
tests/test_msg_mayachain_signtx.py
tests/test_msg_osmosis_signtx.py
tests/test_msg_resetdevice.py
tests/test_msg_session_trust_lifetime.py
tests/test_msg_solana_lut_attestation.py
tests/test_msg_solana_signtx.py
tests/test_msg_thorchain_signtx.py
tests/test_msg_ton_signtx.py
tests/test_msg_zcash_sign_pczt.py
tests/test_msg_zcash_sign_pczt_device.py
tests/test_sign_typed_data.py
tests/test_storage_version_gate.py
tests/test_verify_typed_data.py
```

Resolution checklist:

- `device-protocol` uses `f54f0a7dabb2d38c6f423bf6b6a68e8f979b1b53`, which is the current firmware checkout pin and contains the EIP-712 protocol ancestor plus the Solana certificate field. The checked-in generated `messages_solana_pb2.py` exposes field 13 `clearsign_certificate`.
- `.gitmodules` retains `branch = master` for device-protocol, matching the fork-master SOP.
- Host library files retain pinned additions for canonical EIP-712 identifiers, nested array dimensions, `assert`-independent signing preconditions, denom forwarding, OLED capture timing, and actionable emulator failures.
- EIP-712 tests retain `TestEip712StreamHelpers`, duplicate/overlong/malformed identifier checks, multidimensional-array checks, the Permit2 nested batch test, published hash checks, and the no-AdvancedMode structured-review test.
- Solana tests retain `tests/test_msg_solana_display_disclosure.py`, Relay certificate coverage, LUT attestation, and signed-tail disclosure checks.
- A Python AST comparison found no master-only test method or library function absent from the reconciled tree. The only apparent master-only EIP-712 method is the old `test_advanced_mode_gates_the_endpoint`; it is intentionally superseded by the stronger pinned `test_advanced_mode_is_not_required_for_structured_review`.

## Reconciled validation and remaining gates

From `/private/tmp/python-keepkey-reconcile`:

- `python3 -m compileall -q keepkeylib tests` and `python3 -m py_compile scripts/generate-test-report.py`: passed.
- `git diff --cached --check` before commit: passed.
- `PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python PYTHONPATH=.:tests pytest -q tests/test_clearsign_abi.py tests/test_token_table_generators.py tests/test_msg_zcash_sign_pczt.py tests/test_zcash_seed_fingerprint_helper.py`: `30 passed, 2 skipped`.
- `... pytest -q tests/test_msg_eip712_streaming.py::TestEip712StreamHelpers`: `3 passed`.
- `... pytest -q tests/test_msg_eip712_streaming.py tests/test_msg_solana_display_disclosure.py tests/test_msg_solana_lut_attestation.py --collect-only`: `16 tests collected`.
- Hive collection: `38 tests collected`; execution still requires the root firmware CI emulator/HID transport.
- `git diff eaae16d d0b6669`: empty; `git diff --name-only --diff-filter=U`: empty; conflict-marker scan: zero.

Residual blockers before a firmware gitlink update:

1. The selected device-protocol commit is five commits ahead of fork device-protocol `origin/master` and zero behind (`git rev-list --left-right --count origin/master...f54f0a7` = `5 0`). Land that protocol line on its fork master first so the final alpha pin obeys the SOP.
2. Root firmware must repin to the reconciled companion master commit only after the companion merge and device-protocol master landing. No firmware gitlink or remote branch was changed here.
3. Full Hive, Solana, EIP-712, and emulator integration remains a root CI gate. Local deterministic tests cannot open a HID device; the default protobuf backend also requires the repository's legacy pure-Python compatibility mode in this Python environment.
4. Alpha-specific hermetic fixture commits beyond the pinned tree were not copied because the reconciled tree already preserves the required EIP-712 and Solana coverage. If alpha needs the newer fixture manifest/report catalog, merge those commits separately with the same directional review.
