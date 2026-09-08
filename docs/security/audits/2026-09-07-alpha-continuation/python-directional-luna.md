> Root correction: the protocol ancestry discussion below reversed the comparison. `bee6cdd...f54f0a7` is `5 0`: bee contains f54 plus five metadata commits, with no proto/options changes. No f54 merge is required. See python-reconcile-review-sol.md for corrected evidence.

# Python KeepKey reconciliation directional audit

Date: 2026-09-07

This audit compares the actual trees, source symbols, and behavior-bearing hunks of
fork master `999e776a6e9eb2c21df796609bea3626d45f6aa7` (called **master**) and the
pinned-Hive-fix tree `d0b6669c1aa2a25298ebe786ea081f5702d3b866` (called
**candidate**). It does not infer preservation from ancestry. The local merge under
review is `eaae16db64ae02d2f84c15bd65bb1276f0d7d8d6`, with parents master and
candidate; it has no conflict markers and no remote ref was changed.

## Direct tree result

`git diff --name-status 999e776 d0b6669` has no deletions. The only candidate-only
paths are:

* `tests/test_clearsign_abi.py`
* `tests/test_msg_solana_display_disclosure.py`
* `tests/test_token_table_generators.py`

The master tree has 150 paths under `tests` and candidate has 153. Both have 57
`keepkeylib` paths (the combined `keepkeylib` + `tests` counts are 207 and 210).
Thus no master file disappeared in the direct tree comparison. Candidate-only test
files add coverage; they are not replacements for deleted master files.

An AST inventory over every Python file found exactly one test method whose symbol
exists in master and not candidate:

```text
tests/test_msg_eip712_streaming.py:
    TestMsgEip712Streaming.test_advanced_mode_gates_the_endpoint
```

There are no master-only library functions, classes, or test classes. The omitted
test asserted that a structured EIP-712 endpoint was rejected unless AdvancedMode
was enabled. Candidate replaces that policy with the stronger and now intended
behavior: structured review succeeds without AdvancedMode, while the candidate
also tests exact identifiers, multidimensional array walking, and a realistic
Permit2 nested array. This is the only symbol-level loss from master, and it is a
deliberate security-policy correction rather than an unreviewed dropped test.

## Master behavior-bearing hunks and disposition

The following is the exhaustive inventory of shared paths with executable or test
behavior changes in `git diff 999e776 d0b6669`. “Retained” means the old behavior
still exists or is covered by an equivalent/stronger implementation; “replaced”
means the old behavior is intentionally corrected and the candidate has direct
coverage for the replacement.

### Host library

* `keepkeylib/clearsign_abi.py` — master accepted permissive integer-like values
  and used assertions for ABI assumptions. Candidate adds strict integer/bool/
  bytes validation and `_int_bits`, with the same valid encoding path retained.
  The old permissive acceptance is intentionally replaced; no valid ABI encoding
  is removed.
* `keepkeylib/client.py` — `osmosis_sign_tx` and `thorchain_sign_tx` previously
  rejected non-UOSMO/rune denominations unconditionally. Candidate forwards
  denominations on firmware versions that support them and keeps the version gate.
  `zcash_display_address` gains the account-only form while preserving the legacy
  address form. OLED capture is centralized through `capture_oled`. PCZT signing
  now checks transparent signature count and rejects empty signatures. These are
  additive/corrective paths; no master-only callable remains.
* `keepkeylib/eip712_stream.py` — master accepted ambiguous identifier forms and
  advanced arrays from the wrong dimension. Candidate enforces canonical
  identifiers and resolves multidimensional arrays right-to-left. Existing valid
  scalar/array parsing remains; the old ambiguous acceptance is intentionally
  removed.
* `keepkeylib/eth/ethereum_tokens.py` — master silently returned when a token
  source was missing. Candidate continues across sources, then raises explicit
  missing/empty errors and uses chain-aware token identity. Valid token table
  loading remains and the silent failure is removed.
* `keepkeylib/eth/token_policy.py` — candidate makes token selection chain-aware.
  The prior symbol/address-only collision behavior is replaced by the correct
  chain-qualified lookup.
* `keepkeylib/eth/uniswap_tokens.py` and `uniswap_tokens.json` — serialization is
  explicitly chain 1, retaining the Uniswap table while preventing cross-chain
  ambiguity.
* `keepkeylib/signed_metadata.py` — assertion-only preconditions become explicit
  `ValueError` handling and the Aave V2 address is corrected to the Aave V3
  address. Valid metadata serialization remains; callers now receive a stable
  failure instead of an assertion-dependent failure.
* `keepkeylib/transport_udp.py` — transport reads now raise the dedicated
  `EmulatorNotResponding` exception instead of collapsing failures into generic
  `IOError`. The read/retry behavior is retained with a distinguishable error.
* `keepkeylib/messages_solana_pb2.py` — generated binding contains the additive
  `SolanaSignTx.clearsign_certificate` field (number 13). See the protobuf audit
  below.

### Tests and test fixtures

The AST comparison found no omitted master test except the EIP-712 gate named
above. Every other changed test method remains in candidate, with the following
disposition:

* `tests/common.py:KeepKeyTest.setUp` — retained with updated setup needed by the
  newer protocol/test matrix.
* `tests/test_dylib_confirm_flow.py:TestDylibConfirmFlow.test_features_round_trip`
  — retained with the current feature round-trip expectations.
* `tests/test_msg_binance_sign_tx.py:setup_binance` — retained with current setup.
* `tests/test_msg_display_disclosure.py` (`_assert_distinguishable`, `setUp`,
  `test_signing_shows_at_least_one_screen`) — retained and strengthened to assert
  distinguishable/visible disclosure rather than silently accepting refusal or
  `None`.
* `tests/test_msg_eip712_streaming.py` (`_walk`, `setUp`) — retained. Candidate
  adds `TestEip712StreamHelpers.test_review_identifiers_are_exact_and_unambiguous`,
  `TestMsgEip712Streaming.test_advanced_mode_is_not_required_for_structured_review`,
  and `test_permit2_batch_walks_realistic_nested_array`; these replace the old
  AdvancedMode requirement with explicit coverage of the intended policy.
* `tests/test_msg_eos_signtx.py:test_updateauth` — retained with the current
  expected signature/hash fixture.
* `tests/test_msg_ethereum_clear_signing.py` — the three existing clear-signing
  tests remain; candidate adds dynamic-format `ValueError`, corrected firmware
  gating, and broader blind-signing refusal checks. Aave V3 fixture/address is
  retained.
* `tests/test_msg_ethereum_clearsign_additive.py` — existing additive checks
  remain, with the candidate’s firmware 7.16 gate retained.
* `tests/test_msg_ethereum_erc20_uniswap_liquidity.py:test_sign_uni_remove_liquidity_ETH`
  — retained.
* `tests/test_msg_ethereum_signing_guards.py` — both existing guard tests remain;
  candidate adds full streamed-calldata/no-clear-sign and tail-commitment checks.
* `tests/test_msg_ethereum_signtx.py` — both existing signing tests remain with
  corrected refusal text and omitted-chain handling.
* `tests/test_msg_ethereum_thorchain_deposit.py` — both tests remain with stable
  exception expectations.
* `tests/test_msg_hive.py` (`test_account_create`, `test_transfer`) — retained;
  stale host expectations now assert raw wire symbol `STEEM`, matching legacy
  hived packing. No firmware/protobuf serialization was changed.
* `tests/test_msg_mayachain_signtx.py` — memo cases remain; candidate adds the
  send-plus-deposit acknowledgement conflict rejection.
* `tests/test_msg_osmosis_signtx.py` — offline-client denomination tests remain;
  version gating is retained in the corrected form.
* `tests/test_msg_ping.py` — existing ping tests remain and candidate adds
  `TestPing.test_authenticator_passphrase_cancel_is_terminal`.
* `tests/test_msg_recoverydevice_cipher.py` — both recovery cipher tests remain
  with the current firmware gate.
* `tests/test_msg_resetdevice.py` — all five reset/version/CRC tests remain with
  current framing and checksum expectations.
* `tests/test_msg_session_trust_lifetime.py` — emulator process helper remains.
* `tests/test_msg_solana_lut_attestation.py` — setup and bad-signature coverage
  remain.
* `tests/test_msg_solana_signtx.py` — stake layout tests remain and candidate adds
  certified Relay signing coverage.
* `tests/test_msg_thorchain_signtx.py` — send/signing tests remain; candidate adds
  denomination and acknowledgement-conflict coverage and corrects memo fixtures.
* `tests/test_msg_ton_signtx.py` — all 12 tests remain. Candidate’s explicit
  AdvancedMode policy value is equivalent to master’s policy application.
* `tests/test_msg_zcash_sign_pczt.py` and
  `tests/test_msg_zcash_sign_pczt_device.py` — existing PCZT tests remain and
  candidate adds the Ironwood empty-Orchard case; the old zero-Orchard digest is
  corrected to the ZIP-229 empty-bundle digest.
* `tests/test_sign_typed_data.py` and `tests/test_verify_typed_data.py` — existing
  typed-data cases remain with corrected signing/verification expectations.
* `tests/test_storage_version_gate.py` — all storage gate tests remain with the
  current framing and CRC helpers.
* `tests/test_solana_lut_attestation.py` and `tests/test_msg_solana_signtx.py`
  retain the Solana OLED/certification coverage that the alpha tree later drops.
* `tests/test_protection_levels.py`, `tests/test_multisig.py`,
  `tests/test_message_signing_protocol_bindings.py`,
  `tests/test_msg_ethereum_erc20_0x_signtx.py`, and
  `tests/test_msg_bitcoin_only_variant.py` retain their master behavior; their
  changed hunks are setup, fixture, or matrix updates rather than removed tests.

The direct diff also updates CI’s Bitcoin-only matrix to use an explicit
`requires_bitcoinOnly` path and an integration-BTC job. This preserves the master
matrix intent while making the variant requirement explicit.

## Candidate additions and security coverage

Candidate adds three complete test files: strict ClearSign ABI validation,
Solana display disclosure, and token-table generator validation. These are the
three candidate-only paths shown by the direct tree inventory. Candidate also
retains the complete EIP-712 identifier/Permit2/no-AdvancedMode coverage and the
Solana OLED/certified signing tests; those are absent from the alpha tip and are
therefore a material reason not to repin blindly to alpha.

## Generated protobuf compatibility

The candidate gitlink is device-protocol `f54f0a7dabb2d38c6f423bf6b6a68e8f979b1b53`.
The fork’s device-protocol `master` is `bee6cdd624905d6b5bcc54a05fc3deb24242483d`;
`git rev-list --left-right --count master...f54f0a7` is `5 0`, so f54 is five
commits ahead and contains no fork-master-only commits. The source proto declares
`optional bytes clearsign_certificate = 13` on `SolanaSignTx`; the matching
`messages-solana.options` entry is `SolanaSignTx.clearsign_certificate max_size:139`.
The candidate generated Python descriptor exposes number 13 as
`SolanaSignTx.clearsign_certificate`. This is an additive binding compatible with
the current firmware pin and the source protocol. The residual integration blocker
is procedural: land f54 (or an equivalent reviewed protocol commit) on the
device-protocol fork master before changing the firmware gitlink.

## Comparison with alpha `ff349684`

The alpha tip is `ff3496846a301838874feb0d62dc96191aa82636` (fetched locally as
`FETCH_HEAD`). `git diff --stat d0b6669 FETCH_HEAD` is 24 paths,
`1315 insertions, 411 deletions`. Alpha contributes a hermetic test framework:

* `docs/handoff-python-test-hermeticity.md`
* `keepkeylib/tx_api.py` offline fixture configuration, fail-closed fixture
  loading, and `OfflineFixtureError`
* `tests/conftest.py` loopback-only socket/HTTP network denial
* `tests/test_msg_zcash_transparent_shielding.py`
* `tests/test_tx_fixture_integrity.py`
* `tests/tx_fixture_manifest.py`
* `tests/txcache/manifest.json` and its fixture updates
* CI fixture-manifest and network-gate checks in `.circleci/config.yml` and
  `.github/workflows/ci.yml`

Those alpha additions are absent from candidate and should be brought in as a
separate reviewed hermeticity patch if root wants them. They must not be imported
by taking alpha wholesale: alpha deletes `tests/test_msg_solana_display_disclosure.py`,
deletes `tests/zcash_rpc.py`, removes two txcache fixtures, and removes the
candidate EIP-712 exact-identifier/Permit2/no-AdvancedMode tests. Alpha also drops
`TestPing.test_authenticator_passphrase_cancel_is_terminal`. Candidate deliberately
keeps all of those security and display coverage. Alpha’s EIP-712 file has the old
`test_advanced_mode_gates_the_endpoint`, which is the same one master-only symbol
identified above and is superseded by candidate’s stronger policy test.

The alpha change is therefore a useful optional follow-up for network hermeticity,
not a safe replacement tree for this reconciliation. The candidate’s Hive
assertions already match the alpha wire-symbol correction (`STEEM`).

## Validation evidence

Run in `/private/tmp/python-keepkey-reconcile` with the Python protobuf backend:

```text
PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python \
PYTHONPATH=.:tests PYTHONWARNINGS=ignore \
pytest -q tests/test_clearsign_abi.py tests/test_token_table_generators.py \
  tests/test_msg_zcash_sign_pczt.py tests/test_zcash_seed_fingerprint_helper.py
30 passed, 2 skipped

pytest -q tests/test_msg_eip712_streaming.py::TestEip712StreamHelpers
3 passed

pytest --collect-only -q tests/test_msg_eip712_streaming.py tests/test_msg_solana_signtx.py
16 tests collected

pytest --collect-only -q tests/test_msg_hive.py
38 tests collected

python3 -m compileall -q keepkeylib tests
python3 -m py_compile scripts/generate-test-report.py
```

`git diff --name-only --diff-filter=U` is empty, and a repository scan found no
conflict markers. The full Hive integration requires an emulator/HID endpoint and
is intentionally left for root CI after the firmware gitlink/protocol ancestry is
made coherent; collection and source-level wire-symbol checks pass here.

## Review checklist and residual blockers

1. Review merge `eaae16db64ae02d2f84c15bd65bb1276f0d7d8d6`; its tree is byte-equal
   to candidate d0 (`git diff eaae16d d0` is empty), but the direct diff and AST
   evidence above show what master contributed, what it replaced, and the one
   intentionally superseded gate. Tree equality alone is not the preservation
   claim.
2. Land device-protocol f54 on its fork master, then land the Python merge on
   `BitHighlander/python-keepkey` master. Only after those reviews should firmware
   alpha repin the gitlink and run full emulator/Hive CI.
3. If hermeticity is required, cherry-pick the alpha fixture/`tx_api`/conftest/CI
   additions selectively, retaining candidate EIP-712, Solana OLED, Ping, and
   RPC coverage. Re-run the full test and generated-binding checks after that
   separate patch.

No push, firmware gitlink update, or shared firmware-file edit was performed.
