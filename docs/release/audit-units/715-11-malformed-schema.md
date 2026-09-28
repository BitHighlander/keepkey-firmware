# Block 11: reject malformed transactions before schema evaluation

Base: db7c711a6c824c42e7096d4867429bbe94cb6ffb (provisional accepted block 08).
Finding S11-01: fsm_msgSolanaSignTx can evaluate a runtime schema against a
partially populated parser result after SOL_TX_REVIEW_MALFORMED. A matching
schema can select the schema review branch before the final malformed branch.
This also bypasses the signer check, which only runs for verified/opaque results.
Origin: present at the base. Scope: reject malformed transactions before schema
processing; preserve runtime annotations, AdvancedMode and normal consent.

Acceptance: wire regressions for legacy trailing bytes and truncated v0 lookup
sections, with and without schema; failure must occur before confirmation and
return no signature. Valid matching-schema signing remains a positive control.
Run relevant native Solana and emulator wire tests. No publication or merge.
Block 09/10 integration, embedded qualification and broader block 11 boundary
review remain pending and are not implied by this fix.

Dependency pins at start:
```
 a6470bd8598e5e9a7bfc38bf139a5e5a616f05ec code-signing-keys (heads/master)
 8a392f70a5d5575ece3dfb35f115d4a4b27f497c deps/crypto/trezor-firmware (8a392f70a)
-143a38eee7f5d7072969d25e7cf37760a2503b41 deps/crypto/trezor-firmware/common/defs/ethereum/chains
-c0fd515d273adf532e9751ca7310e1e1b74975ad deps/crypto/trezor-firmware/common/defs/ethereum/tokens
-2904be69e9d666bf3064fdc15093747e695cfae6 deps/crypto/trezor-firmware/crypto/tests/wycheproof
-40d24f38aa0a8180b271b6c88be8633f842ed9d4 deps/crypto/trezor-firmware/vendor/QR-Code-generator
-6dcf78409ac439da55a99290eaa6ad268ad6039e deps/crypto/trezor-firmware/vendor/fido2-tests
-5617ed466444790b787b6df8d7f21d1611905fd1 deps/crypto/trezor-firmware/vendor/libopencm3
-f7e780ae16bc62519e6b78672e43ecae9138ed0a deps/crypto/trezor-firmware/vendor/micropython
-2b48a361786dfb1f63d229840217a93aae064667 deps/crypto/trezor-firmware/vendor/nanopb
-fac477f822a9d493b0d23cc604d741b24a0c9719 deps/crypto/trezor-firmware/vendor/secp256k1-zkp
 5fec9e6906a340be5eb3d795ec746769065b2db8 deps/device-protocol (dice-entropy-v1-83-g5fec9e6)
 7888184f28509dba839e3683409443e0b5bb8948 deps/googletest (release-1.8.0-755-g7888184f)
 d9a02d981ee43fe3e80b28ba02466670e6e8409d deps/python-keepkey (v6.0.3-953-gd9a02d9)
-5fec9e6906a340be5eb3d795ec746769065b2db8 deps/python-keepkey/device-protocol
-89a64f717e1690bb31adb3e4c38e23640357333c deps/python-keepkey/keepkeylib/eth/ethereum-lists
 6dfbfdad5d9303ed190d1c3cb7bec34b565b6ce8 deps/qrenc/QR-Code-generator (v1.4.0-11-g6dfbfda)
 71d356a1141624994cf613bd2d2583892e8e6d5a deps/sca-hardening/SecAESSTM32 (heads/keepkey)
```

## Local repair receipt

S11-01 reproduced on the unmodified base through the emulator: all three
schema-bearing malformed cases reached confirmation and returned ActionCancelled
when the test declined. Their schema-free controls returned SyntaxError. This is
confirmation-path evidence; the baseline test deliberately did not approve a
signature. Source tracing shows the schema branch precedes malformed rejection.

The handler now rejects MALFORMED immediately after classification, zeroes the
derived node, returns SyntaxError and restores the home screen. No schema or
transaction confirmation is reached. The existing later fallback is retained.

Validation on the fixed local tree:
- Full emulator and firmware-unit builds passed using image 7438e53933d4.
- Native Solana: 44/44 pass (baseline and fixed).
- Wire: 34 pass, six regression subtests pass, one skip. The skip is the
  certified-v0 case requiring firmware 7.16; this unit targets runtime 7.15.
- Existing valid runtime-schema and token-signer controls pass.
- Both firmware and Python diffs pass git diff --check.

Artifacts, exact patch hashes and emulator hash:
/private/tmp/kk715-stack11-evidence/receipt.json. Adjacent XML/logs retain baseline
failures and fixed results. Tests force UDP on isolated ports 12144/12145.
Run tests with KK_FORCE_UDP=1, KK_TRANSPORT_MAIN=127.0.0.1:12144 and
KK_TRANSPORT_DEBUG=127.0.0.1:12145 against the isolated emulator:
`python -m pytest test_msg_solana_schema_v2.py::TestSolanaSchemaRuntime test_msg_solana_signtx.py`.
Native filter: `firmware-unit --gtest_filter='Solana.*'`.

The missing nested token-list dependency was initialized at its existing pin
89a64f717e1690bb31adb3e4c38e23640357333c; no dependency pin was changed.
Firmware edits and the Python submodule test remain local and uncommitted.
The Python test must accompany the firmware repair when preparing a candidate.

Block09/10 notes now report final integrated head
476afea2ce9906caaac67bfffa900b6a961fa6c4. This repair has not been replayed or
qualified on that head. ARM/BTC qualification, broader remaining block11 audit,
physical OLED acceptance and release integration remain outstanding.
No block11 completion, publication or release acceptance is claimed.
