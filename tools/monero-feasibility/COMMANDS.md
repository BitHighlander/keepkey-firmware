# Monero address commands in the firmware emulator

This records the address stage. The later [wallet workflow](WALLET.md) adds
watch-key export, encrypted key-image sync and real emulator transaction
signing, with a complete runner and preserved evidence.

The emulator experiment now has a real request/response path. An opt-in native
`libkkemu` build accepts Trezor-compatible `MoneroGetAddress` (540) and returns
`MoneroAddress` (541) through KeepKey's ordinary protobuf dispatcher and HID
packet rings. This extends the earlier [in-process arithmetic experiment](INTEROPERABILITY.md).

## Implemented behavior

- Derive from the emulator wallet's actual seed using Ed25519 SLIP-0010 path
  `m/44'/128'/account'` and the verified Monero scalar convention.
- Support mainnet, testnet, and stagenet base addresses and subaddresses. The
  request's `account` and `minor` fields select subaddress indices, separately
  from the hardened wallet-account component of the derivation path.
- Use the normal initialization, PIN, passphrase, storage-variant, and session
  checks. No private spend/view key or node is returned.
- For `show_display=true`, review network/path/subaddress metadata, the full
  95-character address, and its QR through the existing confirmation flow.
  Button acknowledgement alone does not release the address.
- Refuse malformed paths, unsupported networks, malformed protobuf data, and
  any `payment_id` presence. Integrated addresses are outside this stage.

The handler clears the shared derived HDNode and its owned private derivation
scratch before entering the confirmation wait. This is a claim about the
candidate's owned buffers, not removal of KeepKey's normal seed/session caches
or an audit of every internal crypto stack frame.

## Verification on 2026-11-04

| Test | Result |
| --- | --- |
| Real emulator HID/protobuf integration | 177 checks passed |
| Independent address matrix | 48 addresses: two public seeds × two wallet accounts × four base/subaddress combinations × three networks |
| Additional wire cases | Default fields, packed paths, maximum subaddress indices, fragmented requests and responses passed |
| Authorization | Missing seed, PIN cancellation/wrong/correct/cached PIN, passphrase cancellation, empty/nonempty passphrase wallets, and session isolation passed |
| Display flow | Metadata, full address and QR stages, acknowledgement/decision gating, cancellation at every stage, Initialize, and unexpected nested requests passed |
| Private-node boundary | Shared derived-node observer reports zero before approval and after response/cancellation |
| Crypto helper under ASan/UBSan | 48 independently regenerated addresses and 270 checks passed |
| Compile guards | Non-emulator, Bitcoin-only, missing opt-in, and disabled Monero primitives rejected |
| Ordinary emulator negative control | Rejects command 540 with Failure/UnexpectedMessage; status transport remains usable |

The oracle regenerates the recorded public cases using pinned Monero Core
arithmetic before comparing the command's outputs. Nonempty-passphrase and
maximum-subaddress expectations are independently derived as well.

Tests install only published disposable mnemonics, through the normal
`LoadDevice` command, into a newly allocated anonymous emulator flash buffer.
The first derivation triggers KeepKey's existing encrypted root-seed-cache
commit. Reports record that write explicitly; subsequent address-matrix calls
are verified not to change flash after cache warmup. No physical device or
existing `emulator.img` is accessed.

OLED frames and debug confirmation metadata are captured before approval.
The test checks matching frame-ring evidence and required metadata; it is not
an OCR/pixel-level proof that every glyph was rendered in a particular frame.
Representative captured address screens were visually inspected in the
historical run. Captures are generated outputs and are omitted from this PR;
the runner below regenerates them.

## Isolation and reproduction

The feature is built only by `commands-overlay.cmake`, with explicit
`KK_EMULATOR`, `KK_BUILD_DYLIB`, and `KK_MONERO_EMULATOR_RESEARCH` selection.
The command helpers also reject device and Bitcoin-only compilation. Normal
device/emulator builds do not register IDs 540/541. The shared device-protocol
submodule is unchanged; the bounded research protobuf subset lives here.

The research test build enables DebugLink to automate public-fixture PIN and
button input. The CLI builds a second ordinary emulator without the research
overlay to test rejection of the Monero command.

From the firmware root, using the local toolchain layout and independently
built Core adapter described in the previous experiment:

```sh
python3 tools/monero-feasibility/commands.py \
  --toolchain-root /Users/highlander/keepkey-toolchain \
  --core-library /private/tmp/monero-independent-reference-20261104-final/core-reference.dylib \
  --output /private/tmp/monero-address-commands-new-run
```

The default reference is the checked-in public reference report. An alternative
can be selected with `--reference`. Output directories must be empty. The
runner builds the research and ordinary emulators, runs sanitizer/compile-guard
tests, exercises the wire/UI/session path, and writes reports, logs, generated
protobuf/fixture files, shared libraries, and OLED captures.

The [current alpha summary](evidence/2026-11-04-alpha/summary.json) records
the reproduced address gates and source/artifact hashes. Historical verbose
reports and captures are omitted; the command above regenerates them in a new
output directory.

## Remaining scope

This stage established the emulator address API. Watch-key export, key-image
sync and bounded HF16 signing are now covered by the [wallet experiment](WALLET.md).
Monero wallet application integration, FCMP++/Carrot formats, and
physical-device performance remain outside its scope. Production readiness
is false; no production capability or release was added.
