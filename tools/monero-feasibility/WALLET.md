# Monero wallet workflow in the KeepKey emulator

This records the offline wallet stage. The subsequent [CLI/RPC host stage](HOST.md)
adds real private-chain funding, two confirmed emulator spends and change reuse.

The native firmware emulator implements address derivation, private view-key
export, encrypted key-image synchronization, and bounded transaction signing.
These run through the actual firmware HID/protobuf dispatcher, wallet
derivation, PIN/passphrase checks, and OLED confirmation flow.

The experiment uses disposable public seeds and synthetic funding. Signed
transactions have real CLSAG signatures and Bulletproof+ proofs, but their
funding outputs are not on a blockchain. They were verified offline; no
transaction was mined, relayed, or broadcast. No physical device was accessed.
Production readiness remains false.

## Implemented interfaces

| Workflow | Request → response IDs | Behavior |
| --- | --- | --- |
| Address | 540 → 541 | Mainnet/testnet/stagenet, base addresses and subaddresses; optional complete address/QR review |
| Watch credentials | 542 → 543 | Explicit privacy warning and wallet address review before exporting the private view key and public address |
| Key-image sync | 530 → 531, 532 → 533, 534 → 535 | Owned-output validation, encrypted key images and ring-one proofs; encryption key released only after the complete committed transcript |
| Transaction signing | 65000 → 65001 | Review all destinations, change and exact fee; construct and verify a serialized HF16 transaction with ring size 16, CLSAG and Bulletproof+ |

Address, watch-key and key-image messages use the corresponding Trezor field
conventions. Signing uses a **custom research protocol**, defined in
[messages-monero-research.proto](commands/messages-monero-research.proto).
The streamed Trezor signing protocol and Monero wallet application/GUI
integration are not implemented. This is a working firmware experiment with
Python host drivers, not a released Monero wallet feature.

Wallet derivation is Ed25519 SLIP-0010 `m/44'/128'/account'`, followed by the
verified Monero spend/view scalar convention. Wallet account and subaddress
major/minor indices are separate. The address-stage implementation and tests
are described in [COMMANDS.md](COMMANDS.md).

## Authorization and validation

View-key export requires fresh approval for each request. The UI explains that
the key permits incoming-payment scanning and displays the wallet's full
address. The private spend key is never exported. The derived node is wiped
before UI waits; the handler rederives and checks the approved wallet after
consent. Its owned key and response buffers are wiped after encoding. The
authorized wire response necessarily carries the view key until consumed.

Key-image sync checks canonical prime-subgroup points, the requested wallet
and subaddress, and ownership of every supplied output. Each encrypted record
contains a key image and an independently verifiable ring-one proof. Encryption
uses ChaCha20-Poly1305 with checked random session keys and nonces. The final
key is withheld until both the expected count and Keccak transcript match.
Cancellation, session clearing, initialization, timeout, continuation errors
and unrelated stateful requests revoke the session and wipe its owned
confidential state. `GetFeatures` and `GetCoinTable` preserve an active sync.

Signing validates real-input ownership against each **declared** source
subaddress, real amount/mask commitments, ordered ring indices, canonical
points, duplicate inputs, conflicting global-output data, overflow, balance,
network addresses, change ownership and the exact fee. The UI reviews the
network, path, every recipient/change amount and complete address/QR, and a
final fee/signing confirmation. XMR amounts have all 12 decimal places.

The node is wiped before review. After approval the wallet and complete plan
are revalidated. The signer binds the actual shuffled transaction outputs to
the approved address/amount multiset, checking stealth keys, view tags,
encrypted amounts and commitments before wiping transaction secrets. It then
serializes and verifies the CLSAG signatures, Bulletproof+ proofs, rings,
canonical ordering and fee before returning the transaction and hash.

Owned-buffer wipe observers and session tests cover normal completion and
revocation. They do not establish erasure of every inherited crypto-library
stack frame or remove KeepKey's normal seed/session caches.

## Bounds and isolation

- Signing: 1–4 inputs, 2–4 outputs, exactly 16 ring members per input, at most
  one verified change output, at least one recipient, and a 16 KiB transaction
  response. Unlock time must be zero.
- Key-image sync: at most 64 outputs, batches of at most 4, at most 16
  additional transaction public keys per output, and 32-bit output indices.
- Standard 95-character base/subaddresses are supported. Integrated addresses,
  payment IDs, arbitrary transaction extra, and future FCMP++/Carrot formats
  are outside this experiment.
- Build selection requires `KK_EMULATOR`, `KK_BUILD_DYLIB` and the explicit
  research overlay. Key-image and signing registration have separate opt-ins.
  Ordinary firmware does not register these commands. The shared production
  device-protocol schema is unchanged by this experiment.
- Transaction construction uses a native C++ Monero Core dependency. This is
  **not an STM32 signing port**. The earlier 5,008-byte primitive link delta
  does not measure the wallet/signing implementation's hardware cost.

## Verification

The complete runner builds a research emulator and an ordinary negative
control, then exercises address, watch, key-image, signing and sanitizer gates.
It records source hashes, artifact hashes, the Core build manifest, UI/debug
metadata and individual assertions in `result.json`.

The signing driver independently parses every transaction and computes its
three-part transaction hash. Using a separate pinned Core crypto adapter and
the public recipient fixtures, it scans outputs, checks view tags, decrypts
amounts, reconstructs commitments and compares recipients/change against the
approved plan. Official Core also verifies the actual serialized proofs and
signatures. Tampered signatures, range proofs and truncated blobs must fail.
The source of each oracle is recorded; Core proof verification is not a
second independently implemented CLSAG/Bulletproof+ verifier.

Positive cases include all three networks, 1/2/3/4 inputs, four outputs,
source/recipient/change subaddresses, additional transaction keys, and
PIN/passphrase wallets. Negative cases cover malformed protobuf bounds,
invalid points and masks, ownership/change lies, balance/overflow/ring errors,
authorization, cancellation, nested requests and confidential-state cleanup.

The [current alpha summary](evidence/2026-11-04-alpha/summary.json) records
reproduced stage counts and source/artifact hashes.
[Wallet result notes](evidence/2026-11-04-wallet/README.md) explain the retained
scope and reproduction; verbose generated reports and captures are omitted.

## Vault receive-only build

The Vault-facing emulator can omit the native Monero Core signing engine while
retaining address derivation, consented view-key export and encrypted key-image
synchronization:

```sh
python3 tools/monero-feasibility/wallet_emulator.py \
  --receive-only \
  --toolchain-root /path/to/keepkey-toolchain \
  --core-library /path/to/independent/core-reference.dylib \
  --output /private/tmp/monero-vault-receive-new-run
```

The independent reference library is used by the test process; it is not linked
into this emulator. On macOS, the resulting `libkkemu.dylib` requires only the
system runtime. This mode explicitly tests that research signing requests are
unsupported and also runs the ordinary-build negative controls. Its report sets
`signing_enabled: false` and `engine: null`. `--core-library` remains required,
including with `--build-only`, so a normal run cannot skip the independent checks
accidentally.

This artifact is still an opt-in software emulator with DebugLink support. It
must be selected explicitly by Vault and does not enable a physical-device
Monero feature. The full signing experiment below additionally depends on the
native Core engine and its platform libraries; it is not a standalone portable
wallet binary.

## Reproduce

Build the native signing engine from stable Monero Core v0.18.5.4, commit
`85f036ba7019cd36f08e8a38a27c37ea7b522618`, and its pinned RandomX, rapidjson
and supercop sources. [build_core.py](build_core.py) checks the entire source
tree against four SHA256-pinned archives before building; it retains a
complete manifest. Supply those archives beside the extracted source tree,
or pass `--archive-dir`.

The four archive names and download locations are:

| Local archive | Pinned source URL |
| --- | --- |
| `monero-core-v0.18.5.4.tar.gz` | [Monero v0.18.5.4](https://codeload.github.com/monero-project/monero/tar.gz/refs/tags/v0.18.5.4) |
| `monero-randomx.tar.gz` | [RandomX 12f2c2f](https://codeload.github.com/tevador/RandomX/tar.gz/12f2c2ffe2108d6cf54c391fee33c8bc3646cdab) |
| `monero-rapidjson.tar.gz` | [rapidjson 129d19b](https://codeload.github.com/Tencent/rapidjson/tar.gz/129d19ba7f496df5e33658527a7158c79b99c21c) |
| `monero-supercop.tar.gz` | [supercop 633500a](https://codeload.github.com/monero-project/supercop/tar.gz/633500ad8c8759995049ccd022107d1fa8a1bbc9) |

Extract Core into the source root, then extract each dependency into its
`external/randomx`, `external/rapidjson` or `external/supercop` directory,
stripping the archive's top-level directory each time. Keep build outputs
outside the source tree; the complete-tree check rejects extra source files.
Boost, libsodium, OpenSSL 3, CMake and the normal KeepKey emulator/toolchain
dependencies must be installed.

From the firmware root, with the same local toolchain layout used by the
[independent reference experiment](INTEROPERABILITY.md):

```sh
python3 tools/monero-feasibility/build_core.py \
  --source /private/tmp/monero-core-v0.18.5.4 \
  --output /private/tmp/monero-engine-new-run \
  --openssl-root /opt/homebrew/opt/openssl@3

python3 tools/monero-feasibility/wallet_emulator.py \
  --toolchain-root /Users/highlander/keepkey-toolchain \
  --engine-link /private/tmp/monero-engine-new-run/core-link.cmake \
  --core-library /private/tmp/monero-independent-reference-20261104-final/core-reference.dylib \
  --output /private/tmp/monero-wallet-new-run
```

Output directories must be empty. `build_core.py --build-dir` can reuse a
compatible Core compilation cache while placing the bridge library in the
new run's own directory. The complete runner loads only newly allocated
anonymous emulator flash, installs only the public fixture wallets, and does
not open an existing `emulator.img` or any USB hardware.

The [host stage](HOST.md) now supplies a read-only wallet adapter and funded
private-chain integration. Remaining product work includes GUI wallet
integration, a reviewed streamed/bounded protocol for the MCU, hardware
resource/timing measurements, secret-path and RNG review, and broader funded
coverage. This stage establishes the emulator workflow and offline validity.
