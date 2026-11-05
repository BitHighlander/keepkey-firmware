# Monero feasibility experiment

A separate [private mainnet receiving workflow](PRIVATE_MAINNET.md) generates
a fresh seed, stores encrypted flash with a dedicated OS Keychain key,
verifies restoration in a second process and runs a local view-only monitor.
Actual wallet data is kept outside this repository. The software emulator
remains experimental and provides no hardware-wallet isolation.

The latest [official CLI/RPC host test](HOST.md) passes two emulator-authorized
spends on an isolated local chain, including spending change and verifying
recipient balances and spent-output tracking.

The earlier stage implements the [complete bounded wallet workflow in the
native emulator](WALLET.md): addresses, view-key export, encrypted key-image
sync, and real CLSAG/Bulletproof+ transaction signing over HID/protobuf.
Production readiness remains false; signing uses a native Monero Core
dependency. Physical-device work remains deferred.

The next-stage [address/key-image interoperability experiment](INTEROPERABILITY.md)
adds independent Monero Core comparisons, negative tests, and ARM execution.

The primitive results below are the original 2026-11-04 feasibility stage.
Its device-fit measurements apply only to the primitive probe. Physical-device
work was subsequently deferred in favor of the emulator. The later wallet
experiment does not establish MCU signing feasibility.

## Physical-device audit

The emulator workflow is suitable for an opt-in research PR. A real-device
wallet port remains a separate engineering task; no device has been flashed or
measured by this experiment. Normal builds keep `USE_MONERO=0`, and the wallet
overlay refuses physical-device and Bitcoin-only configurations. The dispatcher
also rejects compiling the wallet research into a non-emulator image.

- **Address and watch credentials:** the C derivation and confirmation code can
  be candidates for an embedded port. The current overlay intentionally exposes
  them only in the native emulator. A hardware implementation must preserve
  PIN/passphrase isolation, fresh view-key-export consent, complete address
  review, cancellation and owned-buffer wiping.
- **Key images:** the implementation is C and uses the firmware's checked RNG,
  but its complete protocol, SRAM, stack, latency, interrupts and reset behavior
  have not been exercised on an MCU. Arithmetic fixtures and the prepared
  boot-only image are narrower evidence.
- **Signing:** the engine is a native C++ Monero Core shared library with dynamic
  containers and a process mutex. Its private node-key argument stays within the
  software emulator process. This architecture cannot be reused by moving the
  engine to an untrusted host for a hardware wallet. An embedded signer needs a
  reviewed bounded or streamed protocol that keeps signing secrets on device.
- **Memory and transport:** the device linker permits a 655,321-byte upload and
  requires a 16 KiB stack/heap reserve. The earlier primitive image's 35,093-byte
  flash headroom and 19,992-byte runtime reserve describe that historical probe,
  not the full wallet. An ARM EABI compile-only layout check of the current
  research headers reports a 25,264-byte signing context, a 7,544-byte plan and a
  16,418-byte signed-response structure. The signing context alone exceeds that
  historical runtime margin; the reply also enlarges the shared response arena.
  The 16 KiB transaction-blob allowance exceeds the real device's 12 KiB frame
  limit. These are concrete redesign constraints, not a full-image fit result.
- **Performance and hardening:** no physical-cycle, watchdog, stack high-water,
  interrupt-load or power-loss result exists. Host time and Unicorn instruction
  counts must not be presented as device latency. Secret scalar paths, entropy
  failure behavior and inherited crypto scratch storage still need review.

The [alpha rebase summary](evidence/2026-11-04-alpha/summary.json) records the
exact base and dependency revisions, implementation hashes, all nine gates for
both the complete signer and the self-contained Vault receive-only build.
The full run passed 1,248 workflow checks and verified 15 synthetic signed
transactions. The receive-only run passed 724 workflow checks, explicitly
refused signing, and linked only the macOS system runtime. Ordinary-build
negative controls passed in both runs. These are native emulator results.

The first hardware milestone should run the existing boot-only public-vector
self-test on a disposable device. It must pass the independent address,
subaddress, output-derivation and key-image fixtures, retain measured stack
margin including interrupts, and finish without watchdog resets. That test
halts before wallet-storage and USB initialization; passing it would not expose
Monero to Vault or authorize real funds. Only then should a separate receive-only
hardware build add normal USB requests and on-device confirmation, followed by
watch export and key-image synchronization. Embedded signing is a later gate.

## Retro on the previous spike

The separate main firmware checkout contains a local `spike/monero-primitives`
branch at `1f147b5081386856f202425b99c22ab57d67a27d`. Its last commit is an
unrelated June 29, 2026 merge. That date is the tip's commit date; the branch's
creation date and original intent could not be recovered.

On that branch, `USE_MONERO=0`, the Monero C sources are commented out, and there
are no KeepKey Monero handlers, dedicated tests, or recorded experiment results.
Its configured upstream is `origin/alpha`. Bundled Trezor Monero code is useful
source material, but its presence does not establish a working KeepKey port.
Live GitHub access failed during the audit, so remote-only work was not ruled out.

The useful starting point is the bundled reusable primitive library. The missing
outcome is evidence: a branch name did not establish buildability, correctness,
resource cost, or host compatibility. This experiment supplies a narrow question,
a paired baseline, preserved measurements, and explicit next gates.

## Question and method

Can the pinned crypto code provide the deterministic primitives needed for
Monero addresses, output derivation, key images, and commitments on Cortex-M3,
within the current regular firmware's flash and static SRAM budgets?

Inputs: firmware `d138ef715836f56b2e087708bb3402134d540bf0` (7.17.0),
crypto `f3fbfc7f14f79bbfc672f5df3121e7d5c1823990`, GNU Arm Embedded GCC
10.2.1, `-Os`, Cortex-M3/Thumb/soft-float, and strong stack protection.

`run.py` adapts the unmodified, pinned Trezor `test_check_monero.h` into a host
executable with AddressSanitizer and UndefinedBehaviorSanitizer. It runs all 30
deterministic groups: scalar/point arithmetic, Keccak, hash-to-scalar/point,
addresses, output derivations, subaddress secrets, commitments, and varints.
The final legacy Borromean range-proof group is deliberately excluded. No
modern range-proof or transaction-signing claim follows from these tests.
These are the library's own upstream vectors, not an independent Monero Core
interoperability test. An unexpected RNG call aborts the host experiment.

The standalone ARM experiment compares identical Ed25519/Keccak baselines with
and without the deterministic Monero pipeline. Its synthetic inputs and volatile
sink prevent dead-code removal. It checks that required Monero symbols survive
linking and that `xmr_random_scalar` is absent. ELF files are link-only probes.

`firmware.py` also builds two complete regular device images from the same
checkout and dependencies. An optional CMake overlay adds the Monero sources,
enables their crypto definitions, and retains `monero_probe` with a linker root.
There is no boot-time call or USB command. A symbol check rejects builds that
accidentally compile out the Monero calls. Default firmware builds do not load
the overlay and continue to use `USE_MONERO=0`.

## Observed results

| Measurement | Baseline | Monero probe | Change |
| --- | ---: | ---: | ---: |
| Full device binary bytes | 615,220 | 620,228 | +5,008 |
| Upload headroom bytes | 40,101 | 35,093 | -5,008 |
| ELF text bytes | 611,816 | 616,792 | +4,976 |
| ELF data bytes | 3,404 | 3,436 | +32 |
| ELF BSS bytes | 105,584 | 105,584 | 0 |
| Stack/heap reserve, `_stack - _ebss` | 20,024 | 19,992 | -32 |

Both full images passed the real firmware linker constraints, including the
16 KiB runtime SRAM reserve. The upload limit is 655,321 bytes, matching the
bootloader overhead allowance in `tools/firmware/keepkey.ld`.

The host run passed 30 vector groups with no sanitizer findings. Its 8,962
assertions include test-adapter hex parsing; that number is not a count of
independent crypto vectors. Host timings are instrumented, group-level CPU
times and are not MCU latency estimates.

The isolated ARM link added 6,164 text bytes with no data/BSS increase relative
to its smaller synthetic baseline. The full image delta is the relevant fit
measurement because it already contains more shared code.

The largest retained per-function ARM frame in the isolated experiment is
`ge25519_scalarmult`, 2,016 bytes; the probe frame is 1,392 bytes. These are
individual compiler estimates, not a maximum call-chain or interrupt-stack
measurement. A 3,440-byte variable-time helper was compiled but discarded by
the probe link; it is not part of the retained pipeline. No ARM code was
executed on hardware in this experiment.

The full images and their hashes are research artifacts. No device was flashed.

## Findings and next gates

1. **Primitive gate: pass.** The existing vectors pass and the retained primitive
   pipeline fits the tested regular image. The remaining 35,093 bytes must also
   cover any future handlers and signing implementation; this experiment does
   not estimate that cost.
2. **Input-boundary gate: open.** `xmr_write_varint(buf, 1, 128)` returns `1` and
   writes `0x80`, a truncated encoding. Its return value cannot be treated as a
   completeness check. Future wrappers must preflight `xmr_size_varint` and
   reject undersized buffers. Decoder bounds, invalid points, noncanonical
   scalars, and malformed addresses still need targeted negative tests.
3. **Device address/key-image gate: next.** Use a disposable test seed, choose
   and document the wallet derivation convention, and compare main address,
   subaddresses, output keys, and key images against an independent Monero
   implementation. Verify the base address separately from subaddress `(0,0)`:
   the subaddress-secret primitive alone does not implement that wallet rule.
   Measure cycles, watchdog behavior, and stack high-water marks on device,
   including interrupt overhead. The synthetic probe is not a wallet derivation
   implementation or a key-image known-answer test.
4. **Signing gate: open.** Design the streamed protocol, host adapter, session
   state, authenticated offloading, user confirmation, and cancellation/reset
   behavior. Implement current transaction/ring-signature/range-proof handling
   and obtain an independently verified test transaction. Inspect secret scalar
   paths for timing behavior, checked RNG use, and zeroization before relying
   on them for spending. The bundled Trezor application is Python; these C
   primitives alone do not port its protocol or establish current compatibility.

Decision: keep the old branch as historical evidence; use this executable
experiment as the baseline for the next stage. Production readiness remains
false until the device and signing gates are met.

## Reproduce

From the firmware root, with a C compiler supporting ASan/UBSan:

```sh
python3 tools/monero-feasibility/run.py \
  --output /private/tmp/monero-primitives-new-run \
  --arm-prefix /path/to/gcc/bin/arm-none-eabi-
```

Omit `--arm-prefix` for host vectors alone. Use the GCC 10.2.1 distribution with
newlib for the recorded ARM comparison. The Homebrew bare compiler without
newlib cannot link this experiment. Output directories must be empty.

For the local KeepKey toolchain layout (`gcc10h`, `libopencm3`, `nanopb`,
`protoc351`, `pyk-venv`) and CMake >= 3.19:

```sh
python3 tools/monero-feasibility/firmware.py \
  --toolchain-root /Users/highlander/keepkey-toolchain \
  --output /private/tmp/monero-firmware-new-run
```

The runners emit JSON reports, compiler commands/logs, symbols, maps, and ARM
stack files. Historical primitive measurements are summarized above; verbose
reports and local build trees are omitted from this PR. The runners regenerate
them in a new output directory. The retained
[alpha summary](evidence/2026-11-04-alpha/summary.json) records the current
firmware rebase gates, while public interoperability and adapter regression
inputs remain under `evidence/` because the default tests consume them.
