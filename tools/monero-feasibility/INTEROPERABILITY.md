# Address and key-image experiment

The subsequent [address-command stage](COMMANDS.md) adds real protobuf/HID
requests, normal wallet authorization, and address confirmation to the native
emulator. The in-process results below remain the earlier arithmetic baseline.

The latest [wallet stage](WALLET.md) also implements private view-key export,
encrypted key-image sync and bounded real transaction signing in the emulator.

The first integration target is the **native KeepKey firmware emulator** used
by Vault. Physical-device work is deferred. A prepared hardware image is not
part of this stage's execution or acceptance criteria.

## Results on 2026-11-04

| Check | Result |
| --- | --- |
| Independent host reference comparison | 96 cases, 2,823 checks passed under ASan/UBSan |
| Deliberate derivation/scalar/key-image faults | All three detected by assertions |
| Actual native `libkkemu` firmware build | 96 cases, 2,823 checks passed |
| Firmware BIP-39/SLIP-0010 derivation | Four public mnemonic/account paths matched the independent reference |
| HID packet rings before and after the test | GetFeatures/Features exchange passed, version 7.17.0 |
| Simulated flash during the test | Unchanged; fresh anonymous buffer, no seed installed |
| Emulator lifecycle guards | Entry rejected before initialization and after shutdown |
| Physical device | Not used |

The native run captures the real firmware OLED results screen. Host runtime
is recorded in its report and is not a physical-device performance estimate.
The research entry is an optional emulator-only FFI self-test; it does not add
a Monero protobuf command or implement full transaction signing.

An instrumented Unicorn run produced a false varint boundary failure: an empty
memory-write hook alone reproduced it, while the same eight-case ELF passed all
271 checks without memory hooks, including the exact `UINT64_MAX` case. The
candidate crypto code was not changed to accommodate that discrepancy. The
failed traced run's instruction/stack measurements are discarded; do not use
them as firmware resource or timing evidence.
The corrected full 96-case ARM instruction run was not completed in this
stage; the complete integration result is the native firmware emulator run.

This extends the [primitive feasibility experiment](README.md). It is research
using public disposable fixtures, with no production wallet input or firmware
command exposed.

## Independent reference

`reference.py` compiles a host-only adapter against Monero Core revision
`b14fae7bca4099cea56205e44c1005602834b7bd`. It verifies SHA-256 hashes for nine
upstream source files before building. The adapter uses Core's Keccak,
scalar reduction, group operations, and hash-to-point implementation. It never
links the candidate Trezor crypto code.

The Python reference independently implements BIP-39/SLIP-0010 and the wallet
recipe. Known Trezor device address/view-key vectors for accounts 0 and 1
validate that recipe; known base-point, hash-to-point, and key-image anchors
validate the Core adapter. This is a direct comparison with Core arithmetic,
not a `monero-wallet-cli` or Monero network test.

The tested key-image mapping is Core's pre-FCMP++/Carrot biased
Keccak/fromfe/mul8 path, used by the legacy/CLSAG implementation. It does not
exercise Core's newer unbiased mapping. Compatibility with FCMP++/Carrot is
unresolved; selecting current Core as the reference does not imply support for
every protocol variant in that revision.

The selected convention is Trezor-compatible:

1. Derive the Ed25519 SLIP-0010 node at `m/44'/128'/account'`, using the BIP-39
   seed and empty passphrase for these public fixtures.
2. Reduce the node's private key directly modulo the Ed25519 subgroup order
   to obtain the spend secret. **Do not hash the node key first.**
3. Reduce Keccak-256 of the canonical spend-secret bytes for the view secret.
4. Treat subaddress `(0,0)` as the base address. For other subaddresses, use
   `m = Hs("SubAddr\0" || view || LE32(major) || LE32(minor))`,
   `D = B + mG`, and `C = view * D`.

The original link-only `probe.c` intentionally used a synthetic hash-to-spend
recipe. It is retained as historical size-test code and is not the derivation
implementation for this experiment.

## Checks

`interoperability.c` uses the generated fixtures on both host and ARM. The 96
cases cover two published test mnemonics, accounts 0 and 1, base addresses plus
subaddresses `(0,1)`, `(1,0)`, `(100,100)`, and output indices `0`, `1`, `127`,
`128`, `65537`, `UINT32_MAX`. All secret-looking values in the fixture report
are reproducible public test material.

Each case compares spend/view secrets and public keys, subaddress public keys,
the 95-character mainnet address, sender and recipient derivations, one-time
output secrets/public keys, and key images. Sender and recipient derivations
must agree. The output secret must correspond to the independently calculated
output public key, including the subaddress-secret adjustment.

Negative checks cover address-checksum corruption, short address buffers,
varint capacities and boundary values, invalid/identity/torsion points, zero
and noncanonical scalars, and mismatched public/secret key pairs. The lifted
scalar test adds the subgroup order to a valid scalar: its public key is
unchanged, so key-pair validation alone cannot reject it.

The experiment initializes point coordinates before the upstream positive-point
decoder: that wrapper negates coordinates even after a failed decode. The
research boundary then requires canonical encoding and a nonidentity point in
the prime subgroup. This does not constitute an audit of every raw library API.

The host runner uses ASan/UBSan and verifies that three deliberate mutations
fail assertions: hashing the node key instead of reducing it, removing the
canonical-scalar check, and corrupting a key-image fixture. Sanitizer crashes
do not count as successful mutation detection.

## Execution boundaries

`emulator.py` builds the real `kkemulator_dylib` target with an explicit research
overlay. It allocates an anonymous erased 1 MiB flash buffer and uses the same
`kkemu_init`, HID ring buffers, polling, display, and shutdown lifecycle as a
native Vault emulator session. GetFeatures is exchanged over the packet rings
before and after an in-process research FFI call that runs the 96 public cases.
That call also exercises the firmware's actual `mnemonic_to_seed`,
`hdnode_from_seed`, and hardened child-derivation functions for both public
mnemonics and both account paths, comparing their node keys with the independent
reference. These four checks use local temporary seed/HDNode buffers, which are
wiped after each case; they do not install a wallet seed in simulated storage.
The flash is compared after initialization and after testing. No `emulator.img`,
real wallet seed, physical USB connection, or background poll thread is used.

`arm_execute.py` compiles the same C checks for Cortex-M3/Thumb and executes
the resulting ELF with Unicorn. It maps the KeepKey application flash/SRAM
regions and rejects unexpected unmapped/MMIO accesses, RNG calls, aborts, and
stack-canary failures. It records instruction counts and painted-stack use.
Emulator wall time and instruction counts are not physical MCU cycles or
device latency. Stack use applies to the test call chain; USB and actual
interrupts require the separate device test.

`hardware.py` prepares an unsigned, boot-only self-test image with a smaller
representative fixture set. It runs after board initialization and stops on a
results screen before normal wallet storage and protocol initialization. It
does not make Monero available to the normal wallet application. Preparation
and actual execution are reported separately; a built image is not a hardware
measurement. Installing unsigned firmware can cause a bootloader storage wipe.

## Reproduce

Obtain the pinned Monero Core checkout, with its original license headers, then
provide its path. `reference.py` and `interop.py` perform no network I/O:

```sh
git clone https://github.com/monero-project/monero /private/tmp/monero-core
git -C /private/tmp/monero-core checkout b14fae7bca4099cea56205e44c1005602834b7bd
python3 tools/monero-feasibility/interop.py \
  --core-source /private/tmp/monero-core \
  --output /private/tmp/monero-interop-fresh
```

Host prerequisites: a C compiler with ASan/UBSan, `pkg-config`, libsodium, and
Boost headers (the generator defaults to `/opt/homebrew/include`). The
reference itself can be run separately with `reference.py --core-source ...
--output ...`; its `--boost-include` option accommodates other installations.

For ARM execution, install `unicorn==2.1.4` and `pyelftools==0.33` in an isolated
Python environment and invoke `arm_execute.py` with the generated
`reference/interop_vectors.h`, a fresh `--output` directory, and
`--arm-prefix /path/to/gcc/bin/arm-none-eabi-`. The paired runner also accepts
`--arm-prefix` and `--arm-python` to execute host and ARM comparisons together.

To run the actual native firmware emulator first, use the local KeepKey
toolchain layout described in the primitive experiment:

```sh
python3 tools/monero-feasibility/emulator.py \
  --reference /private/tmp/monero-interop-fresh/reference/reference.json \
  --toolchain-root /Users/highlander/keepkey-toolchain \
  --output /private/tmp/monero-native-emulator-fresh
```

The output includes a JSON result, configure/build logs, packet transcripts,
the research shared library, and raw/PGM captures of the firmware OLED screen.
This command does not install or flash firmware on a device.

Generated JSON reports retain reference source hashes, fixture expectations,
mutation results, compiler versions, and candidate source hashes. Hardware
measurements remain null until a physical self-test is actually observed.

The retained [public reference vectors](evidence/2026-11-04-interoperability/host.json)
are the default test inputs. The [historical findings](evidence/2026-11-04-interoperability/README.md)
record the scope and discarded instrumentation result. Verbose execution reports
and OLED captures are omitted from this PR; the commands above regenerate them.
The [alpha summary](evidence/2026-11-04-alpha/summary.json) records the current
full-wallet and receive-only native firmware gates.

## Remaining work

Passing these checks establishes the tested address/output/key-image arithmetic
and wallet convention. It does not establish transaction signing, Monero GUI
integration, wallet scanning, authenticated host offloading, UI confirmation,
reset/cancellation behavior, checked signing entropy, or current transaction
format support. Those require implementation and independent transaction-level
tests before enabling a production firmware capability.
