# Monero firmware proof and PDF

The evidence target is the full, opt-in native firmware emulator. The PDF must
show actual OLED pixels for receive addresses, amounts, fees and every approval
screen, then bind those approvals to signed transaction bytes and independently
observed private-chain results. It must not describe the native signer as an
STM32 signing implementation.

`Monero firmware emulator evidence` supports a full-wallet dispatch. The main
firmware CI calls that same workflow with `full_wallet_evidence: true` and requires
its public bundle before generating the canonical firmware PDF. The ordinary
firmware JUnit, OLED and ARM evidence gates remain required. The Monero appendix
identifies its separate research artifact and exact source revision.

The full run:

1. Authenticates pinned Monero Core source archives and official host binaries.
2. Builds the native signing bridge, host adapter and full firmware emulator.
3. Runs address, watch, key-image, signing and ordinary-build negative controls.
4. Runs the four existing dylib screenshot tests on that exact Monero library,
   plus firmware, board, crypto and Zcash display unit executables built from
   the same unchanged firmware archive. These are specified regressions, not
   exhaustive coverage of every supported coin or physical device.
5. Starts a fresh isolated local Monero fakechain with public test fixtures.
   It funds the emulator wallet, signs two payments, mines both, verifies exact
   recipient credits and spends the first payment's change in the second.
6. Rejects real reviews at the fee, output and final stages, checking that no
   signed or delayed response is returned and signing state is cleared.
7. Exports an allowlisted public bundle and validates its hashes, source
   identity, raw OLED pixels, review ordering, amount balance, signed bytes,
   decoded outputs, mining receipts and recipient payments before PDF rendering.

The public transaction parser reveals version, input rings and key images,
one-time output keys, view tags, encrypted amount fields, commitments, fee and
proof type. Recipient addresses and confidential output amounts are established
separately by fixture-view-key recovery, the approved plan and the recipient
wallet's observed credits. Core checks its own signature/proof format; this is
not an independently implemented cryptographic verifier.

Only the exported public bundle and PDF are uploaded. Raw host directories can
contain wallet keys and authenticated output containers and must remain local.
No mainnet transaction is broadcast, no funded profile is opened and no physical
device is accessed during this workflow. Mainnet-formatted fakechain fixture
addresses shown in the report must not receive funds.

See [the renderer instructions](../../scripts/monero-report.md) for focused and
canonical PDF commands. `prepare_core.py --archives DIR --source DIR` can prepare
the four hash-pinned Core source archives for a clean local build; Core and host
builders accept `--jobs 1` through `--jobs 32` to limit native build memory.

Physical-device completion still requires a bounded MCU signing port, measured
SRAM/stack and signing latency, transport streaming within device limits,
watchdog/interrupt behavior, reset/power-loss testing and actual device approval
and rejection evidence. The PDF keeps that verdict explicit.
