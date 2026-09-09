# Released bootloader storage replay

This rehearsal supports the P03 durability audit. It executes released 2.1.4
storage-protection ARM routines against the existing commit-snapshot tests.
See the P03 ledger for scope, binary addresses, identities and limitations.

1. Download `blupdater.bin` from the [upstream v7.3.2 release](https://github.com/keepkey/keepkey-firmware/releases/tag/v7.3.2).
   Verify updater SHA256 `6bb7cfd28262fcd61c450fdc3f6932650bdf16a134ab6c1bc6f90b0d1578e620`.
   Extract 262144 bytes starting at offset 0x3204 into `bootloader-2.1.4.bin`.
   The runner independently requires the firmware-recognized double-SHA256.
2. Install `unicorn==2.1.4` in an isolated Python environment. The
   [Unicorn API documentation](https://www.unicorn-engine.org/docs/tutorial.html)
   describes the memory mapping and bounded execution APIs used by the runner.
3. Build the selected firmware native tests. Create an empty snapshot directory
   and a separate fresh working directory. From the fresh working directory run
   the absolute path to `firmware-unit --gtest_filter=PassphraseTransition.*`
   with `KK_TEST_STORAGE_SNAPSHOTS` set to the snapshot directory's absolute path.
   Require all seven cases to pass before replay; preserve its log and exact head.
4. Run `python bootloader_storage_gate.py bootloader-2.1.4.bin SNAPSHOT_DIRECTORY`.
   Require exit zero, 799 controls and 17 snapshot passes. Preserve its JSON,
   native log, source head, pins and build variant together.

Run native/emulator variants serially. Snapshot files contain only the fixture's
fixed test mnemonic; never point the exporter or runner at a hardware-wallet dump.
The binary runner reads its inputs and operates entirely in process memory.
The erase hook records intended allocations; it does not access a device or
model analog flash behavior. A timeout, wrong binary hash, missing/extra snapshot,
unexpected return or failed control is an error, not a passing or skipped test.
