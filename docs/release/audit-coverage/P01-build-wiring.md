# P01 reviewed build wiring

Scope: the complete changed hunks in the paths below at the frozen product heads.
These dispositions cover build wiring, not the implementation audit of linked
cryptography, RNG, board code or signing consumers. Those remain in their assigned phases.

## Findings and rationale

- Ignore-file changes only exclude local assistant and static-analysis output; they do not change tracked build inputs.
- 7.14.3 adds bip340.c and its native tests. The source exists at crypto pin cdc05bebe9e6989cf711e1b5bea6324fd09f848e. Existing successful native/ARM baseline builds support the source/link wiring. Algorithm and signer review remains P04/dependency scope.
- 7.14.3 board/crypto target order places the RNG library before the emulator provider. The accepted native baseline builds linked and ran those targets; no new configuration is introduced by these hunks.
- 7.14.3/7.15 add rng_health.c to kkrand. The source and public API exist; entropy-site coverage and health policy remain P09.
- 7.15 board, fuzzer and device-tool changes correct the crypto include directory to the pinned trezor-firmware/crypto layout. Only the directory changes; targets and flags are unchanged. No physical bootloader operation was performed.
- The token gate rejects missing, empty and comment-only files and accepts generated X(...) rows. Both product scripts have the same content; the firmware generation target invokes it after both generators. It is a presence gate; row semantics are checked by compilation and signing-table review, not this helper.

## Exact reviewed objects

| Product | Path | Blob |
| --- | --- | --- |
| 7.14.2 | `.gitignore` | `6a4df67a28904668876e2bfe1669a2f6d4337a44` |
| 7.14.3 | `.gitignore` | `6a4df67a28904668876e2bfe1669a2f6d4337a44` |
| 7.14.3 | `deps/crypto/CMakeLists.txt` | `2a9fbff97a03b790945f062d40cd1164b94a149c` |
| 7.14.3 | `lib/rand/CMakeLists.txt` | `ebfd2ce4ecf61bd7ac2a03ec904a7e2e9db9685b` |
| 7.14.3 | `scripts/verify-token-def.py` | `cebe901cb04d21fb4fe7cd1e66bbc0f8e7226189` |
| 7.14.3 | `unittests/board/CMakeLists.txt` | `ddad5512d5054e1925e0256c9b6c76628d16f024` |
| 7.14.3 | `unittests/crypto/CMakeLists.txt` | `22821adc744b3af229462b1128efefd6c956deef` |
| 7.15 | `.gitignore` | `ec14e62d6e056f3d5f1b60321bba6bdb95849b3c` |
| 7.15 | `fuzzer/firmware/CMakeLists.txt` | `99591be6a696a837ca7bc998e5a8f35a7679da83` |
| 7.15 | `lib/board/CMakeLists.txt` | `bb2c376dc8afd7c4214704904315f824cf8274b2` |
| 7.15 | `lib/rand/CMakeLists.txt` | `ebfd2ce4ecf61bd7ac2a03ec904a7e2e9db9685b` |
| 7.15 | `scripts/verify-token-def.py` | `cebe901cb04d21fb4fe7cd1e66bbc0f8e7226189` |
| 7.15 | `tools/blupdater/CMakeLists.txt` | `d5dc9976406da143f930ffdfb08e553b8017786b` |
| 7.15 | `tools/bootloader/CMakeLists.txt` | `e1f4180ae4aed39731f2c5acc735a606d33df4dc` |
| 7.15 | `tools/bootstrap/CMakeLists.txt` | `393dee36dbe75a3c282d90ff67d3fe65acf89b68` |
| 7.15 | `tools/display_test/CMakeLists.txt` | `86da3d16dbf9809ac53c6d1243d1d6fb6dd1a2bd` |
