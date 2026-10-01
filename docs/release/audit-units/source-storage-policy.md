# Storage source-policy reconciliation

Source reconciliation at Block 13 checkpoint `123bb0335` on 2026-09-27:
7.15 writes storage version 17 and already implements the non-destructive
bridge for newer normal-band records. The earlier claim that this candidate
deliberately wipes those records was stale; its cited `docs/StorageVersionGate.md`
is absent from this tree.

`storage_fromFlash()` returns `SUS_TooNew` before invoking a reader when
`STORAGE_VERSION < raw_version < STORAGE_VERSION_BTC_ONLY_BASE`.
`storage_init()` clears the RAM storage shadow, preserves the device metadata,
sets `firmware_too_old`, and does not commit. `storage_commit()` refuses writes
while that flag is set. This keeps the existing flash record available to
firmware that understands it; it does not parse an unsupported format. The
supported version ladder and its shipped-version floor still govern ordinary
upgrades. `StorageVersion_NONE` remains `SUS_Invalid`, whose boot path resets
and commits; the newer-record refusal must not be described as a blanket policy
for all invalid records.

The Bitcoin-only band is separate. Full firmware refuses band-stamped records
with `SUS_BitcoinOnlyLocked`; Bitcoin-only firmware reads supported underlying
versions and refuses newer ones. The locked boot preserves flash and metadata,
and the same commit guard prevents overwrites. `storage_wipe()` clears both
lock flags and erases storage. Host-requested `WipeDevice` retains physical
confirmation before reaching that operation.

The following mappings were inspected in source for this documentation
correction. They are not new execution receipts for Block 13.

| Contract | Existing checks and limits |
| --- | --- |
| V17 bridge and newer normal-band refusal | `Storage.BridgeReleaseDoesNotMigrateFormat` checks version 17; `Storage.NewerStorageVersionRefusedNotWiped` checks reader-dispatch status for current, next eight, older, and band-stamped versions. These native checks do not themselves prove flash preservation at boot. |
| Bitcoin-only classification | `Storage.BitcoinOnlyBandRefused` (full), `Storage.BitcoinOnlyBandMigrates` (Bitcoin-only), and `Storage.FutureBitcoinBandValuesNeverFallThroughToWipe` cover the product boundary and high unsigned values. |
| Reboot persistence and migration | `TestStorageUpgradePreservation.test_reboot_preserves_the_wallet`, `test_v16_blob_upgrades_without_wiping`, and `test_unframed_v16_blob_upgrades_without_wiping` in canonical `test_storage_version_gate.py` compare wallet state/address across reboot. |
| Refused records remain intact | The historical test name `test_unrecognised_version_wipes_on_boot` is retained, but its `SUS_TooNew` branch asserts byte-identical flash and an uninitialized RAM view. `test_bitcoin_only_band_refuses_without_wiping` checks the product-specific band behavior and recovery after restoring the supported stamp. |

S13-008 found that the persistence guard alone did not protect wallet creation.
`CHECK_NOT_INITIALIZED` rejected the Bitcoin-only lock but omitted
`storage_isFirmwareTooOld()`. On a newer normal-band record, `LoadDevice`,
`ResetDevice` and `RecoveryDevice` could pass their start guards; a completed
operation could report success even though `storage_commit()` refused to
persist the new wallet. The repair adds the newer-format check to their shared
`CHECK_NOT_INITIALIZED` macro before consent, entropy collection or seed import.
The original retained record and the confirmed wipe path remain unchanged.

The new native USB tests
`Block13Entropy.NewerNormalBandRefusesAllWalletCreationUntilWipe` and
`Block13Entropy.NewerBitcoinBandRefusesAllWalletCreationUntilWipe` exercise all
three starts using disposable flash stamped V18 and 10018. They require one
failure without consent or continuation requests, no armed setup or initialized
RAM seed, and byte-identical flash. They then confirm a wipe, load a valid wallet
and reload it through `storage_init()`. The old-macro negative control failed for
the newer normal-band case and passed its Bitcoin-only control
(`block13-storage-before.xml`/`.log`); repaired execution remains pending.

Other administrative settings handlers still need their own refusal review;
this repair covers wallet creation. Combined candidate execution, real
power-loss behavior and signed physical upgrade verification remain pending.
Reloading an emulator image through `storage_init()` does not establish physical
reboot behavior, bootloader signature handling or installation recovery on a
physical device.
