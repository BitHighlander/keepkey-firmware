# Artifact #0 — device identity, rc30 hardware round

Captured before any test, over WebUSB, Vault stopped.

| field | value |
|---|---|
| version | 7.14.2 |
| firmware_variant | KeepKey (NOT KeepKeyBTC — handler-dependent tests are valid) |
| device_id | 39353036114736342A004600 |
| label | rc30 |
| initialized | True |
| pin_protection | False |
| passphrase_protection | False |
| bootloader_mode | False |
| firmware_hash (first 16B) | 933dc8ff10c7861ab2b25d67e4cc86dd |
| policies | ShapeShift=False, Pin Caching=True, Experimental=False, AdvancedMode=False |

AdvancedMode reads False at rest, matching the compiled default
(include/keepkey/firmware/policy.h). Every phase-B test re-asserts it anyway.

Artifact was UNSIGNED: flashing wiped storage. Seed present at capture time is
disposable and will be wiped again by T1.

TODO: sha256 of the flashed .bin (host-side, not device-readable).
