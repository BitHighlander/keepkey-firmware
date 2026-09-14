# Astra pilot: 7.15 storage and migration

Candidate: [fork PR #756](https://github.com/BitHighlander/keepkey-firmware/pull/756),
base `06b1d249ada75b53d06cb5b7f27512fd276ef83c`, head
`4921cf913521aa5128f3818828cd049f34b90f49`. This is a bounded review
of storage and migration, not a whole-release approval. No code was changed.

| Status | Head path | Trigger and consequence | Verification needed |
| --- | --- | --- | --- |
| P2, new | `lib/firmware/storage.c:1911,1955` | A valid serialized wallet whose CRC32 is zero is rejected on every retry and then wiped without a failed flash operation. | Commit and reboot a valid zero-CRC fixture; preserve its seed. Remove the zero-as-error check and compare RAM/flash CRCs normally. |
| P2, new | `lib/firmware/storage.c:1946` | A failed boot-protection-marker write is ignored after the payload write. Callers can report success, while the next boot sees a missing marker and wipes storage. | Inject failure at marker programming; require an explicit failed commit and wallet survival through the installed bootloader's protection check. A warning alone does not prevent loss. |
| P1, already open | `lib/firmware/storage.c:1922` | Erasing the active sector before a complete replacement leaves no committed wallet after interruption. This is the durability finding already deferred by the scope-repair contract. | Keep it open under the release owner; test interruption at each erase/program boundary through the supported physical bootloader when the separately scoped design is ready. |

The reviewer compiled the candidate's `storage_commit()` and emulator
`calc_crc32()` in a temporary stub harness. A genuine zero CRC yielded one wipe
and zero flash-programming attempts. Injecting a failed marker write yielded a
normal return with no warning or shutdown. A GF(2) rank calculation over the
serialized U2F counter showed that a legal counter can make the record CRC
zero; the CRC API has no reserved zero sentinel. The marker error propagates
from `flash_write()` through the hardware status check, but `storage_commit()`
discards it. The installed bootloader variants and fault frequency were **not**
verified by this harness.

The changed recovery word-count check and setup abort cleanup had no confirmed
finding in this pass. Existing CRC tests cover vectors and tail coverage, but
do not exercise zero CRC or marker-write failure. Both new P2 findings need a
code disposition, regression evidence, and fresh exact-head CI before this
candidate is described as audit-clean. The existing P1 needs its separate
release-owner disposition and physical-device plan.
