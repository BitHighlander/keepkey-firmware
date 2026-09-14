# Storage baseline disposition for #755 and #756

Release-owner decision: defer the inherited storage durability redesign to
7.17 design/evidence work. No bootloader-dependent feature ships through
7.17; any bootloader rollout is a separate later release. Research pending
storage may remain on alpha but is excluded from the release candidates.

## Baselines and source comparison

The latest published firmware in `keepkey/keepkey-firmware` is `v7.14.1`
(published 2026-06-05). `release/7.14.2` is not a published GitHub release, and
`v7.15.0-rc29` is a prerelease tag, so neither is evidence of what users have
installed. Candidate heads: #755 `758746d77`; #756 `5a3bc376`.

| Failure path | Published `v7.14.1` | Candidate evidence | Disposition |
| --- | --- | --- | --- |
| Power cut after old-sector erase, before replacement and marker | `lib/firmware/storage.c::storage_commit()` erases `storage_location`, rotates, erases the destination, writes record body then magic, and calls `storage_protect_off()` last. | Both heads retain that ordering. | Inherited mechanism; redesign deferred. Physical interruption outcome remains unproven. |
| Persistent marker failure | `storage_protect_off()` erases the marker sector and returns only `flash_write()` status; `storage_commit()` ignores that return. `storage_protect_status()` treats a missing marker beside an active record as enabled, and `storage_protect_wipe()` erases all three sectors. | Both heads add marker readback, three attempts, and an explicit warning/shutdown if unsuccessful. This detects transient failure but does not preserve storage across a persistent failure and next boot. | Inherited loss consequence; the new failure response needs device-level confirmation before any non-regression claim. |
| Old active-sector erase fails while magic survives | The erase primitive returns void. The old record can remain the first active sector when `storage_protect_off()` chooses where to write the marker. | Both heads retain void-returning erase and first-magic selection. A one-shot emulator fault reproduced replacement loss on the 7.15 candidate; no equivalent published-build fault injection or physical reproduction yet. | Source-level inherited mechanism, candidate-specific consequence not fully certified. |
| Firmware update from a no-active pending state | Published `tools/bootloader/usb_flash.c::usb_flash_firmware()` erases all storage if `storage_protect_off()` returns false. | Neither release head ships the pending-record protocol. The alpha/research prototype can enter a pending state where this unchanged bootloader path would wipe storage. | Exclude pending-storage feature from release; test later with bootloader rollout. |

The candidate `storage_commit()` code also stamps `STORAGE_MAGIC_STR` before
serializing the record, adds a marker-readback check in shared
`lib/board/memory.c`, and changes the failure response. Those are **real
candidate changes**. This comparison shows the three broad failure mechanisms
pre-date the PRs; it does not certify that the changed code makes every fault
state no worse. Keep the two #755 storage threads open and carry their scope
to #756's ledger. Do not call this a hardware finding or a clean bill of
storage health.

Before a final Copilot request, reconcile all changed storage paths against
the actual release artifact and audit any candidate-specific new or worsened
state. The owner-accepted legacy redesign is excluded from that gate; physical
signing/recovery OLED evidence, dependency pins, full changed-file coverage,
and exact-head CI remain separate gates. The detailed deferred fault matrix is
in [storage-durability-boundary-20260914.md](storage-durability-boundary-20260914.md).
