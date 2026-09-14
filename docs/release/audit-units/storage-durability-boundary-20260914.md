# Storage durability boundary for 7.14.3 and 7.15

Status: design analysis and deferred legacy risk, not an accepted fix or release
receipt. The release owner deferred the three durability/fault paths described
here from 7.14.3 and 7.15 on 2026-09-14. Track their design, fault matrix and
physical evidence in 7.17; do not ship a feature needing new bootloader behavior
in 7.14.3, 7.15, 7.16 or 7.17. Bootloader deployment needs a separate later
release plan. This applies to the storage implementation shared by #755/#756.

The underlying erase/rotate and bootloader-update behavior is present in the
published v7.14.1 tag and the v7.15.0-rc29 tag. Candidate code changes can
still alter failure consequences, so this inheritance finding is not a blanket
"no regression" certification. Compare fault states against the actual shipped
product artifacts before release. Keep unresolved review threads and risk
acceptance visible; a green CI run does not prove power-cut safety.

## Bootloader compatibility invariant

`find_active_storage()` selects the first sector, in numeric order, whose first
four bytes are `stor`. The bootloader calls `storage_protect_status()` before
booting firmware. That routine requires `STORAGE_PROTECT_OFF_MAGIC`
at the start of `next_storage(active)`; otherwise `storage_protect_wipe()`
erases all three wallet sectors. Firmware uses the same shared board source,
but changing it in a new firmware image does not change an installed
bootloader's behavior. Confirm the actual installed bootloader version and
binary in the physical gate; this source analysis does not attest a device.

Every power-cut state that may reach that bootloader therefore needs a
recoverable wallet record selected by first-magic order *and* the marker in
the sector immediately following that selected record. A CRC-valid pending
record that the installed bootloader cannot select does not satisfy this
invariant.

## Why the current transition fails, and a possible firmware-only route

Start with sector 1 containing the active record, sector 2 the marker, and
sector 3 spare. Firmware currently erases sector 1, writes a replacement to
sector 2, then writes the marker to sector 3. A cut after either erase but
before the new record and marker are complete leaves no safe next boot.

Writing sector 3 first while retaining sector 1 and its sector-2 marker can
preserve the old boot state. The replacement must initially have **no**
leading `stor` magic, plus a verified trailer that new firmware can recognize
without changing shared bootloader code. Then firmware can retire sector 1.
At this point the bootloader's existing `storage_protect_status()` returns
`STORAGE_PROTECT_DISABLED` when it finds no active record, so it preserves
flash on the next boot. New firmware must recover the pending record by
writing its marker into sector 1, then its final magic into sector 3. The
withdrawn durability patch used this no-active transition, but it also
changed shared board selection code; that part crossed the owner-set scope
boundary. A firmware-private pending selector may avoid the boundary.

This route is a **candidate design, not a release fix**. It needs power-cut
enumeration at every write/erase point, especially a failed old-sector erase
that leaves `stor` visible, partially programmed final magic, repeated
recovery faults, and an old-firmware rollback after the pending state exists.
On an old-sector erase failure, firmware must not finalize a second active
record or let `storage_protect_off()` erase the verified replacement. It must
verify the old magic is gone and preserve the old record plus its marker if
that verification fails.

The existing `storage_commit()` also trusts the void-returning old-sector
erase. If its magic survives, `storage_protect_off()` may select that old
sector and erase the newly verified record to write a marker. A native
one-shot erase-fault reproduction is recorded in the re-audit handoff; it
requires a permanent regression on both lines.

A persistent marker write/readback fault cannot be made safe by more retries
in the **current** commit flow: it leaves a visible active record whose marker
may be invalid, so bootloader wipe follows. In the pending route, recovery
must keep the new record non-active until its marker is verified; the
bootloader's no-active path can preserve it for an ordinary later reboot.
There is a second unchanged bootloader path: `usb_flash_firmware()` in
`tools/bootloader/usb_flash.c` erases all storage when `storage_protect_off()`
fails during an update. With no active record, that call returns false. A user
who enters firmware-update mode while a persistent marker fault keeps the
wallet pending therefore loses the pending record. Firmware cannot prevent a
physical bootloader-entry action. The experimental firmware-only transition
does **not** close the persistent-fault release blocker under the required
no-bootloader-change scope.

The isolated prototype is local commit `ebdedeff3` on
`research/417-storage-pending`. It leaves `tools/bootloader/`, the shared
`lib/board/memory.c` selector and board headers unchanged. Its native
`firmware-unit` suite passed 561/561, including emulated boot-policy replay
at completed commit operations, partial write prefixes, marker faults and an
old-sector erase fault. These are firmware and emulator results only; the
update-mode wipe path above remains open.

## Deferred design and validation

The earlier scope repair explicitly excludes bootloader changes and withdrew
the previous durability patch because it altered shared selection logic.
The release owner has deferred the inherited durability redesign rather than
holding these releases on its completion. The firmware-private prototype does
not satisfy the update-mode consequence above, so it must remain outside #755
and #756. Research code may remain on alpha; it is not evidence of release
readiness and must not be carried into a release artifact accidentally. The
existing scope repair removed the earlier shared-selector durability feature
from both candidate diffs. 7.17 owns the design/evidence backlog, with any
bootloader-dependent implementation and rollout after 7.17.

Before claiming the redesign is safe, verify transient and persistent
erase/write/readback faults across every transition, reboot through the
**installed** bootloader after each injection point, and test V17 migration
and rollback. For 7.14.3/#755 and 7.15/#756, separately verify that their
changed storage paths do not introduce a new or worse failure than the actual
shipping baseline, and run both full and bitcoin-only variants on exact heads.
Emulator source review alone does not establish the physical consequence.
