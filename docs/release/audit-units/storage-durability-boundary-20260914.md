# Storage durability boundary for 7.14.3 and 7.15

Status: design analysis, not an accepted fix or release receipt. This applies to
the storage implementation shared by the current #755 and #756 audit heads.

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

## Required decision and validation

The earlier scope repair explicitly excludes bootloader changes and withdrew
the previous durability patch because it altered shared selection logic.
The release owner has kept bootloader changes out of these release lines and
directed that they be held when a storage fix needs a new bootloader. The
firmware-private prototype does not satisfy the update-mode consequence
above, so it must remain outside #755 and #756. The existing scope repair
already removed the earlier shared-selector durability feature from those
candidate diffs. Revisit a complete bootloader compatibility/deployment plan
only on a later line such as 4.17+. An exploratory model review would not
make these releases ready.

Before a final Copilot round, verify transient and persistent erase/write/
readback faults across every transition, reboot through the **installed**
bootloader after each injection point, test V17 migration and rollback, and
run both full and bitcoin-only product variants on exact candidate heads.
Emulator source review alone does not close the physical next-boot gate.
