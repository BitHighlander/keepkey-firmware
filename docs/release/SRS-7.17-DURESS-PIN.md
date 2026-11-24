# Opt-in duress wipe PIN

Firmware review candidate for 7.17. An owner with an ordinary PIN can send
ChangeWipeCode, confirm the destructive purpose on the device, enter their
current PIN and enter a different duress PIN twice. Removing the ordinary PIN
clears both. Clearing the duress PIN alone requires the same approval and
authentication whether enrolled or already clear.

On production firmware a locked device omits wipe_code_protection from
Features in both states. A host receives the usual randomized PIN matrix.
There is no validate-only request. Cancelling before submission does not
evaluate a PIN. Submitting the duress PIN erases this device's wallet and
settings without another confirmation. A recovery phrase stored elsewhere
can still restore the funds. This proposal covers firmware and its USB
protocol. It does not add a Desktop setting.

After the ordinary failed-attempt precommit, firmware writes and verifies
a 16-byte intent in the spare storage sector before teardown or a response.
The first complete intent is the commitment point. Boot checks it before
selecting an active or staged wallet record. Recovery erases and verifies
the active sector, then its boot-protection sector, and finally the intent
sector. If power fails during that last erase, both possible wallet sectors
have already been verified blank. Before commitment, loss of power can leave
the wallet accessible. After commitment, normal boots must complete erasure.

## Acceptance on disposable hardware before release

- Compare production USB transcripts and OLED behavior for enrolled and
  unenrolled devices at discovery, PIN request, cancellation, and ordinary
  unlock. Check timing and the historical OLED concern independently.
- Cut power around PIN submission, intent programming, and each sector erase.
  Repeat cuts during recovery. Capture USB and OLED output against flash
  checkpoints. After the first wipe-specific indication, the old wallet must
  remain inaccessible across every subsequent normal boot.
- Exercise all three active-sector positions, the supported bootloader and
  both firmware variants. Check entry into bootloader update mode after a
  cut separately. DebugLink, invasive flash inspection, and a host that
  witnessed enrollment are outside the locked production interface claim.
