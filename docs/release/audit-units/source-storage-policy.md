# Storage source-policy reconciliation

7.15 is the non-destructive V17 bridge. It preserves unreadable newer
normal-band storage across a downgrade by returning `SUS_TooNew`, clearing only
the RAM shadow, and refusing every commit until the user explicitly wipes. This
is not a parser compatibility shim: the older firmware never loads the newer
record. Reinstalling the newer firmware can therefore recover the wallet.

The retained contract is upgrade preservation, contiguous shipped-version
recognition, explicit refusal of formats the running firmware cannot parse, and
byte-identical preservation while that refusal is active. Bitcoin-only storage
uses the parallel `SUS_BitcoinOnlyLocked` path. The canonical python-keepkey
reboot tests derive which policy a firmware tree implements so older releases
that deliberately reset unknown storage and 7.15's non-destructive bridge can
share one branch without version-string gates.

Signed physical upgrade verification remains a final release gate; emulator
tests prove firmware storage behavior but cannot prove bootloader signature
handling.
