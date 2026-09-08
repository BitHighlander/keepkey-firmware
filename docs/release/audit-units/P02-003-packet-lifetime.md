# P02-003: receive packet storage lifetime (7.14.2)

Base: bae119589956342fdf51914b1c463a1f4dc4acae.

Native UDP reproduction confirms all 64 packet bytes remain after callback
return. Clear the packet buffer after dispatch. Device main/debug/U2F callbacks
have the same persistent storage; wipe after callbacks and on short reads.
This is residual memory retention, not an established remote disclosure exploit.

The new regression fails before the fix and passes afterward. All 155 full
firmware tests pass. Device paths are source reviewed, not native executed;
ARM/host integration remains pending. Normal decoding copies input, U2F copies
fragments, and bootloader RAW consumes packets synchronously. No consumer
retains a packet pointer after callback return. Full phase audit remains open.
