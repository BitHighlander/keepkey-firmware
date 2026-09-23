# P02-003: receive packet storage lifetime (7.14.3)

Base: 97f970147fe23f5cfa95b3575ab8f5874c1ad140.

Native UDP reproduction confirms all 64 packet bytes remain after callback
return. Clear the packet buffer after dispatch. Device main/debug/U2F callbacks
have the same persistent storage; wipe after callbacks and on short reads.
This is residual memory retention, not an established remote disclosure exploit.

The new regression fails before the fix and passes afterward. All 90 Bitcoin-only
firmware tests pass. Device paths are source reviewed, not native executed;
ARM/host integration remains pending. Normal decoding copies input, U2F copies
fragments, and bootloader RAW consumes packets synchronously. No consumer
retains a packet pointer after callback return. Full phase audit remains open.
