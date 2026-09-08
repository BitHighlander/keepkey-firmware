# P01 SRAM gate review (7.15)

Status: gate implementation inspected; runtime interaction audit remains open.
No SRAM threshold or firmware allocation was changed during this review.

Reviewed `tools/check_sram_budget.py`, `tools/sram-budgets.json` and the
16 KiB assertion added to `tools/firmware/keepkey.ld` at a18317f88.
The saved full ARM artifact from CI 34283763680 has a 16,392-byte reserve
and a largest reported static frame of 7,664 bytes. Re-executing the gate
accepts it; empty .su archive, an oversized frame and a reserve requirement
one byte above the measured reserve each fail as expected. Used isolated
Python with pyelftools 0.32; no firmware rebuild or hardware execution.

The archive contains 180 .su files / 1,848 records: 1,837 static,
2 dynamic,bounded and 9 dynamic. Bitcoin-only has 144 files / 1,215 records:
1,210 static and 5 dynamic. Neither archive contains malformed records.

## Interaction obligations (not additional findings)

The numeric size of an unbounded dynamic GCC record is not a complete frame
bound. Likewise, largest-single-frame margin does not establish worst-case
nested call-chain consumption. Do not cite this gate as a complete SRAM proof.

Dynamic entries are base32_8to5; base58 encode/decode wrappers and primitives;
and, on full, the corresponding Ripple functions. The two bounded records are
EOS authorization/vote-producer. Initial source trace: base32 rejects lengths
above eight; checked base58 wrappers cap positive input lengths at 128;
Solana's raw encoder callers pass SOL_PUBKEY_SIZE (32). Ripple callers pass
fixed address sizes. Complete caller/domain and cumulative stack review remains
P04/P06/P07/dependency scope; these observations are not a complete disposition
of those implementations or negative-length domains.

Runtime high-water measurement remains an external hardware validation gate as
already specified by the budget file. Keep software call-chain review distinct
from that physical measurement. No observed overflow was established here.
