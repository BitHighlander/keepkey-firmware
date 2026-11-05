# Native emulator wallet results

The current [alpha summary](../2026-11-04-alpha/summary.json) records the
reproduced native wallet and receive-only builds, exact base/dependency
revisions, source/artifact hashes and stage counts.

The full wallet run passed 1,248 workflow checks and verified 15 synthetic
HF16 CLSAG/Bulletproof+ transactions. Coverage includes addresses, consented
view-key export, owned-output key-image proofs, transaction review, PIN and
passphrase authorization, malformed inputs, cancellation and state wiping.
The ordinary emulator rejected the added command IDs. The separate
receive-only build explicitly rejected signing and had no native Core
signing dependency.

Transaction construction still uses a native C++ Core bridge. Core proof
verification is not a second independently implemented proof verifier.
Top-level buffer wipes do not establish erasure of inherited crypto stack
frames. No physical device or real wallet was accessed; synthetic funding
was not broadcast. Production readiness remains false.

Verbose historical reports, wire transcripts, copied fixtures, transactions
and display captures are generated artifacts and are omitted from this PR.
All source and tests remain. [WALLET.md](../../WALLET.md) gives the complete
reproduction commands; `wallet_emulator.py` regenerates aggregate/stage JSON,
source hashes, signed transactions and OLED captures in a new output directory.
