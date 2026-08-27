# Storage version and downgrade policy

Status: updated for the 7.16 V20 release candidate. Read this before touching
`STORAGE_VERSION`, `storage_versions.inc`, or `STORAGE_PIN_KDF_V19`.

---

## 0. The rule that nearly got "fixed" into a vulnerability

**Wiping storage on downgrade is intentional. It is a security control, not a
bug.**

`storage_fromFlash` maps any version it does not recognise to
`StorageVersion_NONE`, which `storage_init` answers with `storage_reset()` +
`storage_commit()`. That looks like data loss, and during the RC27 audit it was
proposed to "refuse rather than reset" so the wallet would survive.

Do not do this. If storage survived a downgrade, an attacker with physical
access could flash an older *validly signed* image carrying a known extraction
bug and keep the seed. The wallet would then only ever be as strong as the
weakest firmware KeepKey has ever signed. Wiping means a downgrade yields an
empty device, and the attack buys nothing.

The correct way to spare an honest user is to stop the downgrade from
happening, not to make it non-destructive. That is what the security epoch in
`anti-rollback-security-epoch-rfc.md` is for.

### The one exception, and why it is not a contradiction

The bitcoin-only band (`StorageVersion_BTC_ONLY`) *does* refuse rather than
wipe when it sees a wallet newer than the running firmware understands. That is
a different axis: it separates bitcoin-only from multi-chain firmware, not new
from old. Rollback protection still holds, because genuinely older firmware
does not know the band exists — it sees an unrecognised version and wipes, as
above.

---

## 1. Where things stand

| Version | State |
|---|---|
| 17 | **Last shipped storage version.** Same as shipped v7.14.1/7.15. |
| 18 | **Burned.** An alpha clear-sign identity layout wrote this number. It is never reused. |
| 19 | **Burned.** An alpha PIN-KDF layout wrote this number. The rewrap remains disabled behind `STORAGE_PIN_KDF_V19 == 0`. |
| 20 | **7.16 release candidate.** Stores passkey state in V17's reserved area and scrubs the retired identity block. It must not ship until the bootloader security-epoch and exact-candidate V17→V20 hardware gates pass. |

Internal devices that ran the old alpha V18 or V19 formats can be wiped by
other builds exactly per §0. Those numbers remain in `storage_versions.inc` so
the enum stays positional, but V20 never interprets either record as passkey
state. Internal testers need their recovery phrase before changing lines.

### Why the revert was needed

Booting RC27 once on an existing wallet silently migrated it 17 → 19 and
re-committed. No prompt, no user action. From that moment the device could not
be downgraded without being wiped, and nothing in the release enforced a
minimum epoch, so the wipe would fire on ordinary users — including anyone who
drops an older signed `.bin` on Vault's firmware drop zone. Shipping a one-way
migration ahead of the mechanism designed to make it safe is the ordering
`pin-kdf-v19-migration.md` explicitly warns against.

---

## 2. The trap that shapes the gate

The v19 marker is a single flag bit (bit 20 of the public flags word) that only
round-trips in storage version 19. So a v19 *rewrap* and a v19 *write* must be
enabled together, or not at all:

- Rewrap without the version → the key is wrapped with v19 parameters and read
  back as v15/v16 on the next boot. The wallet is not wiped, it is **silently
  and permanently unlockable-by-nobody**, with flash otherwise intact. That is
  worse than a wipe.
- Version without the rewrap → harmless but pointless.

This is why `STORAGE_PIN_KDF_V19` gates the rewrap in
`storage_isPinCorrect_impl` and not just the serializer. The invariant to hold
in review:

> The KDF version selected at unlock must be the one the persisted flag will
> still describe after `storage_commit()`.

The same trap makes a "read V19 but write V17" bridge impossible: reading a
v19 record and committing it as v17 drops the flag while the wrapped key stays
v19-wrapped. Re-wrapping downward needs the PIN, which is not available at
boot. There is no safe path back down; migrated devices wipe and restore.

---

## 3. Enabling the dormant V19 PIN-KDF rewrap

All of the following, in order. Flipping `STORAGE_PIN_KDF_V19` to 1 is the
*last* step, not the first.

1. Implement the anti-rollback security epoch in the bootloader
   (`anti-rollback-security-epoch-rfc.md` is a design note; nothing implements
   it today).
2. Prove bootloader update and interruption behaviour on real devices.
3. Benchmark the 100,000-iteration PIN path on every supported board revision —
   minimum, median, maximum unlock latency, across temperature and power.
4. Exercise v15, v16, V17 and V20 records through wrong PIN, correct PIN,
   interrupted commit, reboot, and recovery.
5. Power-loss testing at every write boundary during the rewrap commit.
6. Ship in a release whose minimum epoch **refuses** firmware that cannot read
   the active storage version, so a downgrade is rejected up front instead of
   wiping.

Only then, in a new storage version: round-trip a dedicated KDF flag in that
version, switch the rewrap and serializer together, and set
`STORAGE_PIN_KDF_V19` to 1. Do not repurpose burned version 19 and do not infer
permission from the fact that V20's compatibility reader can parse its alpha
shape.

The `_Static_assert(VAL == STORAGE_VERSION)` in `version_from_int` and the
absent `default:` case in the `storage_fromFlash` switch mean the compiler
enumerates every site for you. Trust it over grep — that is how the revert was
done.

---

## 4. Clear-sign identity block

`ClearsignIdentity` and the 910-byte `clearsign_identities` array are what made
the alpha version 18. They are **dead**: nothing reads or writes them.

They exist because persisting clear-sign signer identities to public flash was
**rejected** — a rogue persisted signer suppresses the raw-data screen, and
public storage has no authenticated integrity against physical flash
modification. The block was reserved and scrubbed so nothing could outlive a
factory reset.

**Clear-sign does not need it, and the KeepKey-controlled-key direction needs it
least of all**: a KeepKey-issued schema signature verifies against a built-in
anchor compiled into the firmware, which costs zero device storage. If that is
the chosen endgame, the identity block should be deleted outright rather than
carried into a new format.

The 7.16 passkey candidate writes V20, never parses or trusts V18/V19 as passkey
state, and never carries forward the retired identity block. It removes the
legacy in-memory identity array, reclaiming ~910 bytes from the `ConfigFlash`
shadow copy, and keeps the bounded V20 record within the V17 footprint.

---

## 5. Related audit findings

- The `storage_write*` family takes a `len` it does not honour —
  `storage_writeV17` guards `len < 1024` then writes to offset 2569, and the
  historical V18 variant guarded the same 1024 while writing to 3479. V20's
  bounded serializer has its own full-length guard; the legacy V17 contract is
  still wrong and should be fixed separately. `.cppcheck-suppressions`
  currently blanket-suppresses
  `bufferAccessOutOfBounds` for `storage.c`, so CI cannot see either.
- Vault should warn before flashing firmware older than the connected device's
  storage version, whichever way this policy lands. The wipe is correct; a
  user meeting it with no warning is not.
