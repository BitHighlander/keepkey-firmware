# Clear-sign signing authority: why delegation, and the road to it

Status: roadmap for audit. Written to be read by an auditor deciding what to
attack, and by an implementer deciding what to build next.

Companion docs: `7.15.0-rc21-clearsign-release-control.md` (what ships today),
`anti-rollback-security-epoch-rfc.md` (the epoch mechanism this depends on).

---

## 1. What clear-signing is defending against

A hardware wallet's only real guarantee is its own screen. Everything else —
the host, the browser, the dapp, the RPC — is assumed hostile. Blind signing
breaks that guarantee: the user approves a digest, and the screen cannot say
what the digest means. Every drainer attack lives in that gap.

Clear-signing closes it by rendering intent on the trusted display: *who* the
counterparty is, *what* the call does, and with *what* amounts.

The problem is that the device cannot compute that rendering by itself.
Decoding an arbitrary contract call means knowing the ABI, the token decimals,
the protocol's semantics. A 168 KB-of-RAM device cannot hold the world's
contract metadata, and it must not learn it from the same host it distrusts.

**So something has to tell the device how to render a call, and the device has
to be able to verify that instruction came from someone it trusts.** That
"someone" is the signing authority. Every design decision below follows from
having to run one.

---

## 2. Two blob formats, and only one needs a hot key

`signed_metadata.h` already draws the line:

| | v1 `METADATA_VERSION_LEGACY` | v2 `METADATA_VERSION_SCHEMA` |
|---|---|---|
| Scope | one specific transaction | a contract + selector, statically |
| Carries | committed `tx_hash` + pre-decoded values | decode instructions only, no values, no hash |
| Who decodes | the host; device binds to the digest | **the device**, from the calldata it is about to sign |
| Signing | **online, per transaction** | **once, offline**; servable from a CDN |
| Key exposure | hot key, reachable at tx time | none |

v2 is the better design wherever it reaches, precisely because it has no hot
key: the display is bound to the signature by construction, since the device
derives the values from the exact bytes it signs.

**v2 does not reach everywhere.** It cannot cover:

- contracts absent from the catalog — the long tail, and where drainers live;
- values not derivable from calldata alone (token symbol/decimals for an
  arbitrary address, ENS/name resolution, off-chain quote or route data);
- aggregator and bridge flows whose meaning depends on off-chain state at
  quote time;
- anything needing *fresh* reputational context ("this contract was flagged
  yesterday"), which a statically signed catalog cannot express.

Those cases need a signature over *this* transaction, produced *now*. That is
v1, and v1 needs a key that is online when the user is transacting.

**This is the entire reason delegation exists.** Not a preference — a direct
consequence of needing per-transaction attestation for the long tail.

---

## 3. Why the online key cannot be the root

An online signing service is, by construction, exposed: internet-facing,
operationally reachable, subject to host compromise, supply-chain compromise
and insider access. Assume it will eventually be compromised and design for
the day it is.

If that key is the anchor compiled into firmware, compromise is maximal and
near-unfixable:

- an attacker can forge a clear-sign descriptor for **any** transaction, which
  means presenting an arbitrary drainer as a benign transfer on the trusted
  display — reintroducing exactly the attack clear-signing exists to prevent,
  while *increasing* user confidence;
- it affects **every KeepKey ever shipped**, retroactively;
- the only remedy is a firmware release to every device, gated on users
  choosing to update.

So the root must never be the key that signs per-transaction payloads. It signs
one thing: **delegations**.

A delegated signer bounds the damage to something survivable:

- a compromised delegate is valid for a bounded window (target: **1 month**);
- it can be **revoked** without a firmware release, once the revocation
  mechanism in §5 exists;
- it is **scoped** — v1 blobs only, no authority to issue further delegates,
  optionally chain-limited;
- the root stays offline, on hardware, and is used a handful of times a year.

### What Ledger's public implementation does and does not substantiate

Ledger runs the same cryptographic shape for its live path, and the parts we can
verify from public code are worth copying rather than reinventing:

- an OS-level PKI with a root CA (`LEDGER_ROOT_V3`), certificates loaded at
  runtime through a generic `LOAD_CERTIFICATE` APDU, verified and retained as
  the current PKI key, with chaining via previously validated keys;
- **capability-scoped** certificates. The key usage is part of the certificate
  -- `TX_SIMU_SIGNER`, `CALLDATA`, `TRUSTED_NAME`, `NFT_METADATA`, `COIN_META`,
  `PLUGIN_METADATA`, `SWAP_TEMPLATE`, `EXCHANGE_PAYLOAD`, and more. The
  Ethereum app does not trust a bare "Ledger-approved key"; it asks the PKI
  subsystem for a certificate whose usage is
  `CERTIFICATE_PUBLIC_KEY_USAGE_TX_SIMU_SIGNER` and verifies the report with
  that key;
- **transaction binding on the device**, not merely a signature over a report.

Do NOT write that Ledger "reached the same conclusion" about short-lived
revocable delegates. That is not substantiable from public code. In the open
Speculos implementation the certificate's `TIME_VALIDITY` field is only checked
structurally for length -- it is not compared against a trusted clock -- and
`VALIDITY_INDEX` is not visibly ratcheted against tamper-resistant monotonic
state. Speculos emulates BOLOS behaviour and is not the complete proprietary
Ledger OS, so the correct statement is not "Ledger has no revocation" but:

> **the public device and app code does not demonstrate an offline
> expiry/revocation solution we can copy.**

The honest summary: Ledger validates the *certificate to scoped online signer to
tx-bound payload* portion of this design. It does not hand us an answer to the
offline freshness problem, and nothing can -- see section 5b.

---

## 4. The root lives on a KeepKey

`fsm_msg_clearsign_attestor.h` already implements a KeepKey acting as a signing
authority — `ClearsignAttestorPublicKey` and `ClearsignAttestorSignature`, with
the human-attestation gate documented in the RC21 release-control doc: the
device shows program/instruction labels, the full base58 program ID and the
discriminator on their own confirmations, and every argument's ordinal, ABI
type and label before it will sign.

That gate is what makes a KeepKey a *better* root than a conventional HSM for
this job. A YubiHSM signs whatever the calling process hands it; the operator
sees nothing. A KeepKey attestor makes a human read the declaration on a
trusted screen before the signature exists. For an authority whose entire
purpose is to certify "this is what the transaction means," the signing device
displaying the claim is the point, not a formality.

Consistent with the no-AWS/self-hosted-first stance: the root is hardware we
control, in a location we control, with no cloud KMS anywhere in the trust path.

**Root ceremony (to be specified before Phase 3):** air-gapped, multi-person,
recorded; the root key generated on-device with dice entropy; the public key
published and pinned in firmware; delegation issuance a scheduled ceremony,
not an on-call operation.

---

## 5. The hard problem: the device has no clock and no network

Everything above assumes the device can enforce "valid for one month" and
"revoked." **It cannot, and this is the part an auditor should press hardest
on.**

A KeepKey has no real-time clock and no independent network. It knows only
what the host tells it, and the host is the adversary.

- **Host-supplied time is worthless.** An attacker holding a delegate
  certificate compromised 8 months ago simply tells the device it is still
  within the window.
- **Certificate `not-after` fields are advisory only.** They constrain the
  *issuer's* discipline, not the device's acceptance.

What a clockless device *can* enforce is **ordering**, via a monotonic epoch —
the same primitive the anti-rollback RFC needs for storage:

1. Each delegation carries an integer `epoch`.
2. The device refuses any delegation whose epoch is below its stored minimum.
3. Rotating monthly bumps the epoch. Revoking is bumping early.
4. The device raises its minimum when it sees a validly signed higher epoch,
   and never lowers it.

Delivery of the minimum epoch, worst to best:

| Mechanism | Revocation latency | Cost |
|---|---|---|
| Firmware release pins a new minimum | weeks, gated on user updating | none — no new state |
| Signed epoch-bump message the device ratchets on | minutes, on next connect | needs integrity-protected storage |

**The residual risk that must be stated plainly in any audit:** a device that
never sees a newer epoch keeps accepting an old delegation indefinitely. The
one-month bound is real for a device that connects; it is unbounded for one
that does not. No amount of certificate metadata changes this — only contact
with a newer epoch does.

This also means the epoch counter needs integrity. It cannot live in the public
storage section: RC18 rejected persistent trust anchors there precisely because
that section has **no authenticated integrity against physical flash
modification**, and an attacker who can lower the stored minimum re-enables
every revoked delegate. Options — OTP, an authenticated storage section, or
carrying the minimum in the firmware image itself — are exactly the
anti-rollback epoch design, and this work should not fork from it.

---

## 5b. Revocation is not enforceable. Expiry is.

Revocation needs the device to either **learn** it is revoked (a channel the
adversary controls) or **expire on its own** (a clock it does not have). A
withheld message is indistinguishable from no network, so any design resting on
delivering a negative statement -- CRLs, an on-chain revocation record, a
"this delegate is dead" broadcast -- is unenforceable against the party we
already assume is hostile.

Web PKI reached this conclusion when CRLs failed and OCSP stapling won. Adopt
the same answer: **stop revoking, start expiring.** Credentials are short-lived
and revocation means *stop reissuing*. The device then demands proof of
freshness -- a positive statement it can check -- instead of proof of absence,
which it cannot.

The question becomes: where does a clockless device get freshness it cannot be
lied to about?

### Bitcoin headers as the freshness oracle

Validating a header is one `sha256d` and a target comparison, and forging one
at mainnet difficulty means outspending the network. That makes a header
genuine evidence that work and time have passed, and it beats a KeepKey-signed
epoch bump on the axis that matters:

**the ratchet advances without KeepKey's participation.** Any host, explorer or
full node can push the tip forward. A KeepKey-signed epoch only advances if the
device reaches KeepKey infrastructure -- precisely the channel an attacker
suppresses. Decentralised liveness is the entire benefit.

It also yields real elapsed-time semantics rather than bare ordering: one month
is about 4320 blocks, so `cert.height + 4320 >= accepted_tip` is an expiry
check.

What it does **not** fix:

- **Freezing still works.** Withhold new headers and the device is pinned in the
  past. Bitcoin does not remove this residual; it makes the honest path work
  without us.
- **Integrity-protected monotonic storage is still required** for the accepted
  tip. If flash modification can lower it, every expired delegate returns. This
  does not escape the anti-rollback requirement of section 5 -- it rides it.
- **Track cumulative work, not height.** Height alone is forgeable via a
  low-difficulty fork, and difficulty can legitimately fall 4x per retarget, so
  a hardcoded target is soft. Monotonic cumulative work plus firmware-carried
  checkpoints is the defensible form.
- Require the referenced block to be buried by N blocks so reorgs are moot.

### Bitcoin is an input to the epoch, not a replacement for it

Do not let this become a second ratchet. There is ONE monotonic security epoch,
governing storage/KDF migration, clear-sign delegation, and future firmware
trust changes; Bitcoin is a way to advance freshness underneath it, not a
parallel mechanism. Trusted state is roughly:

    security_epoch = 47
    btc_checkpoint = { cumulative work / checkpoint identity }

and a delegation certificate references `epoch_min`/`epoch_max` alongside its
Bitcoin window.

**Constraint that falls out of unifying them:** advancing the epoch from a
Bitcoin-derived signal must never trigger a destructive action. Clear-sign
expiry may key off the epoch freely, because expiring is fail-safe. Anything
that migrates or erases storage must require a *root-signed* statement and
never a derived advance -- otherwise forged headers stop being a nuisance and
become a way to trigger migrations. Unify the epoch **value**; keep the
**actions** separate.

### Why Bitcoin rather than a root-signed epoch broadcast

A root-signed "epoch 48" update distributed over many channels (API, GitHub,
IPFS, CDN, npm, community mirrors, third-party wallets) is far cheaper than
header validation, and a malicious host suppresses it exactly as easily. So
suppression-resistance is NOT the argument.

Nor is ceremony cost, quite: if delegates are reissued monthly, a monthly root
ceremony happens anyway.

The argument that survives is **vendor independence**. In the broadcast model,
freshness is a liveness dependency on KeepKey the company. If KeepKey is
acquired, goes dark, or simply stops publishing, every outstanding delegate
stays valid forever with no path to expiry. With Bitcoin, delegates expire on
schedule whether or not KeepKey still exists. For a hardware wallet that is a
security property, not an operational convenience, and it is the reason to pay
the ROM.

### Forged headers push the ratchet the safe way

An attacker here wants the tip **low** -- freeze the device so a stolen delegate
stays valid. Mining a forged high-work chain advances the tip and *expires their
own delegate*. A low-difficulty private fork therefore buys the attacker nothing
in this threat model; its worst outcome is DoS by prematurely expiring a
legitimate delegate.

That inverts the usual SPV cost/benefit, where forgery gains the attacker money
and full validation is mandatory. It suggests full consensus validation may be
unnecessary here: a firmware-carried **checkpoint plus a bounded window** --
accept at most M headers extending a known-good point, refresh the checkpoint
each firmware release -- is "verify a short extension of a known point" rather
than "implement Bitcoin", at a fraction of the ROM and attack surface.

This relaxation is valid ONLY while epoch advance is non-destructive, per the
constraint above. If that ever stops holding, the validator requirements go back
up to prev-block linkage, nBits validation, retarget rules, cumulative chainwork
and most-work chain selection. Note also that Bitcoin timestamps are stochastic
and consensus-latitudinal: treat the chain as a decentralised monotonic
freshness source, never as a wall clock.

### Freshness must be signed by the root

If the delegate signs its own freshness proof, a stolen delegate signs one too
and the mechanism is theatre. The proof must come from the offline root, which
collapses the design to its simplest statement:

> The root reissues the delegate monthly, each certificate naming a Bitcoin
> block. The device accepts a certificate only if that block lies within about
> 4320 blocks of the best tip the device has accepted. Revoking is not
> reissuing.

No revocation channel is built, because none would work.

### Threat model, stated for audit

| Case | Outcome |
|---|---|
| Signing server compromised, victim's host honest | Vault advances the tip; the stolen delegate expires within a month. **Bounded and defended.** |
| Server compromised **and** host hostile | Attacker freezes the tip and keeps using the stale delegate indefinitely. **Not defended.** Blast radius is still one delegate's scope -- forging a *new* delegate needs the root. |
| Device that never connects | Frozen, indefinitely trusting. Unavoidable for any offline device. |

An on-chain revocation record (OP_RETURN plus an SPV merkle proof) is tempting
and should be skipped: it is a negative statement again, so an attacker simply
does not supply the proof. Positive freshness dominates it at lower ROM cost.

---

## 6. What the device must verify (the new path)

Today a signer is a bare public key in one of `METADATA_MAX_KEYS` (4) RAM
slots, loaded by `LoadClearsignSigner` under a mandatory on-device confirm, and
**anything it signs shows a warning screen naming the alias**. Only a built-in
key can sign warning-free.

A delegate is runtime-loaded by nature — it changes monthly. So under today's
rules every delegated clear-sign would warn, which defeats the purpose. The
missing capability is not another key slot; it is **chain validation**:

```
built-in root anchor  (compiled into firmware, Phase 2)
        │  verifies
        ▼
delegation certificate  { delegate pubkey, epoch, scope, not-after (advisory) }
        │  verifies
        ▼
per-transaction v1 blob  { tx_hash, decoded values }
```

### Capability scoping, taken from Ledger

A certificate must not say "this key is trusted". It must say what the key is
allowed to assert. Copy the shape of Ledger's key-usage enum:

    CLEARSIGN_SCHEMA     static v2 catalog entries
    CLEARSIGN_DYNAMIC    per-tx v1 interpretation
    TX_RISK              risk / simulation verdict only
    TOKEN_METADATA       symbol + decimals for an address
    TRUSTED_NAME         address -> name resolution
    SWAP_QUOTE / BRIDGE_QUOTE

The point is containment: **a compromised TOKEN_METADATA signer must never be
able to author a dynamic transaction interpretation.** Generic "metadata
authority" gives an attacker the whole surface from any one key.

A certificate therefore carries at minimum:

    delegate_pubkey
    usage        = CLEARSIGN_DYNAMIC
    chain_scope  = { 1, 8453, 42161 }
    can_delegate = false
    epoch_min/epoch_max
    bitcoin_not_before / bitcoin_not_after
    signature    = root(...)

### Transaction binding, taken from Ledger verbatim

A signature over a report is not enough; the device must independently bind the
report to the operation actually in progress. Ledger's Ethereum app refuses a
Transaction Check report unless it matches, and these checks are **mandatory,
not advisory**:

- `report.tx_hash == hash of the transaction being signed`
- `report.from == the sender the DEVICE derived` -- device-derived, never
  host-claimed, or a report issued for another address can be replayed
- `report.chain_id == the actual chain id`
- for EIP-712, additionally bind the domain hash

Without these, malware obtains a benign report for transaction A and attaches
it to malicious transaction B. This is the whole reason v1 commits a `tx_hash`.

### Full acceptance rule

Device-side acceptance requires all of:

1. certificate signature verifies against the built-in anchor;
2. `epoch` within `[epoch_min, epoch_max]` and `>=` stored minimum epoch;
3. Bitcoin window satisfied against the accepted tip;
4. `usage` permits this assertion, and `chain_scope` covers this chain;
5. the delegate is not the anchor, and `can_delegate == false` is honoured;
6. payload signature verifies against the delegate key;
7. every binding check above matches the in-progress operation.

Only a chain terminating at the built-in anchor may render warning-free. A bare
`LoadClearsignSigner` key keeps its warning **forever** — that path is for
developers and self-service, and it should never become the production path.

---

## 7. Phases, with what an auditor should attack

### Phase 0 — today, and what the next release ships

Advanced-flag-only, exactly as RC21 is coded: no production signer pinned;
attestor and runtime signer loading usable only under `AdvancedMode`; loaded
identities RAM-only, cleared by session teardown, `ClearSession`, reboot, and
disabling `AdvancedMode`; metadata is **annotation-only**, with the baseline
raw/unverified review retained after the decoded screens.

Audit targets: that the flag genuinely gates every path; that identities cannot
survive a reboot; that a loaded signer can never suppress the raw review — the
failure that closed fw #322 was a rogue signer **suppressing** the raw-data
screen, and it is the highest-value attack in this phase; OLED truncation on
every attestor confirmation (fw #331 class).

### Phase 1 — v2 static catalog, no hot key

Ship the offline-signed schema catalog and the built-in anchor that verifies
it. Covers the head of the distribution with **zero online key exposure**.

Audit targets: device-side decode correctness against adversarial calldata
(the display is only as good as the decoder); catalog distribution integrity;
that a v2 blob cannot assert values it did not derive; confirm-screen overflow
per value, which is value-dependent — measure, do not read.

### Phase 2 — built-in production anchor

Pin the root public key. Warning-free rendering becomes possible for
anchor-verified metadata.

Audit targets: key ceremony and custody; that phase-1 runtime signers still
warn; that nothing can promote a runtime signer to anchor status.

### Phase 3 — delegation and the per-tx service

Certificate chain validation on device, epoch enforcement, the delegation
ceremony, and the online v1 signer holding only a delegate key.

Audit targets: everything in §5 and §6 — epoch rollback via flash modification;
scope escape; re-delegation; delegate reuse across chains; and the behaviour of
a device that has not connected in a year.

---

## 8. Sequencing constraint

**Phase 3 cannot ship before the anti-rollback security epoch exists.** They
are the same mechanism: a monotonic, integrity-protected minimum that a
clockless device enforces by ordering. Building a second one for clear-sign
would mean two ratchets with two failure modes, and the weaker one sets the
security level.

That is also why the storage-V19 revert matters here. The epoch is now on the
critical path for **both** PIN-KDF hardening and delegated clear-signing, which
should raise its priority above what a storage-only view would suggest.

---

## 9. Open questions

- Epoch/tip storage: OTP, authenticated storage section, or firmware-carried
  minimum? Decides expiry latency and whether flash modification can undo an
  expiry.
- Bitcoin header validation cost in ROM (validation + retarget + checkpoints)
  measured against the reclaimed budget, and whether the btc-only variant
  carries it too.
- Certificate encoding — a compact fixed layout, not X.509. ROM is scarce
  and an ASN.1 parser on a trust boundary is a liability.
- Delegate count: one, or several with disjoint scopes (per chain, per
  partner)? More delegates means smaller blast radius but more chain
  validation and more ROM.
- Does a delegated v1 render truly warning-free, or keep a subtler marker
  ("described by KeepKey, 12 Aug") — recording that a third party asserted the
  meaning, without the alarm of the self-service path?
- Does v2's reach make v1 rare enough that the per-tx service is
  opt-in rather than default?
