# Clear-sign signing authority: why delegation, and the road to it

Status: roadmap for audit. Written to be read by an auditor deciding what to
attack, and by an implementer deciding what to build next.

Companion docs: `7.15.0-rc21-clearsign-release-control.md` (what ships today),
`anti-rollback-security-epoch-rfc.md` (the epoch mechanism this depends on).

The governing sentence for this work:

> **Bitcoin-derived evidence may only reduce clear-sign authority; metadata
> failure may never silently reduce the level of review required to produce a
> signature.**

---

## 0. Blocking decisions — read this before costing anything

An earlier reading of this document concluded that the architecture was settled
and only ROM measurement remained open. **That is false, and it is the most
expensive misreading available here.** Eight foundations are undecided, and six
of them change *what would be measured*: the ratchet substrate does not exist in
the form this document assumes, the authority model names a class rather than a
key, the updater invariant it depends on is contradicted by the shipping
bootloader, and the certificate schema is inconsistent between §5b and §6.
Measuring a validator against an undecided substrate produces a number with no
referent.

ROM measurement comes **last**, after the seven rows above it are settled.

| # | Sev | Blocker | Where resolved | Status |
|---|---|---|---|---|
| 2 | High | Ratchet substrate. The four-field `SecurityRatchets` facility does not exist; the anti-rollback RFC defines a single 256-step unary OTP counter that cannot represent a block height. | §5b *Substrate* | Shape specified here; four parameters need an owner |
| 3 | High | Authority model. "ROOT SIGNATURE" is an authority class, not a key. | §5b *Authority* | Requirement specified; key/quorum inventory needed |
| 4 | High | Updater invariant. The bootloader erases the whole application partition before it has seen the candidate. | §8 *Updater invariant* | Three options stated; needs a decision |
| 8 | Med | Certificate schema conflicts across the document; the acceptance rule tests an epoch range that is never defined. | §6 *Canonical certificate* | Resolved here |
| 1 | High | Cross-variant preservation. "absent or inert" in bitcoin-only resurrects expired delegates on the round trip back to full. | §5b *Variant scope* | Resolved here |
| 6 | High | Proof-session inputs are host-supplied. | §5b *What the device validates* | Resolved here |
| 7 | High | Blind-sign policy is security-critical persistent state with no integrity protection. | §5b *Policy integrity* | Requirement specified; storage medium follows #2 |
| 5 | High | Single-root custody: one compromise yields globally warning-free false interpretations until firmware replacement. | §4 *Custody* | **Owner decision. Not decidable in this document.** |

Suggested order — substrate (2) → authority (3) → updater invariant (4) →
certificate transcript (8) → cross-variant preservation (1) → proof-session
inputs (6) → policy integrity (7) → custody (5). Each one changes the shape of
the next.

Still undecided and previously flagged: blind-sign policy stickiness (§5b,
*Four things the policy model must get right*, item 4).

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

The precise wording to use, because it is the hardest to shoot down:

> Ledger's public implementation demonstrates the same underlying PKI pattern:
> dynamic transaction assessments are signed by runtime-loaded,
> capability-scoped keys whose certificates are validated through Ledger's PKI,
> rather than treating a generic online signer as unrestricted trust. The
> public Speculos implementation exposes certificate validity fields but does
> not demonstrate an offline revocation/freshness mechanism we can rely on as
> precedent; Speculos models BOLOS behaviour but is not the complete
> proprietary BOLOS implementation.

So Ledger validates the *certificate -> scoped online signer -> tx-bound
payload* portion of this design. It does not hand us an answer to the offline
freshness problem, and nothing can -- see section 5b.

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

### Custody — BLOCKER 5. Owner decision, and it is not decidable here

"Air-gapped, multi-person, recorded; the root key generated on-device with dice
entropy" describes a *ceremony*. It does not describe **custody**, and the
distinction is the blocker: as written, this is one dice-generated key on one
KeepKey. A single root means a single compromise, and the consequence is worse
than for any other key in the system, because §6 grants exactly one privilege to
a root-verified chain — **warning-free rendering**. One stolen root produces
globally warning-free false interpretations on every device that trusts it, and
the only remedy is a firmware release that every user must choose to install.
That is the failure mode §3 opens this document by rejecting for the online key,
reappearing one level up.

The requirement is **N-of-M across independent devices and locations**, so that
no single device seizure, no single premises compromise and no single insider
produces a signature. Four things have to be specified alongside it, and each
one is a way for the scheme to fail quietly if left implicit:

- **Rotation.** How a root is retired on schedule rather than only in crisis.
- **Backup.** How M is reconstituted after a lost device, without the backup
  itself becoming a 1-of-1 path around the quorum.
- **Disaster recovery.** What happens when quorum becomes unreachable —
  bearing in mind the fail-closed story in *Why Bitcoin rather than a root-signed
  epoch broadcast*: delegates age out, static and device-native signing continue.
  Losing the root must degrade to that, not to a rushed single-key restore.
- **Overlapping-anchor transition.** Firmware pins the root, so rotating it
  means shipping firmware that trusts old and new simultaneously for a window
  long enough that devices which update late are never stranded. Without this,
  rotation is indistinguishable from a compromise-forced emergency.

**These parameters commit the organisation to an operational programme, so they
are not decided in this document.** What is decided here is that Phase 2 must
not pin a delegation root before they are, because pinning is the irreversible
step: a root in shipped firmware cannot be un-shipped.

Note the sequencing relief from §6 *Two roots, not one*: the **schema** root
signs the offline v2 catalog and grants no per-transaction authority, so Phase 1
can proceed on a lighter custody model while this decision is outstanding. Only
the **delegation** root needs the full programme above.

**Ceremony (still required, and downstream of the above):** air-gapped,
multi-person, recorded; keys generated on-device with dice entropy; public keys
published and pinned in firmware; delegation issuance a scheduled ceremony, not
an on-call operation; the Bitcoin anchor chosen at issuance must be recent, or
the validity window opens in the past.

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

## 5b. Revocation cannot be forced onto an offline device

Revocation needs the device to either **learn** it is revoked (a channel the
adversary controls) or **expire on its own** (a clock it does not have). A
withheld message is indistinguishable from no network, so any design resting on
delivering a negative statement -- a revocation list, an on-chain revocation
record, a "this delegate is dead" broadcast -- is unenforceable against the
party we already assume is hostile.

The precise claim, which is weaker than "expiry is enforceable" and is the one
that survives audit:

> **Revocation cannot be forced onto an offline device. Freshness-gated expiry
> becomes enforceable once the device receives sufficient authenticated
> evidence of progress.**

So: credentials are short-lived, revoking means *stop reissuing*, and the
device demands proof of freshness -- a positive statement it can check --
rather than proof of non-revocation, which it cannot. Bitcoin improves **who
can supply** that evidence, not **whether an adversarial host can suppress it**.

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

### The invariant

> **Bitcoin does not provide revocation to an offline device. It provides
> vendor-independent positive evidence of elapsed work. The device uses that
> evidence only to REDUCE clear-signing authority -- never to grant authority,
> and never to trigger a destructive state transition.**

That asymmetry is the point. It turns any parser or work-accounting mistake
from a potential key-management failure into, at worst, a clear-sign
availability failure.

### Substrate — BLOCKER 2. The facility this design assumes does not exist

Do NOT collapse everything into one global integer. The intent is **one**
integrity-protected monotonic state facility -- one implementation, one atomic
update path, one set of anti-rollback guarantees, one audit surface -- holding
domain-separated counters:

    SecurityRatchets {
        firmware_epoch;
        storage_epoch;
        clearsign_epoch;
        clearsign_freshness;   /* Bitcoin-derived */
    }

**This is a requirement, not a component that exists, and the mechanism the
anti-rollback RFC actually specifies cannot provide it.** Earlier text here
said the options "are exactly the anti-rollback epoch design, and this work
should not fork from it". The first half is wrong. `anti-rollback-security-
epoch-rfc.md` reserves *one* audited OTP block as a **256-step unary counter**:
epoch `N` is the length of the programmed prefix, and there are 256 advances in
the device's lifetime, total. Four consequences, each of which has to be
answered before any of this is buildable:

- **A unary OTP counter cannot hold a block height.** `clearsign_freshness`
  tracks a Bitcoin tip in the hundreds of thousands. It does not fit in 256
  unary steps and never will. `firmware_epoch` and `clearsign_freshness` are
  not the same kind of value and cannot share a representation.
- **Authenticated flash prevents forgery, not restoration.** An attacker who
  can rewrite flash and replay an *authenticated older snapshot* of the ratchet
  block has rolled the ratchet back without forging anything. Monotonicity needs
  an anti-replay binding to something the attacker cannot restore -- OTP state,
  or a counter in a region the attacker cannot rewrite -- not merely a MAC.
- **Committing on every `Finish` wears flash.** The protocol below advances
  freshness once per accepted proof. At monthly reissuance that is modest; under
  a host that submits proofs continuously it is not, and the wear budget has to
  be a stated number rather than an assumption.
- **A hostile host can force advances with honest chains.** It does not need to
  forge anything: it replays genuine, ever-longer header chains from the real
  network to drive one persistent advance per proof. Rate limiting is therefore
  not an optimisation (see *What the device validates*, below).

**Required shape:** OTP-backed coarse generation or checkpoint -- cheap,
irreversible, few lifetime advances -- carrying an authenticated journal in
rewritable storage for the fine-grained values, where the journal is bound to
the current OTP generation so that restoring a journal from a previous
generation is detectable and rejected.

Four parameters must be decided with that shape, and none is a detail:

1. **Rollback tolerance.** How far may fine-grained state legitimately regress
   within one generation (power loss, torn write) before the device treats it as
   an attack?
2. **Checkpoint granularity.** How many block heights per OTP generation? This
   sets both the wear budget and the worst-case rollback window.
3. **Wear budget.** Erase cycles per year at the assumed proof rate, against the
   part's endurance, with the rate limit that keeps it there.
4. **Power-loss state machine.** Exactly which intermediate states are
   reachable, and what each one means at the next boot.

Until these are answered, "measure the validator's ROM" has no referent: the
journal, the atomic update path and the generation binding are all unmeasured
and all mandatory.

### Authority — BLOCKER 3. "ROOT SIGNATURE" is a class, not a key

The separation this design depends on is:

    <firmware root>   -> firmware_epoch
    <storage root>    -> storage_epoch
    <clearsign root>  -> clearsign_epoch
    BITCOIN WORK      -> clearsign_freshness  (and nothing else, ever)

Written as "ROOT SIGNATURE -> firmware_epoch, storage_epoch, clearsign_epoch"
this reads as one key with authority over all three, which is precisely the
concentration §3 argues against -- and it would let a compromised clear-sign
root revoke firmware or migrate storage. **Name which root governs which
ratchet, and make the separation cryptographic rather than notational:**

- **distinct keys or quorums per authority.** Not one key signing
  differently-typed messages; different keys. Sharing a key makes the
  domain tag the only thing standing between a clear-sign compromise and the
  firmware floor.
- **domain-tagged signed transcripts.** Every signed object commits to its
  purpose, so a message minted for one authority cannot be reinterpreted as
  another. The tag is inside the signed bytes, at a fixed offset, before any
  variable-length field.
- **binding to network, model, variant, format version and purpose**, so a
  certificate for one deployment cannot be replayed into another.
- **negative tests, as release gates:** cross-protocol replay (a clear-sign
  certificate offered as a firmware epoch bump, and the reverse), type confusion
  between certificate and proof-session messages, and a delegate certificate
  presented where a root object is expected.

The clear-sign root must never gain authority over firmware or storage epochs.
That is the property the whole domain separation exists to deliver, and it is
structural only once the keys differ.

With that in place, Bitcoin-derived state can never cause a KDF migration, a
storage rewrite, a seed wipe, a firmware trust change, or a PIN behaviour
change, no matter how far it is pushed or how wrong the validator is -- which
is stronger than "unify the epoch and separate the actions", a rule that relies
on discipline at every call site.

### What the device actually validates

The delegate certificate carries its own Bitcoin anchor, so the trusted point
is re-established at every issuance and never goes stale between firmware
releases. **The certificate layout is defined once, in §6 *Canonical
certificate*** -- the fields used here are `btc_anchor_hash`,
`btc_anchor_height`, `expiry_height_delta` and `expiry_min_work`, all covered by
the delegation root's signature.

The host then supplies 80-byte headers extending the certificate's anchor, and
the device checks only:

- `prev_hash` links each header to the last;
- `sha256d(header) <= target` encoded by that header's `nBits`;
- the target is within sane bounds;
- header count;
- accumulated work, derived from each header's claimed target.

**Why this is sound without consensus rules:** work is computed from the
*claimed* target and the hash is verified to *meet* that target, so claimed
work is always backed by demonstrated work. Cheap `nBits` yields trivial
accumulated work and fails `W`; hard `nBits` requires genuinely finding those
hashes. `prev_hash` linkage from a root-signed anchor prevents splicing real
headers from elsewhere in the chain. No retarget validation, no median-time-
past, no version bits, no chain selection: the question is not "is this
Bitcoin's canonical chain" but "does a chain descending from my trusted anchor
contain enough genuine SHA-256 work".

Expiry requires `height_delta >= 4320` **and** `work >= W`. The AND matters:
height alone is forgeable cheaply, so an OR would let an attacker expire
legitimate delegates for free.

Bitcoin timestamps are stochastic and consensus-latitudinal. Treat the chain as
a decentralised monotonic freshness source, never as a wall clock.

### Forged forward progress: bounded to denial of service

An attacker cannot preserve a stolen delegate by forging progress -- advancing
the tip expires their own credential. But the earlier claim that "forged
headers only help us" was wrong:

> Forged forward progress cannot extend the attacker's authorization. Its
> security consequence is bounded to **denial of service**, provided
> Bitcoin-derived state has no authority over destructive or key-management
> operations.

The DoS is real: fabricated far-future freshness is monotonic, so legitimate
certificates anchored near the true network height would read as ancient for
years -- a permanent clear-sign outage. Requiring genuine accumulated work
makes that expensive in proportion to how far the attacker pushes, and a cap on
advance-per-session plus sane target bounds keeps it bounded.

### Metadata absence is metadata failure

Downgrade-by-expiry has a companion that is *easier* to exploit, and it is the
one that blocks Phase 3 until closed. If a failed validation lands the user on
the ordinary raw-review path, an attacker does not need to submit an expired
certificate at all -- **they simply omit the metadata**. No certificate, no
descriptor, no validation failure, and the device takes the normal blind path.

So this cannot be expressed as "if metadata is present, validate it". It
requires a device-enforced signing policy:

    typedef enum {
        SIGN_POLICY_DEVICE_PARSED,                    /* device renders it fully itself */
        SIGN_POLICY_VERIFIED_INTERPRETATION_REQUIRED, /* external attestation mandatory */
        SIGN_POLICY_EXPLICIT_BLIND_SIGNING,           /* separately enabled on device */
    } signing_policy_t;

Under `VERIFIED_INTERPRETATION_REQUIRED`, every one of these is the **same
terminal condition** -- explicit error, no signing confirmation, no signature:

    missing certificate        wrong capability
    expired certificate        tx-binding mismatch
    invalid certificate        malformed interpretation

**The invariant:**

> Raw review is additive, not a fallback. When the active device policy
> requires verified interpretation, missing, malformed, invalid, expired,
> wrongly scoped or transaction-mismatched metadata terminates the signing
> session without producing a signature. A host cannot enter blind signing by
> omitting metadata or by causing validation to fail. Blind signing is
> reachable only through a separately enabled on-device policy and begins a
> new, explicitly unverified signing flow.

Two distinct protections, and Phase 0 establishes only the first:

1. successful clear-signing cannot **suppress** the underlying raw review;
2. failed clear-signing cannot **fall through** to an otherwise normal flow.

The second must be its own testable state-machine invariant.

No inline "Continue anyway" on the expiry screen. The device returns a failure.
A user determined to blind-sign must leave the flow, enable the policy, and
start again -- otherwise the error becomes one more click-through warning.

### Four things the policy model must get right

**1. The policy is device state; the host must never select it.** If the
transaction request can name its own policy, the host simply always names
`EXPLICIT_BLIND_SIGNING` and the entire mechanism evaporates. Policy is
persisted device configuration, changed only through an on-device flow, and
never a field in a signing request. The selection channel is itself a trust
boundary.

**1b. BLOCKER 7 — and "persisted device configuration" is not yet a safe
place.** The policy is security-critical persistent state, and no integrity
protection has been specified for it. Today's public storage section has **no
authenticated integrity against physical flash modification** -- that is exactly
why RC18 retired the V18 clear-sign identity records. A policy byte stored there
means an attacker with physical access flips one bit and enables the downgrade
policy directly, without touching a certificate, a delegate or a proof. Every
protection in this section then evaporates, and it evaporates *silently*,
because the device believes the user chose it.

Two acceptable models, and the choice follows the substrate decision (#2):

- **Authenticated storage.** The policy lives in the integrity-protected
  facility, so modification is detected. This is the natural home if that
  facility exists; it is another reason #2 comes first.
- **Session-scoped with physical confirmation.** Blind signing is never
  persisted at all: it is enabled per session by an on-device confirmation and
  cleared at teardown. This needs no authenticated storage, at the cost of
  nagging -- and it interacts directly with the stickiness question in item 4
  below, which it would answer by construction.

Three behaviours must be specified either way, because each is a way for the
protection to end up off without anyone deciding:

- **after a device reset** the policy returns to the secure default, never to
  whatever was there before;
- **after a variant change** (full -> bitcoin-only -> full) the policy is either
  preserved authentically or reset to the secure default; it must not be
  inherited from uninterpreted bytes;
- **on corrupted or unreadable policy state** the device selects the strict
  policy, not the permissive one. Fail closed here for the same reason the
  signing path fails closed: an attacker who can corrupt the field must not gain
  anything by doing so.

**2. The policy is per transaction class, not global.** A plain ETH transfer
with empty calldata, or an ERC-20 `transfer` the device decodes with its own
built-in token table, needs no external attestation -- there is nothing to
attest. If `VERIFIED_INTERPRETATION_REQUIRED` blocks those, it blocks ordinary
sends and users will disable it immediately. The device must first classify
what it can render **itself**, and the policy governs only the residue it
cannot. That classification must be derived from the transaction the device is
signing, never from a host-supplied hint.

**3. Rollout ordering: a policy users are forced to disable is worse than no
policy.** Defaulting to `VERIFIED_INTERPRETATION_REQUIRED` before catalog
coverage is high produces a wave of legitimate transactions that simply fail,
and the support answer becomes "turn on blind signing" -- which users then
leave on forever. Coverage first, default-on second. Shipping the default early
converts a security feature into a permanent opt-out.

**4. Open question: should the blind-sign policy be sticky?** Permanent
enablement means the first support incident disables the protection for that
user for good, which is how security settings decay. Session-scoped or
time-limited enablement resists decay but nags. Not decided here; decide it
before Phase 3 ships, because retrofitting stickiness changes the threat model.

### Downgrade-by-expiry must fail closed

A consequence of "Bitcoin may only reduce authority" that needs stating,
because reducing authority is not automatically safe: if expiring the
clear-sign path causes the device to fall back to a flow that *looks* normal --
raw hex the user approves out of habit -- then an attacker who can force
expiry has downgraded the user's protection rather than denied service.

Expiry must fail **closed** and **visibly**: no clear-sign rendering, and a
screen that says the interpretation is unavailable and unverified. It must
never resemble a successful signing flow. Phase 0's annotation-only shape, with
the raw review always retained, is already the correct behaviour here and must
survive into later phases.

### Two complementary revocation paths

| | Mechanism | Latency | Requires |
|---|---|---|---|
| Emergency invalidation | root signs `clearsign_epoch >= 48` | immediate **on receipt** | KeepKey alive to issue it |
| Natural | Bitcoin freshness crosses the certificate's expiry threshold | up to the window | nothing but Bitcoin |

Together they cover both failure modes: a compromise discovered while KeepKey
operates is killed immediately, and a credential outlives KeepKey's existence
only until it ages out. A hostile host can suppress both -- the unavoidable
offline-device boundary from section 5b.

### Why Bitcoin rather than a root-signed epoch broadcast

A root-signed "epoch 48" distributed over many channels (API, GitHub, IPFS,
CDN, npm, community mirrors, third-party wallets) is far cheaper than header
validation, and a malicious host suppresses it exactly as easily. So
suppression-resistance is NOT the argument, and ceremony cost barely is --
monthly delegate reissuance implies a monthly ceremony anyway.

The argument that survives is **vendor independence**, and the resulting
failure mode is fail-closed:

    KeepKey disappears
            v
    no new delegate certificates
            v
    dynamic clear-sign service eventually stops
            v
    existing delegates nevertheless age out
            v
    static/device-native signing still works

Under a broadcast model, freshness is a liveness dependency on KeepKey
continuing to publish: if the company is acquired or goes dark, every
outstanding delegate stays valid forever with no path to expiry. That is the
reason to pay the ROM.

### Variant scope: none of this ships in bitcoin-only

Bitcoin-only firmware does not need clear-signing and must not carry any of it.
A Bitcoin transaction is inputs, outputs, addresses and amounts, all of which
the device already renders natively and completely. There is no opaque calldata
to interpret, so there is nothing for a signing authority to attest to.

This is already the case in the build and is not a change: `signed_metadata.c`
sits inside `if(NOT ${KK_BITCOIN_ONLY})` in `lib/firmware/CMakeLists.txt`, and
the attestor message handlers are behind `#if !BITCOIN_ONLY` in `fsm.c`.

**The domain-separated ratchet design is what makes this exclusion possible.**
The substrate -- the integrity-protected monotonic store -- ships in both
variants, because `firmware_epoch` and `storage_epoch` apply to bitcoin-only
just as much. Only `clearsign_freshness` and the header validator are
full-variant. Under a single global epoch that Bitcoin work could advance,
bitcoin-only would have to carry header validation just to stay coherent with
an epoch it shares with storage anti-rollback. Domain separation means the
variant simply has no field that Bitcoin has authority over, and therefore no
reason to validate a header.

Two things follow that are easy to get backwards:

- **The Bitcoin header validator ships in the multi-chain firmware and NOT in
  the bitcoin-only firmware.** Correct, and it reads as backwards; expect to
  explain it more than once.
- **The ROM cost concentrates on the tighter variant.** Excluding bitcoin-only
  does not split the budget, it loads all of it onto full -- which is the
  build that was down to ~572 bytes free before the 34 KB reclaim in fw #339
  and #340. Bitcoin-only has headroom precisely because the coins are stripped,
  and none of that headroom helps here.

**Memory availability is not an inclusion criterion on a trust boundary.**
Bitcoin-only has hundreds of kilobytes free, and that is not a reason to put a
remotely reachable header parser, a proof-session state machine, compact-target
arithmetic, persistent ratchet update paths and extra protocol surface on a
device that has no delegate whose authority needs expiring. It would also
create a second variant to fuzz and audit for no benefit.

    shared across variants:
        integrity-protected ratchet substrate
        domain-separated ratchet definitions
        generic atomic monotonic update machinery

    full / multi-chain only:
        delegation certificates
        dynamic clear-sign payloads
        Bitcoin freshness validator
        clearsign_freshness updates

    bitcoin-only retail:
        no delegation validator
        clearsign_freshness PRESERVED OPAQUELY -- carried, never interpreted,
        never advanced, never lowered

    root-attestor special firmware:
        may optionally include validator tooling
        is NOT the retail bitcoin-only image

**BLOCKER 1 — "absent or inert" was wrong, and it contradicted the shared
substrate above.** If bitcoin-only firmware drops or zeroes
`clearsign_freshness`, the round trip

    full  ->  bitcoin-only  ->  full

resets freshness to nothing, and **every delegate the device had already aged
out becomes valid again.** Reflashing is a host-initiated operation, so this is
a downgrade an attacker performs, not an accident. It is also internally
inconsistent: the substrate is declared shared across variants, and a shared
substrate whose fields one variant discards is not shared.

The transition rule has to be explicit, and there are exactly two defensible
forms:

1. **Opaque preservation (preferred).** Bitcoin-only carries the field as
   authenticated bytes inside the same ratchet facility, with no code that can
   advance or lower it. It has no validator, so it has no way to interpret the
   value -- which is the point: it cannot be tricked into moving something it
   cannot read. Costs the field's storage and its integrity binding, nothing
   more; specifically it does *not* pull the header validator into the variant.
2. **Full firmware refuses clear-signing when the preserved state is missing.**
   If preservation is not implemented, a device returning from bitcoin-only has
   no freshness, and full firmware must treat "no freshness state" as
   *unexpired-cannot-be-established* -- clear-signing off until a fresh proof
   arrives -- rather than as freshness zero, which would accept everything.

What is NOT acceptable is leaving it unstated, because the default behaviour of
a missing field is option 2's failure mode with option 1's assumption: the
field reads as zero and every certificate looks fresh.

The root-signing KeepKey does not itself need to validate a header chain: its
ceremony establishes the recent anchor through independent tooling and human
verification. A special attestor image may carry the validator later; that is a
different threat model from putting it on every bitcoin-only customer device.

Revisit only if bitcoin-only ever wants a capability that needs an external
attestation -- `TRUSTED_NAME` for Bitcoin addresses is the plausible one. That
is not a requirement today and should not be built speculatively; this
paragraph exists so the exclusion stays a decision rather than becoming an
oversight.

### Validator engineering: budget, protocol, and what gets persisted

Engineering estimates, not measurements. SHA-256 and the multiprecision
machinery are already linked, so this is not a new crypto library.

| Component | Likely incremental ROM |
|---|---|
| Header parsing, linkage, bounds | 1-2 KB |
| Compact-target decode + PoW compare | 1-2 KB |
| Exact 256-bit block work + accumulation | 2-5 KB |
| Proof-session FSM, protocol, failures | 1.5-3 KB |
| **Total** | **5-10 KB** |

Against roughly 35 KB of headroom in the current full build this is plausible,
but it needs an exact map-diff spike against the eventual Phase 3 base before
anyone commits.

**Hard acceptance criteria, not optimisations** -- this repo has a 16 KiB
reserve gate and a history of boot faults from large static and automatic
buffers:

- persistent/static validator state: **<= 512 B**
- additional maximum stack frame: **<= 256 B**
- whole-proof buffering: **0 B**

**BLOCKER 6 — every proof constraint comes from the certificate, never from the
host.** An earlier draft of this protocol had `BitcoinFreshnessBegin` carry the
anchor hash, anchor height and thresholds. Those are exactly the values that
decide whether a proof succeeds; supplying them from the host means the host
picks an anchor it can cheaply extend and thresholds it can trivially meet, and
the validator then correctly verifies a proof that means nothing. The host may
**reference** a certificate the device has already verified, and stream headers.
Nothing else:

    BitcoinFreshnessBegin   cert_hash            (selects an ALREADY-VERIFIED cert)
    BitcoinFreshnessChunk   sequence, concatenated 80-byte headers
    BitcoinFreshnessFinish  expected total header count

    anchor hash, anchor height, expiry_height_delta and expiry_min_work are
    read from the referenced certificate's ROOT-SIGNED bytes. If no verified
    certificate matches cert_hash, the session does not start.

**Rate-limit persistent advances.** A hostile host does not have to forge
anything to hammer the ratchet: it replays genuine header chains from the real
network, each longer than the last, and drives one persistent advance per proof.
Either cap advances per session and per unit of device uptime, or require a
minimum checkpoint delta -- the advance must be large enough to be worth a write
-- so that the number of flash commits per year is bounded by design rather than
by host politeness. This is the wear budget from *Substrate* above, enforced.

    for each 80-byte header:
        require prev_hash == running_tip
        decode and validate nBits
        require sha256d(header) <= target
        accumulate block work
        running_tip = header_hash; count++

A chunk of 4-16 headers avoids 4320 USB round trips without materialising the
proof; the chunk buffer is transient and belongs to the existing transport
machinery, not to validator state. On any failure: wipe pending context, return
Failure, **do not alter persistent freshness**. On disconnect, cancel, reboot or
power loss: discard pending, committed freshness unchanged. Only `Finish`,
after both thresholds pass, atomically advances the ratchet -- which also keeps
flash wear and power-loss ambiguity out of the design.

**Persist height only; work is a witness.** After a proof passes both
thresholds, commit:

    clearsign_freshness_height =
        max(clearsign_freshness_height, cert.anchor_height + accepted_headers)

and persist neither the running tip, nor per-anchor accumulated work, nor
historical anchors. This is sound because every proof starts from a
**root-signed** anchor: work proves the claimed height advance was expensive,
and the resulting monotonic height alone then evaluates *any* certificate's
expiry (`freshness_height >= cert.anchor_height + cert.expiry_height_delta`).
It also sidesteps the incoherent comparison of "work since anchor A" against
"work since anchor B". The integrity-protected field stays a single monotonic
height.

**Compact-target arithmetic** is the ROM and runtime wildcard:
`floor(2^256 / (target + 1))`. Cache `last_nBits -> last_target ->
last_block_work`; an honest window repeats nBits for long stretches, so the
expensive path runs a handful of times. A malicious host can vary nBits every
header and force it 4320 times -- bounded session-level compute DoS, not an
authorization bypass.

The decoder must explicitly reject: zero target, negative compact target,
overflowed target, target above `powLimit`, non-canonical compact encoding,
hash/target endian confusion, and work-accumulator overflow.

**The endian case needs a dedicated golden test** with a real mainnet header:
Bitcoin's serialised hash conventions make it easy to compare byte-reversed
values and build a validator that accepts nearly everything or nearly nothing,
and both failure modes look "working" in a happy-path test. (We already carry
the genesis hash in our own chain identifiers, `bip122:000000000019d6689c...`,
so at least one vector is independently checkable.)

**ROM fallback if exact work is too expensive:** have the certificate sign
`maximum_permitted_target` and `minimum_header_count`, and require per header
`hash <= header.target <= cert.maximum_permitted_target`. N headers then prove a
conservative minimum of work with no division and no 256-bit accumulator.
Smaller, but it handles hashrate collapse worse: if real difficulty falls below
the permitted floor, expiry stops entirely, whereas exact work merely slows.
Prototype exact work first; keep the target-floor construction as the fallback.

### Hashrate drift is correctly asymmetric

| Condition | Effect |
|---|---|
| Hashrate rises | W may arrive early; H prevents premature expiry |
| Hashrate falls | H may arrive before W; expiry delayed |
| Fake low-difficulty chain | H may advance cheaply; W does not |
| Short high-difficulty chain | W may advance; H does not |

Both unusual network conditions and implementation conservatism can only
*extend* credential life; neither buys early expiry. State the target lifetime
as issuance policy, never as a guarantee: *"approximately one month under the
work and block-production conditions assumed at issuance; severe hashrate loss
extends the validity interval."*

### Implementation constraints worth pricing early

- **Streaming, O(1) state.** 4320 headers is ~346 KB. It cannot be buffered on
  this device: headers must be validated and folded incrementally, keeping only
  the running tip and accumulated work.
- **Anchor recency at issuance.** The root ceremony must anchor to a recent
  block, or the validity window opens in the past.
- **Hashrate drift.** With AND-semantics, a sustained hashrate collapse makes
  work accumulate slowly and extends credential life. Bitcoin has never seen a
  sustained collapse of the magnitude that would matter, but the direction of
  the error should be recorded rather than discovered.

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

### Canonical certificate — BLOCKER 8. One layout, defined here

This document previously described the certificate twice, with different
fields: §5b named `btc_anchor_hash` / `btc_anchor_height` /
`expiry_height_delta` / `expiry_min_work`, while this section named
`bitcoin_not_before` / `bitcoin_not_after`. The acceptance rule then tested
"`epoch` within `[epoch_min, epoch_max]`" against a scalar `epoch` field that
appears in neither list. Three descriptions of one signed object is three
implementations, and on a trust boundary that is a vulnerability rather than an
inconsistency: the verifier and the issuer disagree about which bytes are
covered.

**The canonical layout — a compact fixed encoding, not X.509 (ROM is scarce and
an ASN.1 parser on a trust boundary is a liability):**

    offset  field                    notes
    ------  -----------------------  ---------------------------------------
      0     format_version           refuse anything not exactly known
      2     domain_tag               "KKCLEARSIGN-DELEGATE-V1"; fixed offset,
                                     before any variable-length field (§5b
                                     Authority)
      *     network_id               mainnet / testnet deployment binding
      *     model_binding            device model class
      *     variant_binding          full only; bitcoin-only holds no delegate
      *     delegate_pubkey          33-byte compressed secp256k1
      *     usage                    CLEARSIGN_DYNAMIC, TOKEN_METADATA, ...
      *     chain_scope              EVM chain ids this delegate may assert on
      *     can_delegate             MUST be false for every delegate issued
      *     cert_epoch               scalar. Revocation ordering. Accepted only
                                     if >= the device's stored clearsign_epoch
      *     btc_anchor_hash          root-chosen, recent at issuance
      *     btc_anchor_height        height of that anchor
      *     expiry_height_delta      e.g. 4320 (~1 month)
      *     expiry_min_work          W; expiry needs delta AND work
      *     root_signature           by the DELEGATION root (see below)

`bitcoin_not_before` / `bitcoin_not_after` are **removed**: they expressed the
same constraint as anchor + delta, in a form that invites treating them as wall
clock. `epoch_min` / `epoch_max` are **removed**: a certificate has one epoch.
A range described nothing the device could check, which is why the acceptance
rule tested a field that did not exist.

### Two roots, not one — and this is what Phase 1 vs Phase 2 was confusing

Phase 1 ships "the built-in anchor that verifies the catalog" and Phase 2 says
"pin the root public key". Both are true because they are **different keys**,
and saying "the anchor" for both is what made the phases look contradictory:

| Root | Signs | Pinned in | May advance |
|---|---|---|---|
| **Schema root** | v2 static catalog entries. Offline, no hot key downstream. | Phase 1 firmware | nothing |
| **Delegation root** | delegate certificates for the per-tx v1 service. | Phase 2 firmware | `clearsign_epoch` |

They are separate keys with separate ceremonies and separate compromise stories.
A compromised schema root can mis-describe catalogued contracts; a compromised
delegation root can mint delegates for anything. Neither has any authority over
`firmware_epoch` or `storage_epoch` (§5b *Authority*). Phase 1 can therefore ship
its anchor without waiting on the custody decision for the delegation root,
which is the sequencing benefit of splitting them.

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

1. certificate signature verifies against the built-in **delegation root**, and
   `format_version`, `domain_tag`, `network_id`, `model_binding` and
   `variant_binding` all match this device and this object type;
2. `cert_epoch >=` the device's stored `clearsign_epoch` minimum;
3. Bitcoin window satisfied against the accepted tip —
   `clearsign_freshness_height < cert.btc_anchor_height +
   cert.expiry_height_delta` — with freshness read as *established*, not
   defaulted (§5b *Variant scope*, option 2);
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

Ship the offline-signed schema catalog and the built-in **schema root** that
verifies it (§6 *Two roots, not one*). Covers the head of the distribution with
**zero online key exposure**, and does not wait on the delegation-root custody
decision, because a schema root grants no per-transaction authority.

Audit targets: device-side decode correctness against adversarial calldata
(the display is only as good as the decoder); catalog distribution integrity;
that a v2 blob cannot assert values it did not derive; confirm-screen overflow
per value, which is value-dependent — measure, do not read.

### Phase 2 — built-in production delegation root

Pin the **delegation** root public key, distinct from Phase 1's schema root.
Warning-free rendering becomes possible for chains terminating at it.

**Gated on BLOCKER 5.** Pinning is irreversible — a root in shipped firmware
cannot be un-shipped — so the custody programme in §4 must be decided first.

Audit targets: key ceremony and custody; that phase-1 runtime signers still
warn; that nothing can promote a runtime signer to anchor status; that the
schema root cannot verify a delegate certificate, or the delegation root a
catalog entry (§5b *Authority*, cross-protocol replay).

### Phase 3 — delegation and the per-tx service

Certificate chain validation on device, epoch enforcement, the delegation
ceremony, and the online v1 signer holding only a delegate key.

Audit targets: everything in sections 5, 5b and 6. **Release gates, not
suggestions** — and the first is the single most important test in the
programme:

    verified interpretation required + metadata OMITTED   -> no signature

    expired cert                        -> no signature
    invalid cert signature              -> no signature
    wrong certificate capability        -> no signature
    delegate attempting re-delegation   -> no signature
    tx hash mismatch                    -> no signature
    device-derived sender mismatch      -> no signature
    chain id mismatch                   -> no signature
    EIP-712 domain mismatch             -> no signature

    proof height met, work short        -> no ratchet advance
    proof work met, height short        -> no ratchet advance
    bad prev_hash midway                -> no ratchet advance
    power loss before Finish            -> old ratchet retained
    replay below committed freshness    -> rejected
    Bitcoin proof touching storage_epoch-> structurally impossible

One per §0 blocker, because each closes a path that produces no error today:

    Begin naming its own anchor/thresholds -> rejected; constraints come only
                                              from the verified certificate (#6)
    honest chains replayed to force writes -> advances rate-limited (#2, #6)
    clearsign cert offered as a firmware
      epoch bump, and the reverse          -> rejected on domain tag AND key (#3)
    schema root verifying a delegate cert  -> rejected (#3, #8)
    full -> bitcoin-only -> full round trip -> expired delegates STAY expired;
                                              freshness preserved opaquely (#1)
    policy byte corrupted in flash         -> strict policy selected, not
                                              permissive (#7)
    policy after device reset              -> secure default, never the previous
                                              value (#7)
    ratchet journal from a previous OTP
      generation replayed                  -> rejected (#2)
    candidate epoch below floor            -> rejected BEFORE the erase, or the
                                              documented recovery-only state (#4)

Plus explicit mode separation: **metadata validation failure != blind-sign
entry.** That test must assert not only a returned error but that signing state
was cleared and no subsequent Ack can resurrect the original session.

Plus policy integrity: the host cannot select the policy in a signing request;
the policy survives reboot; the device's own transaction classification cannot
be steered by host-supplied hints.

Plus epoch rollback via flash modification, scope escape, re-delegation,
delegate reuse across chains, and the behaviour of a device that has not
connected in a year.

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

### Updater invariant — BLOCKER 4. The shipping bootloader contradicts it

The anti-rollback RFC's update state machine requires, in order: verify the
candidate's bounds, hash and full signature policy; decode the OTP floor;
**reject `candidate_epoch < floor` before erasing the installed image**. Its
security invariant is stronger still:

> A power loss must leave the device able to boot either the previous accepted
> image or the new accepted image.

**Neither is achievable with the current bootloader.** `handler_erase()` in
`tools/bootloader/usb_flash.c:425-493` erases sectors 7-11 — the entire
application partition — on receipt of `FirmwareErase`, which arrives *before*
any candidate bytes or metadata. At that moment the bootloader has seen no
epoch, no hash and no signature; there is nothing to compare against the floor.
And with one application slot, the window between erase and a completed upload
is a state in which **neither** image is bootable. That is not a regression this
work introduces — it is today's behaviour — but the epoch design cannot be built
on top of it, because "reject before erase" has no erase left to precede.

Three ways out, and one must be chosen before the epoch ships:

1. **Staging or dual-slot.** Receive into a second region, verify fully, then
   activate. Restores both properties directly. Costs an application-sized
   region the part may not have spare, so this needs a flash-map answer before
   it is costed.
2. **Signed-digest preflight with streamed verification.** The candidate's
   signed metadata — including its epoch and image digest — is transferred and
   verified *first*, the floor comparison happens there, and only then does the
   erase proceed; the body is streamed and verified against the committed digest
   as it lands. Preserves "reject before erase" without a second slot, but does
   **not** restore old-or-new bootability across power loss.
3. **Rewrite the invariant** to admit recovery-only interruption states: state
   explicitly that a power loss mid-upload leaves the device in a bootloader
   recovery mode with no bootable application, and that this is accepted. This
   is the honest description of today's device, and it is a legitimate choice —
   but it must be written down, because the RFC currently promises otherwise and
   an auditor will read the promise.

Whichever is chosen, the OTP floor must still only advance after the image has
been verified *from flash* (RFC step 6→7), so a torn write can never ratchet the
device past an image it cannot boot.

---

## 9. Open questions — parameters, downstream of §0

**These are not the blockers.** The blockers are in §0 and they are structural;
what follows are parameters that only become answerable once §0 is settled.
Reading this list as "what remains" is the misreading §0 exists to prevent.

- **ROM cost of the streaming header validator**, measured against the
  post-#339/#340 headroom in the FULL variant. Bitcoin-only does not carry the
  validator (see *Variant scope*), so the whole cost lands on the tighter build.
  **Measure last.** The substrate (#2) determines whether there is a journal and
  an atomic update path to measure at all; the authority model (#3) determines
  how many verification contexts exist; the updater decision (#4) may add a
  staging path; the certificate layout (#8) sets the parser. A number produced
  before those exist describes a design nobody has chosen.
- Delegate count: one, or several with disjoint scopes (per chain, per
  partner)? More delegates means smaller blast radius but more chain
  validation and more ROM. Follows the custody decision (#5), which sets how
  expensive an issuance ceremony is.
- Does a delegated v1 render truly warning-free, or keep a subtler marker
  ("described by KeepKey, 12 Aug") — recording that a third party asserted the
  meaning, without the alarm of the self-service path?
- Does v2's reach make v1 rare enough that the per-tx service is
  opt-in rather than default?
- Blind-sign policy stickiness (§5b, *Four things the policy model must get
  right*, item 4). Note that the session-scoped option under BLOCKER 7 answers
  this by construction, so the two should be decided together rather than
  separately.

Resolved out of this list: epoch/tip storage is now BLOCKER 2, not a parameter —
it is not a choice between three media but a facility that does not exist.
Certificate encoding is settled in §6 *Canonical certificate*: a compact fixed
layout, never X.509.
