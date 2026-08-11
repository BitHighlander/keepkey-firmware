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

### Unify the ratchet substrate; domain-separate the authority

Do NOT collapse everything into one global integer. Build **one**
integrity-protected monotonic state facility -- one implementation, one atomic
update path, one set of anti-rollback guarantees, one audit surface -- holding
domain-separated counters:

    SecurityRatchets {
        firmware_epoch;
        storage_epoch;
        clearsign_epoch;
        clearsign_freshness;   /* Bitcoin-derived */
    }

with different authorities permitted to advance different fields:

    ROOT SIGNATURE  -> firmware_epoch, storage_epoch, clearsign_epoch
    BITCOIN WORK    -> clearsign_freshness  (and nothing else, ever)

Bitcoin-derived state can therefore never cause a KDF migration, a storage
rewrite, a seed wipe, a firmware trust change, or a PIN behaviour change, no
matter how far it is pushed or how wrong the validator is. This is stronger
than "unify the epoch and separate the actions", which relies on discipline at
every call site; here the separation is structural.

### What the device actually validates

The delegate certificate carries its own Bitcoin anchor, so the trusted point
is re-established at every issuance and never goes stale between firmware
releases:

    delegate_pubkey
    usage               = CLEARSIGN_DYNAMIC
    chain_scope         = { 1, 8453, 42161 }
    can_delegate        = false
    epoch_min/epoch_max
    btc_anchor_hash     = H
    btc_anchor_height   = 1_050_000
    expiry_height_delta = 4320
    expiry_min_work     = W
    root_signature

The host then supplies 80-byte headers extending H, and the device checks only:

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
        clearsign_freshness absent or inert

    root-attestor special firmware:
        may optionally include validator tooling
        is NOT the retail bitcoin-only image

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

Protocol is a three-message session, validated and folded incrementally:

    BitcoinFreshnessBegin   cert hash, anchor hash, anchor height, thresholds
    BitcoinFreshnessChunk   sequence, concatenated 80-byte headers
    BitcoinFreshnessFinish  expected total header count

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

---

## 9. Open questions

- Epoch/tip storage: OTP, authenticated storage section, or firmware-carried
  minimum? Decides expiry latency and whether flash modification can undo an
  expiry.
- Streaming header-validator cost in ROM, measured against the post-#339/#340
  reclaimed headroom in the FULL variant. Bitcoin-only does not carry it (see
  the variant-scope section), so the whole cost lands on the tighter build.
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
