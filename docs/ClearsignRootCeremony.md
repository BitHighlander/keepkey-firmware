# Clear-signing delegation root — ceremony runbook

**The root key is the whole of 7.16.** In 7.15 a describer can mislabel a
transaction but never conceal it, because the raw-data review always follows —
which is exactly why 7.15 needed no custody programme. 7.16 lets a describer
KeepKey has vouched for omit that review. The key that does the vouching is not
adjacent work to the release; it *is* the release, and this document is how it
comes into existence.

The ceremony below was executed end to end on hardware on **2026-08-21**. The
root it produced, `02de9231…dae7`, is the **alpha root**: every 7.16 alpha build
embeds it, and its private half is on the marked root KeepKey (device
`393137350D4736341B003900`, `m/44'/60'/0'/0/0`). The certificate it produced is
the fixture `unittests/firmware/clearsign_root.cpp` verifies against, so every
step here has been run at least once.

**The alpha root is alpha-only.** Production gets its own root from a new run of
this ceremony after the 7.15 re-release, not before, and that root replaces the
alpha bytes before any 7.16 production release (§4.4). The release pipeline
enforces it: `release.yml` fails any release whose firmware image or emulator
libraries contain the alpha root (§8). The two decisions in §7 are still open.
They are presented as decisions, not as recommendations wearing a fact's
clothes.

Read with `security/DESIGN-716-reductive.md` (why one branch is the whole
feature), `release/SRS-7.16.md` (the requirements), and
`security/7.15.0-rc21-clearsign-release-control.md` (the provisioning rules this
runbook inherits and extends).

---

## 1. What the root key is

| | |
|---|---|
| the key | secp256k1 at `m/44'/60'/0'/0/0` of a seed generated **on a KeepKey** |
| what ships | the 33-byte compressed **public** half, compiled into `lib/firmware/clearsign_root.c` in **every** 7.16 build — there is no build flag and no rootless variant. Today that is the alpha root, which no release may carry (§8) |
| what it signs | 139-byte delegate certificates, and nothing else |
| who reads it | `clearsign_root_verify_cert()` — the only function in the firmware that trusts the array. `clearsign_root_is_present()` only tests it for zero. |
| the private half | on the device, and on its paper backup. Never a file, never in CI, never on a laptop. |

`clearsign_root.c` exists as its own translation unit so that "who can reach the
root key" is a one-line grep. **Adding a second reader is a security change, not
a refactor**, and must be reviewed as one.

**Why there is no flag.** Vault enables certified ClearSign from the firmware
version alone (`>= 7.16.0`). A 7.16 build without a root refuses every
certificate it is sent — which is exactly what happened when the emulator
library Vault installs was built without the old `KK_CLEARSIGN_ALPHA_ROOT`
option: every certified description came back `MALFORMED`. So the root is not a
build option. The version and the root move together, and
`ClearsignRoot.SevenSixteenAlwaysShipsTheRoot` fails the unit suite if they ever
come apart.

**What keeps the alpha root out of production is the release gate, not a
flag.** `release.yml` refuses the alpha root's bytes in every release artifact.
Production gets its own root after the 7.15 re-release, not before, so no 7.16
production release can go out until that root has replaced the alpha one.

### 1.1 Why the root is a stock KeepKey and not an HSM

A certificate is signed over

```
digest = keccak( 0x19 || 0x01 || DOMAIN_SEP || keccak(cert[0..74]) )

DOMAIN_SEP = keccak( keccak("EIP712Domain(string name,string version)")
                  || keccak("KeepKey Clearsign Delegation")
                  || keccak("1") )
           = 8839401f8d0112b4348770ddace152e96fc5e5081aefeed6b5d8bef0d6ecdf66
```

That is not a KeepKey-specific construction dressed up as EIP-712. It **is**
EIP-712: `EthereumSignTypedHash` takes a domain-separator hash and a message
hash and signs `keccak(0x19||0x01||ds||mh)`. Hand it `DOMAIN_SEP` and
`keccak(cert[0..74])` as those two halves and the device produces the
certificate signature itself.

Three consequences, all of them the point:

- **No new signing path.** No raw-digest message had to be added to the
  protocol, and the root device runs ordinary shipped firmware. A capability
  that does not exist cannot be abused.
- **Low-S for free.** `trezor-crypto` normalises S; `ecdsa_verify_digest()`
  rejects high-S. A host-side signer that forgets to normalise emits a
  certificate no device accepts, at random, roughly half the time, with nothing
  in the output to say why. The device cannot make that mistake.
- **The domain is ours and never crosses the wire.** A host can neither
  substitute nor elide it, and a certificate preimage can never also parse as a
  metadata payload.

The preimage was not always this. The verifier once hashed `sha256(TAG||body)`
while the ceremony signed EIP-712, and **every certificate a real ceremony
produced would have been rejected by every device**. The unit test passed
throughout, because its fixture had been generated by the same code path it was
testing. See §6.3 — this is why step 6 exists at all.

### 1.2 The certificate

Fixed layout. No TLV, no length fields, nothing to fuzz.

| off | len | field |
|---|---|---|
| 0 | 1 | `cert_version`, must be `0x01` |
| 1 | 1 | `usage_flags`; bit0 = `MAY_SUPPRESS_RAW`, **all other bits must be 0** |
| 2 | 4 | `chain_id`, big endian, **nonzero** |
| 6 | 4 | `not_after`, big endian unix seconds |
| 10 | 32 | `alias`, NUL-padded ASCII |
| 42 | 33 | `delegate_pubkey`, compressed secp256k1 (`0x02`/`0x03`) |
| 75 | 64 | `root_sig`, compact ECDSA over the digest above |
| | **139** | |

A certified envelope on the wire is `[0x03][cert 139][inner v2 payload]`. The
certificate is checked against the compiled-in root, the inner payload is then
checked against the **delegate** key the certificate carries, and the
certificate is **discarded**. Two signatures, two distinct keys, one message,
and nothing about the delegation survives into the next transaction. There is no
slot to promote and no state to inherit.

Field notes that matter when you choose values in §4.5:

- **`chain_id` must be nonzero and is matched exactly** against the transaction.
  A certificate is bound to one network, because the same address means
  something else entirely on another one. There is no wildcard, by omission or
  otherwise.
- **Reserved flag bits must be zero.** A flag the firmware does not understand
  is a capability it never agreed to.
- **`not_after` is compared against `KK_CLEARSIGN_MIN_EXPIRY`, not against a
  clock.** The device has none. See §6.
- **Failure degrades, it does not refuse.** An unverifiable, expired,
  wrong-chain or malformed certificate lands on the 7.15 additive path, where
  the raw review still runs. Refusing would hand anyone able to age out a
  certificate a remote kill switch.

---

## 2. Before you start

| precondition | how you know it holds |
|---|---|
| A device dedicated to this role, holding no funds and no other wallet | it is the device you are about to wipe and reset; nothing else has ever been loaded on it |
| A **signed release** installed on it, not an RC | `Features.firmware_hash` is in the shipped table; an RC reports `firmwareVerified: false` in vault |
| The exact firmware version recorded before anything else happens | §4.1 prints it |
| A host with the `python-keepkey` commit this release pins | `git -C deps/python-keepkey rev-parse HEAD` matches the gitlink in the release commit |
| The delegate's **public** key, 33 bytes compressed, from the provider | the ceremony never sees a delegate private half |
| A second, independent host that can recompute `keccak(cert[0..74])` | you will compare it against the OLED in §4.5 |

**OPEN — ceremony tooling provenance.** The script used on 2026-08-21,
`sign_delegate_cert.py`, is an untracked scratch file. The device shows two
digests, not the certificate's fields (§4.5), so **the tool that assembles the
body is trusted to assemble it correctly**. Before a production ceremony,
decide where that tool lives, who reviews it, and how the operator confirms the
copy they are running is the reviewed one. Until then the second-host
recomputation in §4.5 is the only thing standing between a typo and a signed
certificate for the wrong chain.

**OPEN — venue, witnesses and recording.** Not decided. The practice run was one
operator at a desk. Whatever is chosen must at minimum produce the ceremony log
in §9, since the release reviewer has nothing else to check the compiled-in
bytes against.

**Never provision while a hidden wallet is active.** Keys derive from the active
seed/passphrase session, so a hidden wallet silently yields a different
identity. This rule is inherited verbatim from
`7.15.0-rc21-clearsign-release-control.md` and it has not become less important
now that the key in question can suppress a screen.

---

## 3. AdvancedMode is required, and it is session state

`fsm_msgEthereumSignTypedHash` refuses outright unless the `AdvancedMode` policy
is on:

```
"Enable AdvancedMode to blind-sign typed hashes"
```

`AdvancedMode` is **never persisted**. `storage.c` ignores whatever the retired
policy bit holds in flash and starts every load with it disabled, and
`session_clear(true)` turns it off on any lock — screensaver, `ClearSession`,
recovery. So it must be enabled **once per ceremony**, and it is off again the
moment the root device is unplugged.

Enabling it is not a silent host call. `fsm_msgApplyPolicies` shows

```
Enable Policy
Do you want to enable AdvancedMode policy?
```

and then runs `CHECK_PIN_UNCACHED` — a fresh PIN entry, if the device has one,
that a cached session cannot satisfy.

**This is a desirable property for a root key, not an obstacle.** The root's
entire job is to sign a hash it cannot interpret. A capability like that should
not be a durable attribute of the device; it should be something a human turns
on, in front of the device, for the duration of one ceremony, and that decays on
its own the instant the ceremony ends. A root device found unplugged in a safe
is a root device with blind signing disabled — provably, because there is no
storage path that could have left it on.

The corollary is that **an attacker with the device also needs the physical
button**, and with §7.1 answered one way, the PIN as well.

---

## 4. The ceremony

Six steps. Each one names what you observe, not what you assume.

### 4.1 Bring the device to a known state and record it

```python
from keepkeylib.client import KeepKeyClient
from keepkeylib.transport_hid import HidTransport

c = KeepKeyClient(HidTransport(HidTransport.enumerate()[0]))
f = c.features
print("version    :", f.major_version, f.minor_version, f.patch_version)
print("device_id  :", f.device_id)
print("label      :", f.label)
print("initialized:", f.initialized)
print("fw_hash    :", f.firmware_hash.hex())
print("revision   :", f.revision.hex())
```

Record every line in the ceremony log. `initialized` must be `False` before you
proceed — if it is `True`, this is not a fresh device and you must stop and
decide deliberately whether to wipe it, not do it by reflex.

The firmware version is pinned here and never changes mid-ceremony. If the
device is updated later, the root key is unaffected — but the log entry stops
describing the machine that produced the signature, which is the only reason the
entry exists.

### 4.2 Generate the seed **on the device**

```python
c.reset_device(display_random=False,
               strength=128,          # §7.2 — 128 = 12 words, 256 = 24
               passphrase_protection=False,
               pin_protection=False,  # §7.1 — the practice run had no PIN
               label="clearsign-root",
               language="english")
```

**Never `load_device`.** A root key that was ever a string on a host is a root
key whose custody story begins on that host. `reset_device` generates it inside
the device: the firmware commits to its own internal entropy first, then asks
the host for a contribution via `EntropyRequest`/`EntropyAck` and hashes over
both, so the host cannot weaken the result and cannot know it.

The device shows the recovery sentence on the OLED and asks you to confirm the
words. Write them down there and then. That paper is the only backup of the
delegation root, and nothing in this system can reissue it.

If you cancel at any screen, nothing is armed and nothing was written: the
staged ceremony is discarded (`setup_stage()`/`setup_arm()` in `reset.c`, where
`setup.kind` is the only armed-ness there is). Re-read `Features.initialized`
to confirm before retrying.

**OPEN — dice entropy.** `ResetDevice.dice_entropy` exists from 7.15 and folds
on-device dice rolls into the seed (`docs/DiceEntropy.md`); the pinned client's
`reset_device()` does not set it. Whether the production root ceremony uses dice
is undecided. Note what dice do and do not buy: the displayed digest proves your
rolls were captured, and proves nothing about whether they reached the seed.
They are worth the effort only if the RNG is the thing you distrust — and you
are trusting the same firmware either way.

### 4.3 Read the root public key — twice

```python
n  = c.expand_path("m/44'/60'/0'/0/0")
pk = c.get_public_node(n).node.public_key
print("root pubkey:", pk.hex())        # 33 bytes, 0x02 or 0x03 prefix
```

Then `c.clear_session()`, physically reconnect, re-enter the **standard** wallet
with an **empty** passphrase, and derive again. **Accept the key only if both
readings match byte for byte.** This is the rc21 provisioning rule and it exists
because a passphrase session silently produces a different, perfectly valid
looking key.

Also record the Ethereum address for that node — `c.ethereum_get_address(n)` —
because §4.5 is going to show it to you on the glass, and it is the only thing
on that screen that ties the signature to the key you are about to compile in.

### 4.4 Compile the public key in

`lib/firmware/clearsign_root.c` holds exactly one root, unconditionally. Today
it is the alpha root:

```c
static const uint8_t kk_clearsign_root_pubkey[CLEARSIGN_PUBKEY_LEN] = {
    0x02, 0xde, 0x92, 0x31, /* … 33 bytes … */ 0x06, 0xda, 0xe7,
};
```

There is no `#if`, no all-zero arm and no CMake option: every 7.16 build —
device, emulator, dylib/DLL — carries these bytes.

**The alpha root is alpha-only.** Production gets its own root from a new run
of this ceremony after the 7.15 re-release, not before, and that root replaces
the alpha bytes before any 7.16 production release. Until it does, no 7.16
release can go out: `release.yml` fails any release whose firmware image or
emulator libraries contain the alpha bytes (§8). That is intended.

The replacement is one reviewed diff. The production root's 33 bytes go in four
places, and nowhere else:

- the array in `lib/firmware/clearsign_root.c`, with its comment naming the new
  device id, version and date, and no longer calling it the alpha root;
- the root constant in the three `ci.yml` checks that require the embedded root
  in every full build and emulator library: the ARM product-boundary gate,
  `python-dylib-tests`, and the `publish-emulator-libs` stage step.

`release.yml`'s two checks do **not** change. They keep refusing the alpha
root's bytes, which keeps the alpha root out of every later release as well.

The unit fixtures signed by the alpha root (`kValidCertHex` and `kCert501Hex` in
`clearsign_root.cpp`, `kCert501Hex` in `solana.cpp`, python-keepkey's
`CERT_501`) stop verifying and must be re-minted by the new root in the same
change — see §4.6(a). `ClearsignRoot.TheEmbeddedRootIsTheAlphaRoot` pins the
embedded key through two of those certificates instead of reading the key. It
needs two: an ECDSA signature verifies under two public keys, and only the
intended root verifies both. The replacement re-mints both and renames the
test.

What a reviewer checks on this diff, and can actually check:

- exactly 33 bytes, first byte `0x02` or `0x03`, identical in all four places;
- the bytes equal the pubkey recorded in the ceremony log — **both** readings
  from §4.3;
- the comment names a real device id, version and date, and the log corroborates
  all three;
- nothing else in `clearsign_root.c` changed, and `release.yml` still refuses
  `02de9231…dae7`.

A reviewer with no independent record of the bytes is not reviewing anything and
should not approve. Nothing validates that the array is a point on the curve; a
mistyped key simply fails every verification, and the certified fixtures in the
unit suite then fail by name.

### 4.5 Sign the delegate certificate

Enable the policy for this session, then sign:

```python
c.apply_policy("AdvancedMode", True)   # confirm on device; PIN if set
```

```sh
./sign_delegate_cert.py --backend keepkey \
    --delegate-pubkey <33-byte compressed hex, from the provider> \
    --chain-id 1 \
    --expiry <unix seconds, must exceed KK_CLEARSIGN_MIN_EXPIRY> \
    --alias "KeepKey" \
    --may-suppress \
    --path "m/44'/60'/0'/0/0" \
    --out cert.bin
```

The device then shows **four** screens, in this order. Each one is a thing you
verify, not a thing you dismiss:

| screen | body | what you check |
|---|---|---|
| `EIP-712 Blind Sign` | *Cannot verify these hashes. Trust the host?* | An accurate warning. The device cannot see the certificate's fields. This is why the next three screens matter. |
| `Verify Address` | `0x…` | **Equals the address recorded in §4.3.** This is what binds the signature to the key you compiled in. |
| `Typed Data domain` | 64 hex chars | **Equals `8839401f8d0112b4348770ddace152e96fc5e5081aefeed6b5d8bef0d6ecdf66`.** Any other value means you are signing into somebody else's domain. |
| `Typed Data message` | 64 hex chars | **Equals `keccak(cert[0..74])` as computed on your second host** from the fields you intended. This is the only check that catches a body assembled wrong. |

Do not press the button on the fourth screen until the second host agrees. The
device is telling you truthfully that it cannot check these for you.

Result: `cert.bin`, exactly 139 bytes. Parse it back before doing anything else
— version `0x01`, flags `0x01`, your chain, your expiry, your alias, the
delegate pubkey you were handed.

**OPEN — how the delegate public key reaches the ceremony.** The practice run
generated a throwaway delegate locally. In production the delegate is the
provider's signing key and the transfer needs an authentication story of its
own: a certificate for the wrong 33 bytes is a valid certificate for a key
nobody intended to trust, and the OLED will not catch it — only the second-host
recomputation will.

### 4.6 Verify the certificate against the built firmware, before shipping

Three checks. The first is the one that has already caught a real defect; the
others are cheap and independent.

**(a) The C verifier, compiled with the production root, accepts this exact
certificate — and rejects it with any single byte of `cert[0..74]` flipped.**

This is the check that would have caught the sha256-vs-EIP-712 drift. It works
only if the fixture comes from the *other* side of the pipeline: a certificate
produced by the ceremony, verified by the firmware's own code. A fixture
generated by the code under test proves self-consistency and nothing else.

The run needs no flag, because every build carries the root:

```sh
docker run --rm --platform linux/amd64 -v "$PWD":/root/keepkey-firmware:z \
  kktech/firmware:v15 /bin/sh -c "\
    mkdir -p /root/ut && cd /root/ut && \
    cmake /root/keepkey-firmware -DCMAKE_BUILD_TYPE=Debug -DKK_EMULATOR=ON \
      >/dev/null 2>&1 && \
    make -j4 firmware-unit >/dev/null 2>&1; \
    ./bin/firmware-unit --gtest_filter='ClearsignRoot*'"
```

The fixture in `unittests/firmware/clearsign_root.cpp` was signed by the root
this firmware embeds (today the alpha root), so
`TheCeremonysCertificateVerifies` exercises the exact verifier and root the
build carries. The production ceremony also produces the certificates that
replace these fixtures, in the same change as the §4.4 diff. **The requirement
does not change: the compiled release verifier accepts the ceremony's
certificate, and rejects it under single-byte mutation.** Do not substitute a
host-side check — that is the ceremony marking its own homework.

**(b) The ARM release binary contains the production root and not the alpha
root.**

```sh
python3 - <<'EOF'
PROD = bytes.fromhex("<the 33 bytes from §4.3>")
ALPHA = bytes.fromhex(
    "02de9231b2094433235532fb1932e324a2c7304195e12e610c675cccbbd606dae7")
blob = open("bin/firmware.keepkey.bin", "rb").read()
print("production root present:", PROD in blob)
print("alpha root present     :", ALPHA in blob)
EOF
```

The first line must be `True` and the second `False`. `release.yml` enforces
the second on both firmware images and both emulator libraries. `ci.yml`'s
gates enforce the first once §4.4 has put the production bytes in them.

**(c) End-to-end on an emulator carrying the production root.**

Build the emulator from the release source (it carries the same root as the
device image; there is no flag to pass), feed it a certified envelope and an
`EthereumSignTx`, and observe on screen: `Verified by KeepKey`, the delegate
alias and fingerprint, and **no raw-data review**. Then flip one byte of the
certificate and observe the raw-data review return.

One trap here, which produces a green result that means nothing:

- **OPEN — there is no host tool that builds a `[0x03][cert][inner v2]`
  envelope.** `METADATA_VERSION_CERTIFIED` appears only in firmware sources.
  Until one exists and is reviewed, (c) cannot be run at all, and (a) plus (b)
  are the whole of step 6.

---

## 5. What the user sees, and why the marker is positive

Not part of the ceremony, but the reason it is worth performing. A delegated
render shows

```
Verified by KeepKey
<alias> (<fingerprint>) describes this transaction.
```

A **positive** marker, not the absence of a warning. An absence signals nothing
to a user who has never seen the thing that is missing, and on EVM there is
nothing to miss anyway — "NOT verified by KeepKey" appears only on the load-time
consent screen for runtime signers, never per transaction. A delegated describer
that merely dropped a warning would be indistinguishable from a stranger, on the
one screen where the difference decides whether the raw review is about to be
skipped.

No expiry date is shown. The device has no clock, and displaying a date would
imply a freshness check it did not perform.

---

## 6. Revocation

### 6.1 There is exactly one lever

`KK_CLEARSIGN_MIN_EXPIRY`, in `include/keepkey/firmware/clearsign_root.h`. A
certificate whose `not_after` is at or below the floor fails verification and
the transaction degrades to the additive path.

It is a constant, hand-set at each release cut. It is **deliberately not derived
from the build date**: an auto-moving floor rots test fixtures silently and
cannot be reviewed in a diff, and the entire value of the mechanism is that
revocation is one reviewable line in a signed release.

The current value is `1787270400` = **2026-08-21T00:00:00Z**, the 7.16 cut
instant. The floor IS the cut, which is the only value that costs nothing and
still means something: it honours every certificate that had not already
expired when the firmware was built, and rejects every one that had.

It was `1755000000` = 2025-08-12, a year *before* its own cut, so it passed
every certificate that has ever existed and the lever was decoration.
**Setting it is a decision the release cut has to actually make**, not a line
to leave alone.

The next bump is squeezed between two bounds that pull opposite ways. To revoke
a delegate the floor must go **above** that certificate's `not_after` — a bump
that does not clear it is not a revocation. To keep every other delegate
working it must stay **below** theirs, including the committed unit-test
fixture's `1818806400` (2027-08-21T00:00:00Z). When those two cannot both be
satisfied, the fixture gets re-minted; see §6.3.

### 6.2 The consequence, stated plainly

**A device that never updates never revokes.** There is no online check, no CRL,
no counter, and no way to reach a device that sits in a drawer. Revoking a
compromised delegate means shipping a signed firmware release with a higher
floor and waiting for users to install it. Between the compromise and the
install, that delegate can suppress the raw-data review on every device carrying
the old floor.

This is an accepted limitation, and SRS-7.16 R-2.3 requires exactly that it be
written down with its blast radius rather than left implicit. This section is
that writing-down.

The mitigation that already exists is scope: a certificate is bound to one
chain, one delegate key and one expiry, and it grants nothing beyond describing
transactions on that chain. The mitigation that does not exist is time.

**OPEN — certificate lifetime.** The practice certificate used one year
(`1818806400` = 2027-08-21T00:00:00Z). Shorter lifetimes narrow the compromise
window but only in combination with a floor that actually moves; a one-year
certificate under a floor nobody bumps expires on paper and nowhere else. Decide
the two together or neither is real.

### 6.3 The trap this section inherits

The floor is checked before the signature. Bumping it invalidates every
certificate below it *including the unit-test fixtures*, which is intended — a
fixture that survives a revocation is a fixture pinned to a certificate the
firmware no longer honours. Expect §4.6(a) to need a re-issued certificate after
a floor bump, and treat a green test run across a bump as a signal to look
harder, not as reassurance.

---

## 7. Open decisions

Two, both about the production root, both genuinely undecided. They are stated
with their tradeoffs rather than resolved here.

### 7.1 PIN on the root device

The practice run had none.

**For a PIN.** It is the only thing between physical possession of the device
and a signed certificate. Enabling `AdvancedMode` runs `CHECK_PIN_UNCACHED`, so
a PIN turns the once-per-ceremony policy toggle into a per-ceremony
authentication — the attacker needs the device, the button, and the secret.

**Against a PIN.** It is one more secret to escrow, and losing it means losing
the ability to issue certificates without a recovery from the paper backup —
which is the one operation the whole custody model is trying never to perform.
A PIN also protects against exactly one threat model, physical theft of the
device, and does nothing about the operator.

**What it does not change either way.** The private key still never leaves the
device, and the raw-data suppression it authorises still lives or dies on the
signed release that carries the public half.

### 7.2 12 words or 24

**The security argument is settled and it is not the argument people expect.**
secp256k1 gives roughly 128-bit security regardless of seed length: 24 words
carries 256 bits of entropy into a key space that offers 128 bits of resistance.
It buys **no cryptographic strength** over 12 words, and it doubles the
transcription surface — twice the words to write down, read back, and re-enter
under pressure, on the one backup that cannot be reissued.

**The counterargument is real and is not cryptographic.** 24 words is the
convention for high-value keys. An auditor, a customer, or a future team member
who finds a 12-word backup for a delegation root will ask why, and "it makes no
difference" is a correct answer that still costs a conversation every time. The
cost of the convention is one-time; the cost of explaining its absence recurs.

There is no right answer here. There is a choice between a smaller error
surface and a smaller explanation surface. Make it explicitly and record which
one was chosen and why in the ceremony log, so the next person does not have to
reconstruct the reasoning from a word count.

---

## 8. Release gating

What must be true before a release carrying a root key is signed:

1. **No release carries the alpha root.** `02de9231…dae7` is embedded in every
   7.16 alpha build, and it is alpha-only. The gates check the bytes, not the
   source:
   - `release.yml` `build-firmware`, "Refuse the alpha ClearSign root": fails
     the release if the full or the bitcoin-only firmware image contains the
     alpha bytes.
   - `release.yml` "Attach emulator libraries": fails the release if either
     emulator library contains them. The libraries are not rebuilt; they come
     from the newest green CI run for the tagged commit.

   Both fail with `alpha ClearSign root in a release artifact: production needs
   its own root (new ceremony after the 7.15 re-release)`. Until the §4.4
   replacement lands, every 7.16 tag fails here, release candidates included.
   That is intended: production gets its own root after the 7.15 re-release,
   not before.
2. **Every 7.16 build carries a root.** There is no rootless build and no flag.
   What proves it:
   - `firmware-unit`: `ClearsignRoot.SevenSixteenAlwaysShipsTheRoot` fails a
     7.16+ build whose root is all zero, and
     `ClearsignRoot.TheEmbeddedRootIsTheAlphaRoot` pins the exact key through
     two certificates the alpha root signed.
   - `ci.yml` `build-arm-firmware`, on every push and PR run: the full image must
     contain the alpha root and the bitcoin-only image must not (bitcoin-only
     does not link `clearsign_root.c`; `lib/firmware/CMakeLists.txt` lists it
     under `NOT KK_BITCOIN_ONLY`).
   - `ci.yml` `python-dylib-tests`: fails when the dylib or DLL it built (the
     libraries Vault installs) lacks the alpha root, and then does not upload
     them as the commit's `libkkemu-<sha>` artifact.
   - `ci.yml` `publish-emulator-libs`: refuses to publish a dylib or DLL
     without the alpha root to the rolling `emulator-dylib-latest` prerelease.
3. **The production root has replaced the alpha root.** It comes from a new run
   of this ceremony, after the 7.15 re-release, on its own device; §4.4 lists
   what the diff changes.
4. **Any change to the root was reviewed against the ceremony log**, per §4.4,
   by someone with an independent copy of the recorded pubkey.
5. **§4.6(a) passed on the release commit** — the compiled verifier accepts the
   production certificate and rejects it under single-byte mutation.
6. **`KK_CLEARSIGN_MIN_EXPIRY` was set deliberately for this cut**, and the
   value appears in the release diff whether or not it changed.
7. **The 7.15 additive invariant still holds.** Atlas section F must pass
   unchanged against 7.16 firmware: a runtime provider never suppresses. This is
   the single most important regression in the release — 7.16 must not promote
   self-service providers by accident.
8. **Gate 3 OLED evidence for both tiers**, captured side by side, so a human
   can see the difference the design claims to make.

A failed early CI gate skips the whole downstream graph and the run summary
still looks clean. Judge from job logs, not from the summary.

---

## 9. Verification checklist

Every item is something the operator or reviewer can **observe**. None of it is
something they have to take on trust.

**Device and seed**

- [ ] `Features` recorded before anything else: version, `device_id`, `label`,
      `firmware_hash`, `revision`
- [ ] The installed firmware is a signed release, not an RC
- [ ] `Features.initialized` was `False` before the reset and `True` after
- [ ] The seed came from `reset_device` — `load_device` was never sent
- [ ] The recovery sentence was shown on the OLED, written down, and confirmed
      back to the device
- [ ] `Features.passphrase_protection` is `False`; no hidden wallet was active

**Root key**

- [ ] `get_public_node("m/44'/60'/0'/0/0")` returns 33 bytes, prefix `0x02`/`0x03`
- [ ] The read was repeated after `clear_session()` and a physical reconnect,
      into the standard wallet with an empty passphrase
- [ ] Both readings are **byte-for-byte identical**
- [ ] The Ethereum address for that node is recorded

**Compilation**

- [ ] The 33 bytes in the `clearsign_root.c` diff equal both recorded readings
- [ ] The same 33 bytes replaced the alpha root in the three `ci.yml` checks,
      and `release.yml` still refuses the alpha bytes (§4.4)
- [ ] The unit fixtures signed by the alpha root were re-minted by the new root
- [ ] Nothing else in `clearsign_root.c` changed

**Signing**

- [ ] `Enable Policy / AdvancedMode` was confirmed on the device this session
- [ ] `Verify Address` showed the address recorded above
- [ ] `Typed Data domain` showed
      `8839401f8d0112b4348770ddace152e96fc5e5081aefeed6b5d8bef0d6ecdf66`
- [ ] `Typed Data message` matched `keccak(cert[0..74])` from the second host
- [ ] The certificate is exactly 139 bytes
- [ ] Parsed back: version `0x01`, flags `0x01`, the intended chain, `not_after`
      above the firmware floor, the intended alias, and the delegate pubkey as
      supplied by the provider

**Before shipping**

- [ ] The compiled release verifier accepts the certificate (§4.6a)
- [ ] It rejects the certificate with any single byte of `cert[0..74]` flipped
- [ ] The full ARM binary contains the production root (§4.6b)
- [ ] No release artifact contains the alpha root: neither firmware image and
      neither emulator lib (`libkkemu-macos-arm64.dylib`,
      `libkkemu-win-x64.dll`) — `release.yml` refuses them otherwise
- [ ] `KK_CLEARSIGN_MIN_EXPIRY` was reviewed for this cut
- [ ] Atlas section F passed unchanged

**Aftermath**

- [ ] The root device is unplugged; `AdvancedMode` is off by construction
- [ ] The paper backup is where the custody decision says it goes
- [ ] The ceremony log records the §7.1 and §7.2 choices **and their reasons**

---

## 10. Known divergences from SRS-7.16

Recorded here rather than quietly reconciled, because the SRS text has not been
updated and a reader who finds the difference deserves to know it was noticed.

| SRS | text | what was built |
|---|---|---|
| R-1.2 | root private key held offline "HSM or equivalent self-hosted; not a cloud KMS" | a stock KeepKey, seed generated on device. It satisfies offline and self-hosted; it is not an HSM, and §1.1 is the argument for why that is the stronger choice here rather than a compromise. |
| R-2.2 | "the device SHALL refuse an expired one" | the device **degrades** to the 7.15 additive path. Refusing would make certificate expiry a remote kill switch for signing itself. The implementation is deliberate; the requirement text is wrong. |
| R-2.3 | revocation without a firmware update, "or its absence SHALL be stated as an accepted limitation with its blast radius" | absent. §6.2 is the statement the requirement asks for. |
