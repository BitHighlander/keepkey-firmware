# Duress wipe passphrase

The duress passphrase is a separate, opt-in factory-reset trigger. It is not a
PIN, the existing numeric wipe code, or a BIP39 wallet. Entering it in an ordinary
wallet passphrase request erases the device before displaying the passphrase,
asking for confirmation, caching it, or deriving keys. The pending wallet
operation fails; the device then reports uninitialized. It does not open a decoy
wallet or conceal the reset.

## Configuration protocol

Hosts must check `Features.supports_duress_passphrase == true`. The separate
`Features.duress_passphrase_protection` reports whether it is armed. Old firmware
does not report support and must not be offered this setting.

An initialized device must have a PIN and BIP39 passphrase protection enabled.
Send `ChangeDuressPassphrase { remove: false }` (wire ID 1800). Firmware displays
an explicit erase warning, requests the current PIN even when it was cached,
then requests the new passphrase using `PassphraseRequest`. It shows that value
on the device with the title **Duress Passphrase**, asks the user to repeat it,
and requests and displays the second value. Only matching, nonempty entries are
committed. The maximum is 50 bytes, matching the ordinary wallet passphrase
limit; spaces, case, and UTF-8 bytes are significant. Embedded NUL bytes are
rejected before decoding. No normalization is added.
Cancellation, an empty entry, mismatch, or entropy failure preserves the previous
configuration. These setup requests do not trigger a previously configured
duress value.

To remove protection, send `ChangeDuressPassphrase { remove: true }`; device
consent and fresh PIN authorization are required. Remove duress protection
before disabling BIP39 passphrases or removing the PIN. Changing the PIN remains
available. A successful configuration change clears the cached wallet passphrase
so the next wallet operation requests it again.

Triggering requires an actual wallet passphrase request. If the current wallet
passphrase is cached, clear the session or reconnect first. No extra host command
or wipe confirmation is involved in triggering. Ordinary passphrases, including
the empty wallet passphrase, retain their existing confirmation behavior.

## Persistence and reset

Storage V21 uses 49 bytes at public offset 1440 within the existing reserved
area: an enabled byte, 16 bytes of checked random salt, and a 32-byte verifier.
PBKDF2-HMAC-SHA256 uses 100,000 iterations with the salt prefixed by the ASCII
domain `KeepKey duress v1`. The plaintext is never persisted or exposed through
debug state. Comparison uses the existing hardened comparison primitive.

V20 and older storage upgrades with duress disabled; randomized reserved bytes
are never interpreted as a verifier. Passkey metadata and the encrypted wallet
layout are preserved. Bitcoin-only storage uses the corresponding V21 band.
Firmware that understands the existing newer-format guard refuses V21 on
downgrade and preserves the wallet for a firmware upgrade.

On a match, firmware revokes signing and authenticator sessions, erases all
three rotating storage sectors, verifies their erasure, resets RAM storage and
cryptographic caches, creates a new device UUID, and commits empty settings.
An erase failure halts instead of reporting a successful reset. As with any
flash erase, uninterrupted power is needed to finish; this is not an atomic
guarantee against power removal during the erase sequence.

Use a strong, unique phrase distinct from every wallet passphrase. A host that
collects the phrase can learn it, and someone reading flash can attempt offline
guesses against the salted verifier. The feature does not invalidate an external
recovery backup, erase host-side data, or provide plausible deniability. Wallets
remain recoverable from their recovery sentence and original wallet passphrases.

## Validation

The `DuressPassphrase.*` native suite drives the real PIN matrix and passphrase
state machines over emulator USB messages. It covers fresh authorization,
two-entry setup, cancellation and mismatch, ordinary and empty wallet phrases,
maximum length, persistence, removal, and migration. The match test checks that
no confirmation screen displays the trigger and that a reboot remains empty.
Physical-device timing and power-interruption characterization remain release
validation tasks; these tests operate only on emulator flash.
