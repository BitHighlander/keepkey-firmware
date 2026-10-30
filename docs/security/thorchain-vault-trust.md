# THORChain / Maya router deposits: what the device can and cannot check

Status for 7.17 (alpha), 2026-10-29.

## What the device shows

A `deposit()` / `depositWithExpiry()` to a pinned router (chain id + address)
is reviewed on the device:

1. `Routing through Thorchain router` (or the Maya router label).
2. `Pays UNVERIFIED vault <hex>`.
3. The amount and asset sent, the expiry.
4. The memo, decoded: output asset and chain, destination, the least the swap
   pays out, the affiliate fee, aggregator fields.
5. The complete raw memo, paged.

7.17 changes step 4: a swap limit is shown as an amount of the output asset
(`Receive at least 0.00006074 BTC.BTC`) instead of a bare 1e8 integer
(`Confirm limit 6074`). A limit of 0 reads `No minimum output (limit 0)`.
Limits in other spellings (streaming `LIM/INT/QTY`, `1e8`) are shown as
written, and outputs on the MAYA chain are never scaled. A Maya router deposit
is now reviewed by the Maya memo parser, with Maya titles.

## The gap that remains: the vault

The router pays whatever `vault` the host puts in the call. The device has no
chain state and no clock, so it cannot tell a current Asgard vault from an
attacker's address, and it says so (`UNVERIFIED`). Every real deposit shows
that label today.

A vault attestation was prototyped on 2026-10-10 (branches
`proto/vault-attest`, `feat/alpha-vault-attestation`): the device issues a
nonce, a delegate key signs `nonce || chain id || router || vault`, and the
vault screen names the signer. It is not ported, because the nonce needs a key
that answers each request live, and D-018 rules out live signing. A
nonce-free, ceremony-signed list of vaults would fit D-018, but vaults churn
every few days and a clockless device cannot revoke a retired one; that is an
owner decision, not built here.

Until then the host is the check: KeepKey Desktop should compare the vault
with THORChain's inbound addresses from more than one operator and refuse on a
mismatch.

Follow-up (device-derivable, small): refuse a vault equal to the router or the
zero address. Neither is ever valid, and a host that falls back to the router
address would strand a token deposit. The python-keepkey deposit fixtures use
the router as the vault, so they must change first.
