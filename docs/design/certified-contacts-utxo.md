# Certified contacts for Bitcoin-family coins (7.17)

Firmware 7.16 certifies EVM contacts only, through `EthereumTxMetadata`.
This block uses the reserved destination type 2 (`UTXO_SCRIPT`) for the
`SignTx` coins KeepKey Desktop names by CAIP-2.

## Entry

`UTXO_SCRIPT` = (network, exact scriptPubKey, name), in the same KKABREQ1
book and KKABRT01 signature as EVM entries, so one certification covers a
mixed book. Its Merkle leaf is tagged `KKABUTXO` instead of `KKABLEAF`:
alpha builds before 7.17 certified any entry type with the script shown only
as hex and no duplicate rules, and those books must never name a Bitcoin
output. 7.16 never certified type 2, so nothing released breaks.

- **Network**: the CAIP-2 string Desktop and Pioneer already send. A firmware
  table binds each to one coin:

  | network | coin |
  |---|---|
  | `bip122:000000000019d6689c085ae165831e93` | Bitcoin |
  | `bip122:000000000933ea01ad0ee984209779ba` | Testnet |
  | `bip122:12a765e31ffd4059bada1e25190f6e98` | Litecoin |
  | `bip122:00000000001a91e3dace36e2be3bf030` | Dogecoin |
  | `bip122:000000000000000000651ef99cb9fcbe` | BitcoinCash |
  | `bip122:000007d91d1254d60e2dd1ae58038307` | Dash |
  | `bip122:00040fe8ec8471911baa1db1266ea15d` | Zcash (transparent) |
  | `bip122:4da631f2ac1bed857bd968c67c913978` | DigiByte |

  The Dogecoin and Dash strings are Pioneer's, not the genesis-hash
  convention: the device compares bytes. A coin outside the table, or this
  build, cannot be certified; its sends are reviewed as usual.
- **Destination**: the exact output script. Matching bytes, not address
  strings, covers every form with one rule: P2PKH (25 bytes), P2SH (23),
  P2WPKH (22), P2WSH (34), P2TR (34), and CashAddr, which encodes the same
  scripts. Only these templates are certifiable, because the device must show
  each as an address. OP_RETURN and anything else is refused.
- **Coin binding** is the network string, which is in the leaf. BTC and BCH
  share script bytes, as Dogecoin and DigiByte share a P2PKH version byte;
  a contact for one never names the other.
- The 7.16 rules stay: ASCII names, no edge or double spaces, one name per
  address and one address per name per network.

## Certification

`ClearsignAttestorSign(KKABREQ1)` reviews UTXO entries like EVM ones: the
summary screen, then per contact `<name>\n<coin name>` (not the CAIP-2
string) and a `Destination` screen with the script rendered as that coin's
address (Base58Check, bech32/bech32m, or CashAddr with its `bitcoincash:`
prefix). A book the device cannot render is refused before the first
screen. The bitcoin-only build accepts UTXO entries only, and has no
`ClearsignAttestorGetPublicKey` or schema attestation.

## Delivery: `SignTx.contact_proof` (optional bytes, field 16, max 428)

Considered:

1. **Optional field on `SignTx`** (chosen). One request, no new message, no
   state held between messages. Old firmware skips the unknown field
   (nanopb), so 7.16 just shows the unnamed review. Works in the
   bitcoin-only build, which has no Ethereum messages.
2. A message just before `SignTx`, held in session RAM as on EVM: a new
   message type and dispatch rules. More surface, same result.

Handling:

- Checked in `fsm_msgSignTx` after the PIN, before the signing root is
  derived (shared scratch), against this seed and passphrase's attestor key.
- Kept only if it is a valid `UTXO_SCRIPT` proof for the coin being signed.
  A bad signature, another seed or book, a tampered path, an EVM entry or
  another coin is dropped silently; signing continues with no name. **A
  proof never makes a send fail.**
- Single use: cleared by a new `SignTx`, the end of signing (done or
  aborted), Cancel, ClearSession, a lock, and any request outside the signing
  flow. `signing_abort()` drops only a `UTXO_SCRIPT` proof, so an EVM proof
  loaded for the next `EthereumSignTx` survives the engine reset before it.
- `EthereumTxMetadata` keeps, and reports "Contact verified" for, EVM
  proofs only; a UTXO proof there is "Invalid contact".

## Screen

A name is shown only on an output that is given by address (no `address_n`:
change and own-account transfers never), is not OP_RETURN, and whose compiled
script and coin network equal the proof's. Its screen
`Send 0.001 BTC to\n<address>` becomes `Send 0.001 BTC to Alice\n<address>`,
one screen. When that does not fit (a long name or amount with a two-line
address), page `1/2` shows `Send <amount> to <name>` and page `2/2` the
whole address, which is never split. The address is rendered from the script
in its certified spelling (lowercase bech32, CashAddr for BCH), whatever
spelling the host sent. Every output paying
that script is named; change, fee and total screens are unchanged, and the
signed transaction is identical.

Limit: one proof, one contact per transaction. Batches naming several
contacts need repeated proofs, a later change.

## Capability

`CAPABILITY_CERTIFIED_CONTACTS_UTXO = 28`, appended in the device-protocol
fork and reported last by both builds.
`Fsm.FeaturesReportExactlyTheStagedCapabilities` pins both lists;
`scripts/generate-test-report.py` lists it in `KNOWN_CAPABILITIES`.

## Cost

The contact book and the address-book half of the attestor now build into
the bitcoin-only image, so `tools/check_bitcoin_only_identity.py` forbids
only `fsm_msgClearsignAttestorGetPublicKey`. Full-build RAM gains a few
bytes: the proof slot exists, and the field sits in the decode buffer.

## Not covered (documented limits)

- Revocation: as on EVM, old certifications stay valid for the seed and
  passphrase: a proof from an earlier revision still names its contact
  (pinned by a unit vector).
- The host is not told whether the proof was accepted. Desktop must not
  record "verified"; the device screen is the evidence.
- Coins outside the table (BTG, GRS, RVN, KMD, others) and the Zcash, LTC
  and BCH testnets.
