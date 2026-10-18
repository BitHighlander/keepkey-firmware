# Certified contacts for Bitcoin-family coins (7.17)

Firmware 7.16 certifies EVM contacts only. Their proof reaches the device only
through `EthereumTxMetadata`, and only the EVM send screen checks it. The
contact format already reserves destination type 2 (`UTXO_SCRIPT`), unused
until now. This block uses it for the `SignTx` coins KeepKey Desktop names by
CAIP-2.

## Entry

`UTXO_SCRIPT` = (network, exact scriptPubKey, name), in the same KKABREQ1
book, Merkle leaf and KKABRT01 signature as EVM entries. The wire format is
unchanged, so one certification covers a mixed book.

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
  convention: the device compares bytes, so it must match what the host
  sends. A coin outside the table, or outside this build, cannot be
  certified; its sends are reviewed as usual.
- **Destination**: the exact output script. Matching bytes, not address
  strings, covers every form with one rule: P2PKH (25 bytes), P2SH (23),
  P2WPKH (22), P2WSH (34), P2TR (34), and CashAddr, which encodes the same
  scripts. Only these templates are certifiable, because the device must show
  each as an address. OP_RETURN and anything else is refused.
- **Coin binding** is the network string, which is in the leaf. BTC and BCH
  share script bytes, as Dogecoin and DigiByte share a P2PKH version byte;
  a contact for one never names the other.
- The 7.16 rules stay: ASCII names, no edge or double spaces, one name per
  address and one address per name per network. A person's P2WPKH and P2TR
  addresses need two names.

## Certification

`ClearsignAttestorSign(KKABREQ1)` reviews UTXO entries like EVM ones: the
summary screen, then per contact `<name>\n<coin name>` (not the CAIP-2
string) and a `Destination` screen with the script rendered as that coin's
address (Base58Check with the coin's version bytes, bech32/bech32m, or
CashAddr with its `bitcoincash:` prefix, as the BCH send screen shows it).
A book the device cannot render is refused before the first screen. The
bitcoin-only build has no EVM code and accepts UTXO entries only; it
registers `ClearsignAttestorSign` (address books only) but not
`ClearsignAttestorGetPublicKey` or schema attestation.

## Delivery: `SignTx.contact_proof` (optional bytes, field 16, max 428)

Considered:

1. **Optional field on `SignTx`** (chosen). One request, no new message, no
   dispatch exemption, no state held between messages before signing. Old
   firmware skips the unknown field (nanopb), so a 7.17 Desktop on 7.16 just
   gets the unnamed review. Works in the bitcoin-only build, which has no
   Ethereum messages.
2. A message just before `SignTx`, held in session RAM as on EVM: a new
   message type, a dispatch rule keeping the proof while every other request
   drops it, and Cancel/error ordering. More surface, same result.

Handling:

- Checked in `fsm_msgSignTx` after the PIN and before the signing root is
  derived (both use the shared derivation scratch), against this seed and
  passphrase's attestor key.
- Kept only if it is a valid `UTXO_SCRIPT` proof for the coin being signed.
  A bad signature, another seed or book, a tampered path, an EVM entry or
  another coin is dropped silently; signing continues with no name. **A
  proof never makes a send fail.**
- Single use: cleared by a new `SignTx`, the end of signing (done or
  aborted), Cancel, ClearSession, a lock, and any request outside the signing
  flow. `signing_abort()` drops only a `UTXO_SCRIPT` proof, so an EVM proof
  loaded for the next `EthereumSignTx` survives the engine reset before it.

## Screen

A name is shown only on an output that is given by address (no `address_n`:
change and own-account transfers never), is not OP_RETURN, and whose compiled
script and coin network equal the proof's. Its screen
`Send 0.001 BTC to\n<address>` becomes `Send 0.001 BTC to Alice\n<address>`:
still one screen and one ButtonRequest, paged without cutting if long. The
full address stays, and the duplicate-output check still compares it. Every
output paying that script is named; other outputs, change, fee and total
screens are unchanged, and the signed transaction is identical.

Limit: one proof, one contact per transaction. Batches naming several
contacts need repeated proofs, a later change.

## Capability

`CAPABILITY_CERTIFIED_CONTACTS_UTXO = 28`, appended in the device-protocol
fork and reported by both builds: last in the full list (after
`CERTIFIED_CONTACTS`), and after the five base capabilities in bitcoin-only.
`Fsm.FeaturesReportExactlyTheStagedCapabilities` pins both lists;
`scripts/generate-test-report.py` lists it in `KNOWN_CAPABILITIES`.

## Cost

`contact_book.c`, `contact_book_utxo.c` and the address-book half of the
attestor handler now build into the bitcoin-only image too, so
`tools/check_bitcoin_only_identity.py` forbids `fsm_msgClearsignAttestorGetPublicKey`
instead of every `fsm_msgClearsignAttestor*` symbol. Full-build RAM gains
only a few bytes: the proof slot already exists, and the field sits in the
shared decode buffer.

## Not covered (documented limits)

- Revocation: as on EVM, old certifications stay valid for the seed and
  passphrase.
- The host is not told whether the proof was accepted. Desktop must not
  record "verified"; the device screen is the evidence.
- Coins outside the table (BTG, GRS, RVN, KMD, others) and the Zcash, LTC
  and BCH testnets.
