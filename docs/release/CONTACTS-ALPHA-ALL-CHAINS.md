# Native certified contacts on alpha

This block extends the existing seed-certified address book to the firmware's
native payment signers. It retains the `KKABREQ1`, `KKABRT01`, `KKABPRF1` and
`KKABLEAF` envelopes and existing EVM vectors. Capability 32 identifies the
new native address form; a version string alone does not enable the host path.

## Certificate and destination contract

Destination type 1 remains an EVM address in 20 bytes. New type 4 is the exact
printable ASCII destination, 1–255 bytes, with no spaces, controls or Unicode.
Types 2 and 3 remain reserved: this change does not attest arbitrary scripts or
account bytes under their old placeholders. Labels retain the 24-byte ASCII
limit and reject `%`, controls, edge spaces and repeated spaces.

The complete 16-entry request can be 5,550 bytes, inside the existing 26 KiB
decode arena. Every label, network and complete destination is reviewed before
the device signs the domain-separated root manifest. Proofs remain bounded by
the existing 1,024-byte metadata field. A signature on an address-book root
does not attest ownership, a multisig policy, deployment, a token or an amount.

Network identifiers must match the signer adapter exactly. Existing Desktop
Pioneer identifiers are preserved for its UTXO, XRP, Solana, TRON and Monero
networks. Tendermint namespaces include the actual signed chain ID. EOS uses
the signed chain ID's first 16 bytes, hex encoded. Other firmware UTXO coins
use `keepkey:<hex of exact coin_name>` rather than a guessed genesis identifier.

Most destinations preserve their exact validated address text. Special forms:

* TON uses `workchain:lowercase-account-hash`, reconstructed from a checksum-
  checked mainnet friendly address. Both workchain and hash are signed.
* XRP uses `classic-address?dt=<unsigned decimal tag>` when a destination tag
  is present; a certificate for the bare address never labels a tagged payment.
* Solana SPL may name a token account, or an owner only after the device derives
  its ATA and matches that account. Host-resolved lookup keys cannot get names.
* Hive names are eligible only on the exact 32-byte mainnet chain ID.
* Zcash names follow receiver/user-address verification. Monero names follow
  the device's destination encoding, including integrated payment IDs.

## Review and lifetime

The name adds a `Certified contact` page. Every pre-existing full destination,
amount, fee, memo, authority and policy review remains. A name never enables a
blind-signing policy or applies to an approval/unknown contract action.

A proof belongs to one signing attempt, including that workflow's streamed
continuations. Completion, failure, refusal, cancellation, locking, a new
attempt or an unrelated operation scrubs it. Status polls do not advance it.
The EOS completion fix is necessary because its previous successful path kept
the signing session active and rejected the next preload.

Desktop injects a candidate proof immediately before the signing-start message,
inside hdwallet's existing transport lock. Preliminary address/feature reads
therefore cannot consume it. The device authenticates and matches the candidate;
host address matching is not an assertion that a name was displayed. Hidden
wallets do not preload the standard wallet's saved contacts.

## Signer coverage ledger

Owner and reviewer: Codex. Positive signer controls exercise baseline-screen
preservation, unchanged signed bytes, one-attempt isolation, wrong-network and
cancellation in `test_msg_native_certified_contacts.py`. Exclusion rows instead
assert the name is absent. Randomized Monero signatures use the independent
reference transaction verifier; a separate test covers its network and cancel
boundaries.

| Surface | Adapter | Named wire control |
| --- | --- | --- |
| UTXO external outputs | `transaction.c` | `test_bitcoin_output` |
| Cosmos | `fsm_msg_cosmos.h` | `test_cosmos_send` |
| Osmosis | `fsm_msg_osmosis.h` | `test_osmosis_send` |
| THORChain | `fsm_msg_thorchain.h` | `test_thorchain_send` |
| MAYAChain | `fsm_msg_mayachain.h` | `test_mayachain_send` |
| XRP and destination tag | `fsm_msg_ripple.h` | `test_xrp_and_destination_tag_binding` |
| EOS token transfers | `eos.c`, `eosio.token.c` | `test_eos_transfer` |
| Nano send link | `nano.c` | `test_nano_send` |
| Solana native | `fsm_msg_solana.h` | `test_solana_system_transfer` |
| Solana checked tokens/ATA | same | `test_solana_checked_token_account_and_verified_owner` |
| Solana nonce/close destinations | same | `test_solana_nonce_withdrawal_and_account_close` |
| Solana unproven lookup keys | same | `test_solana_host_lookup_destination_never_acquires_a_name` |
| TRON native/known TRC-20 | `fsm_msg_tron.h` | `test_tron_native_send`, `test_tron_known_token_and_unknown_fallback` |
| TON WalletV4R2 | `ton.c`, `fsm_msg_ton.h` | `test_ton_verified_transfer_and_forged_fields`, 96 independent @ton/core vectors |
| Zcash shielded | `fsm_msg_zcash.h` | `test_zcash_verified_user_address` |
| Zcash transparent PCZT | same | `test_zcash_transparent_pczt_output` |
| Monero standard/subaddress/integrated | `fsm_msg_monero.h` | `test_monero_standard_subaddress_and_integrated` |
| Hive transfer/streamed value operations | `fsm_msg_hive.h` | `test_hive_transfer`, `test_hive_streamed_value_operations` |
| Existing EVM | unchanged destination encoding | `test_msg_ethereum_certified_contacts.py`, legacy native vectors |
| Maximum request/proof and malformed text | `contact_book.c`, attestor | `test_maximum_text_book_and_proof_validation` |

Banano has no active `CoinType` row in this selected alpha product. A direct
wire probe returns `Failure_InvalidCoinName` before any review or signature.
Its namespace mapping is reserved only and is not a supported-chain claim.

The host companion is based on the audited modern Vault tree
`8014db143f104a79898ea397b5038f7c9e5e09d5`; the old fork master is a different
application history and must not be merged to publish this companion. Review:
https://github.com/BitHighlander/keepkey-vault/pull/6 at
`01765ed9d87209ba3733c9b8da7ad8cf3b500b0e` (86 focused tests pass).

## Necessary prerequisites and review findings

* `CONTACT-EOS-001`: finish and clear the EOS session before replying with the
  signature; the next proof preload must work without another unrelated call.
* `CONTACT-TON-001`: verify the WalletV4R2 cell hash before showing any verified
  destination. Mismatched/incomplete structured fields refuse signing. Opaque
  raw signing retains its AdvancedMode gate and never displays a contact name.
* `ALPHA-NATIVE-001`: apply the same Monero compiler flags to every native probe.
* `ALPHA-UDP-001`: size the emulator/test receive queues for bounded preloaded
  review frames. Both standalone and composed native CI jobs raise the host
  receive-buffer ceiling. The full suite runs without the audit's LD_PRELOAD shim.
* `ALPHA-PALLAS-001`: use the shared Zcash arena member directly. The source
  boundary gate can then guard its identifier without permitting macro aliases.
  Its operation requirements and adversarial alias checks remain enforced.
* `ALPHA-PINS-001`: reconcile the firmware-pinned protocol/Python features into
  fork master, preserve the fork's other applicable test fixes, and pin exact
  resulting masters. No upstream dependency PR or develop branch is changed.
* `ALPHA-PYK-001`: the inherited Uniswap external-recipient test incorrectly
  expected refusal on the pinned 7.15 candidate. Its source already requires
  explicit consent to that complete recipient. The corrected test checks the
  actual warning pixels, historical signature and cancellation on both 7.15
  and alpha; no firmware policy changes or new test skips are needed.
* `CONTACT-HOST-001`: match the pinned hdwallet API's decimal-string XRP tags
  and byte/base58 Solana owner hints. Tag zero stays distinct from no tag, and
  a bare contact cannot displace a routed contact. Tests cover the real Ripple
  adapter; a JS-to-emulator control certifies the host's request and verifies
  its proof, OLED name, unchanged signature and one-attempt consumption.
* `CONTACT-HOST-002`: Desktop accepts raw TON addresses, while the wire field
  is bounded to friendly encoding. The capability-gated host adapter converts
  only that presentation, derives an omitted destination workchain, and keeps
  the signed hash and explicit workchain claims intact. Real SDK packets from
  Desktop's builder pass on both workchains with AdvancedMode disabled; the
  prior raw packets reproduce the bounded-protobuf rejection.

Qualification evidence records the exact source, dependency trees, containers,
test counts, skips, ARM ELF/binary hashes and memory gates. The full product's
measured reserve is 18,684 bytes, largest frame 8,672 bytes, margin 10,012 bytes;
the bitcoin-only reserve is 44,824 bytes. Budgets remain 16 KiB and 4 KiB.
Certificate review's own largest frame is 6,224 bytes. Hardware high-water
measurement and release qualification remain separate from alpha integration.
