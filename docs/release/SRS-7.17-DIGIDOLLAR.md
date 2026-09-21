# Firmware 7.17 — DigiByte Taproot and DigiDollar

Status: alpha implementation gate. Minimum version: **7.17.0**.

## Scope

Firmware 7.17 enables BIP-340/341 key-path signing and BIP-86 address display
for DigiByte (`m/86'/20'/account'/change/index`, `dgb1p`). This is the device
foundation for DigiDollar. Hosts MUST gate every DigiDollar flow on firmware
7.17.0 or newer.

DigiDollar is not an ordinary DGB balance. Its token outputs carry zero DGB;
amounts in integer USD cents are committed in transaction metadata. Hosts MUST
exclude every zero-satoshi output from ordinary DGB coin selection.

## Release requirements

- DGB key-path P2TR receive, change, and spend match BIP-340/341/86 vectors.
- The device displays the complete `dgb1p` destination and DGB amount before
  signing an ordinary DGB Taproot transaction.
- A DigiDollar transfer review displays DD amounts as cents, DGB miner fees
  separately, and never describes a zero-satoshi token output as zero value.
- Mint review displays DD minted, DGB collateral, lock tier, and unlock height.
- Redeem review displays DD burned, DGB released, and any DD change.
- Unknown or malformed DigiDollar transaction versions/metadata are refused.
- The device never signs a DigiDollar transaction through the generic DGB
  path without the DigiDollar-specific review above.

## Capability stages

The initial alpha flag enables ordinary DigiByte key-path Taproot only. Vault
must keep DigiDollar hidden until its dedicated transaction parser and review
tests pass. Mint collateral and redemption use Taproot script paths; those
flows remain disabled until script-path commitments and control blocks are
implemented and verified. Key-path transfer support does not imply mint or
redeem support.

## Acceptance

1. Derive and display the expected mainnet `dgb1p` address from a fixed BIP-86
   vector at coin type 20.
2. Sign and broadcast an ordinary DGB key-path Taproot spend on testnet26.
3. Reject a DD carrier output offered as an ordinary DGB input.
4. Verify DD transfer, mint, and redeem fixtures from DigiByte Core v9.26.5.
5. Exercise malformed version, wrong-cent amount, altered OP_RETURN, missing
   previous-output amount/script, and mixed-input cases.
6. Report flash and RAM headroom from the alpha build.

