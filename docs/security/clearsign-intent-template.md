# ClearSign intent templates (Solana KKSOLSC1 v3): format and screens

Status: SRS-7.16 §3.7 / SRS-7.15 R-1.5, owner-approved 2026-10-02. This file
describes what the firmware implements (solana.c `solana_buildIntentReview`).

The ClearSign server writes the words. The device fills in every value from the
bytes it signs, and the device owns all risk wording.

## 1. Roles and templates (shared)

**Roles** (one byte per amount): `1` spend-max, `2` receive-min, `3` spend-exact,
`4` receive-exact, `5` cap (each use at most). Amount arguments must carry 1–5.
Every other argument must carry 0. Any other value rejects the schema.

**Template**: 1..96 printable ASCII characters (0x20–0x7e), with no `%`.
- `{n}` is replaced with argument n, formatted by the device.
- Solana only: `{aN}` is replaced with schema account N.
- An unmatched `{` or `}`, an index out of range, or an opaque or bytes
  argument in the sentence rejects the template.
- Coverage: every amount argument must appear.
- Width: the widest possible expansion must fit the summary (280 characters).
  An amount counts as 34 characters, a short address as 11. A template that
  could overflow is rejected when parsed, never cut off on screen.
- No digits outside placeholders: every number on screen is the device's
  formatting of signed bytes, never text the server wrote.

The delegate signature covers the whole payload: wording, roles and layout.

## 2. Wire formats

**Solana KKSOLSC1 version 3** is version 2 plus a role byte after each argument
and a `template` field (1 + 0..96) after the accounts. The payload limit is
256 bytes. Versions 1 and 2 still parse. A certified v1/v2 schema gets the
same review with the instruction name as its summary. A runtime v1/v2 schema
keeps the older raw review.

## 3. How values are shown

Amounts are always exact, at full precision, and never rounded. Addresses are
shortened only inside the summary sentence, and the full form follows on a
later screen. The native mint So11…112 is shown as SOL by firmware rule. A
token without a certified identity is shown in base units, with its full mint.

## 4. Certified screen order

1. **Summary.** Title: program name. Body: the
   filled-in template.
2. **Limits.** One screen per role-tagged amount: "You spend at most",
   "You receive at least", "You spend", "You receive", or "Each use at most".
   A token amount is followed by its full mint.
   - Solana adds every SOL transfer from the signer with its full recipient
     ("Also sends X SOL to\n<address>"), then "Network fee up to X SOL"
     (5000 per signature plus the maximum priority fee), plus "paid by
     <address>" when the payer is not the signer.
3. **Side effects** (Solana; only when present). The word "your" and the phrase
   "back to you" appear only when the device key is the owner or destination:
   - "Creates a temporary wSOL account, closed back to you"
   - "Creates your token account for mint\n<mint>"
   - "Closes your token account\n<acct>\nrent back to you"
   - Otherwise the owner or destination is named in full.
   - Memos are paged as bytes.
4. **Details.** Every argument the sentence
   omits or only shortens, and every schema account (Solana).
5. **Who.** "Described by <alias> <fp>\ncertified by KeepKey". No date is shown,
   because the device has no clock. An expired certificate fails closed.

**Runtime tier** (7.15, AdvancedMode): the heading "<alias> (NOT verified by
KeepKey) says:" plus the filled-in template, then Limits, then the unchanged raw
review.

## 5. Real transactions (unit tests pin these screens)

**PumpSwap sell** (solana.cpp `IntentReviewOfRealPumpSellMatchesTheSpec`),
template `Sell {0} for at least {1}`:

| Title | Body |
|---|---|
| Pump.fun | Sell 7738120.185405 SDICE for at least 8.509507889 SOL |
| Limits | You spend / 7738120.185405 SDICE / 4nCmpwne…pump (full) |
| Limits | You receive at least / 8.509507889 SOL |
| Limits | Also sends 0.001000000 SOL to / DfXygSm4…DXjh (full) |
| Limits | Network fee up to 0.001005000 SOL |
| Side effects | Creates a temporary wSOL account, closed back to you |
| KeepKey ClearSign | Described by KeepKey Vault a9531b9d / certified by KeepKey |

**SoltoshiDICE blackjack join** (solana.cpp `IntentReviewCapRoleAndUnstated…`),
template `Join blackjack seat {2} for {3}; key {4} may bet {7} each, {6} total,
for {5}`: the buy-in is spend-exact, the allowance spend-max and the per-bet
limit a cap. Each one gets its own Limits line.

**SoltoshiDICE poker join** (catalog only, not pinned by a unit test): the
buy-in comes from table state, not from the instruction, so the template says
it is "set by the table". Stating the buy-in needs a program-checked argument,
or claimed context in 7.17.

## 6. Server obligations (R-7.8)

- Every catalog entry ships its template, roles and evidence for its layout.
- Certify only what the firmware will accept: the instruction cap,
  companions, coverage, roles, width and the native-mint rule.
- Certify every TOKEN_AMOUNT mint. The native mint needs no certification.
