# ClearSign intent templates (KKSOLSC1 v3, EVM schema v3): format and screens

Status: **design for SRS-7.16 §3.7 / SRS-7.15 R-1.5**, owner-approved 2026-10-02.
The ClearSign server authors the words; the device fills every value from the
signed bytes and owns all risk wording.

## 1. Byte layout (Solana, KKSOLSC1 version 3)

Version 3 is version 2 plus two fields. Versions 1 and 2 keep parsing and render
through R-7.5 (firmware-generated summary).

```
magic        8   "KKSOLSC1"
version      1   3
program_id   32
disc         1 + 1..8
program name 1 + 1..20          printable 0x20-0x7e, no '%'
instr name   1 + 1..20
n_args       1   0..8
  per arg:   type 1, label 1 + 1..16, [mint_account 1 if TOKEN_AMOUNT],
             role 1                                  <- v3
n_accounts   1   0..4
  per acct:  index 1, label 1 + 1..16
template     1 + 0..96          printable 0x20-0x7e, no '%'   <- v3; 0 = none
```

The delegate signature covers the whole payload, so wording, roles and layout
are one signed object. The payload limit stays at 256 bytes.

**Roles** (`role` byte): `0` none, `1` spend-max, `2` receive-min, `3` spend-exact,
`4` receive-exact. Amount types (LAMPORTS, TOKEN_AMOUNT) must carry 1–4; all
other types must carry 0. Anything else is rejected.

**Template rules** (rejection is fail-closed on the certified path, R-1.4):
- `{n}` (n = 0..n_args-1) is replaced by the device's formatting of argument n;
  `{aN}` (N = 0..n_accounts-1) by schema account N, shortened `ABCD…WXYZ`.
- `{` or `}` anywhere else rejects the template; so does an out-of-range index.
- Coverage: every amount argument appears at least once.
- Values are never taken from the template; it has no digits of its own that
  the device treats as amounts.

## 2. Device formatting of facts

| Arg type | In the summary | On the Limits screen |
|---|---|---|
| TOKEN_AMOUNT, certified identity | `2,727,077.86 SDICE` (2 dp) | full precision + full mint on its own line |
| TOKEN_AMOUNT, mint = native `So11…1112` | `2.8265 SOL` | `2.826522391 SOL` (firmware fact, no definition needed) |
| TOKEN_AMOUNT, no certified identity | `2727077857751 base units` | same + full mint |
| LAMPORTS | `0.0100 SOL` | 9 dp |
| PUBKEY / `{aN}` | `ADuU…DcEt` | full address on a detail screen |

## 3. Certified screen order

1. **Summary.** Title = program name; body = filled template.
2. **Limits.** Firmware wording, one line per role-tagged amount, then every SOL
   transfer out of the signer that the device decodes natively, then the fee:
   `You spend at most / You receive at least / You spend / You receive`,
   `Also sends 0.001 SOL to ADuU…DcEt`, `Network fee up to 0.001005 SOL`.
   Full mints follow on the next page when an amount is a token.
3. **Side effects.** Only when present, firmware wording:
   `Creates a temporary wSOL account, closed back to you` (ATA create/sync +
   close to signer), `Creates a token account for you (rent ~0.002 SOL)`.
4. **Who.** `Described by <alias> <fp8>` / `certified by KeepKey` → hold to sign.

Runtime tier (7.15, AdvancedMode): heading `<alias> (NOT verified by KeepKey)
says:` + the filled template, then Limits, then the unchanged raw review.

## 4. Expected screens from the owner's real transactions

### PumpSwap sell (Vault request 2026-10-02, 6 instructions)
Schema `pumpAmmSell`: args `You sell` TOKEN_AMOUNT(mint acct 3) role 3,
`Receive at least` TOKEN_AMOUNT(mint acct 4) role 2; no accounts; template
`Sell {0} for at least {1}`.

| # | Title | Body |
|---|---|---|
| 1 | Pump.fun | Sell 2,727,077.86 SDICE for at least 2.8265 SOL |
| 2 | Limits | You spend 2,727,077.857751 SDICE / You receive at least 2.826522391 SOL |
| 3 | Limits 2/3 | SDICE mint 4nCmpwne7hCoWTSpAd54uENmCgHJrHTyn4DMPCEMpump |
| 4 | Limits 3/3 | Also sends 0.001 SOL to ADuU…DcEt / Network fee up to 0.001005 SOL |
| 5 | Side effects | Creates a temporary wSOL account, closed back to you |
| 6 | Who | Described by KeepKey Vault a9531b9d, certified by KeepKey |

(Today: 20 screens.)

### PumpSwap buy (mainnet 2TVzaEUK…, 9 instructions)
Schema `pumpAmmBuy`: `You get` TOKEN_AMOUNT(3) role 4, `Pay at most`
TOKEN_AMOUNT(4) role 1, `Track volume` U8 role 0; template
`Buy {0} for at most {1}`.
Summary: `Buy 2,996,422.23 SDICE for at most 0.5324 SOL`.
Limits: `You spend at most 0.532378090 SOL / You receive 2,996,422.230511 SDICE`.

### SoltoshiDICE poker join (riverproof `join_table`)
The buy-in is not in the instruction data (it comes from table state), so the
template cannot state it and the Limits screen must say so in firmware wording:
`Amount set by the program, not shown in this transaction`. This entry needs a
server-side redesign (a buy-in argument the program checks, or claimed context
in 7.17) before it can meet the objective; until then its review states the gap.

## 5. Server obligations (R-7.8)
- Every catalog entry ships template, roles and the expected screens above,
  generated from the same formatter rules, plus the evidence for its layout.
- Certify only when firmware will accept (instruction cap, companions,
  coverage, roles, native-mint rule).
- Token identities: certify every TOKEN_AMOUNT mint; the native mint needs none.
