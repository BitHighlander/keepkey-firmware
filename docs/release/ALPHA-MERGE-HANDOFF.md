# alpha <- develop merge: handoff

**alpha is at `681df4a0a` and is NOT merged.** The work in progress is on
`alpha-merge2`, which is not ready and must not be merged as-is.

## What this merge is

alpha carries 216 commits of 7.15 work (Zcash, vendored crypto, rc18). develop
carries the 89-commit 7.14.2 security line. **79 files were modified by both.**
They are two parallel evolutions of the same firmware, not a branch and its
upstream.

That is why an ordinary merge is dangerous here: it keeps whichever
non-conflicting hunks each side happens to have, compiles clean, and silently
reverts security fixes or 7.15 features depending on which way each hunk fell.

## What already went wrong, so it is not repeated

A first attempt (`355a0b314`, reverted, still recoverable) resolved `lib/` and
`include/` by taking develop's file wholesale. It **dropped 95 alpha symbols**,
including `storage_zcashOrchardKeys`, the whole Solana schema layer, PIN KDF
V18/V19 readers, dice entropy, and `random_buffer`. It passed a hand-written
gate that only checked 7.14.2 markers -- the gate did not look in the direction
that broke.

It was caught by alpha's own `tools/check_pallas_api_boundary.py`, not by me.

Two process errors worth not repeating:

- **Verifying against a moved ref.** After pushing the merge to `alpha`, I
  compared `origin/alpha` against the merge and got "0 lost symbols" -- I was
  diffing the merge against itself. Always compare against the fixed SHA
  `681df4a0a`.
- **rerere replaying bad resolutions.** The second attempt silently reapplied
  the first attempt's wrong resolutions. `rerere.enabled` is now false in this
  clone; check it before starting.

## The gate (the important artifact)

`/tmp/gate2.py` in-session; reproduce with the two steps below. The rule:

> A symbol defined in alpha `681df4a0a` may be dropped **only if nothing in the
> merged tree still references it.** Anything still called is a regression.

It also asserts the 7.14.2 markers are present, so it fails in both directions.
Current status on `alpha-merge2`: **40 still-referenced regressions**, 53 safe
drops.

## The 40 outstanding

Each needs alpha's function definition merged back into develop's version of the
file -- a hunk merge, not a file swap.
```
STILL REFERENCED but no longer defined: 40  <-- these are regressions
   lib/board/confirm_sm.c                   confirm_body_split                 3 call site(s)
   lib/board/font.c                         calc_str_line_n                    1 call site(s)
   lib/board/font.c                         calc_str_page                      4 call site(s)
   lib/firmware/app_confirm.c               confirm_bytes_is_text              10 call site(s)
   lib/firmware/app_confirm.c               confirm_zcash_address              1 call site(s)
   lib/firmware/ethereum.c                  ethereum_eip712_is_domain_primary_type 5 call site(s)
   lib/firmware/ethereum_contracts/thortx.c thor_confirmMayaTx                 1 call site(s)
   lib/firmware/ethereum_contracts/thortx.c thor_isMayachainTx                 1 call site(s)
   lib/firmware/ethereum_contracts/zxliquidtx.c zx_formatZxLiquidityPrimaryAmount  4 call site(s)
   lib/firmware/fsm_msg_ethereum.h          fsm_msgEthereumTxMetadata          1 call site(s)
   lib/firmware/fsm_msg_ethereum.h          fsm_msgLoadClearsignSigner         1 call site(s)
   lib/firmware/mayachain.c                 mayachain_isValidAsset             1 call site(s)
   lib/firmware/mayachain.c                 mayachain_isValidDenom             12 call site(s)
   lib/firmware/mayachain.c                 mayachain_isValidSigner            1 call site(s)
   lib/firmware/osmosis.c                   osmosis_formatAmount               8 call site(s)
   lib/firmware/reset.c                     reset_get_dice_digest              1 call site(s)
   lib/firmware/solana.c                    solana_deriveAssociatedTokenAddress 1 call site(s)
   lib/firmware/solana.c                    solana_findKnownToken              2 call site(s)
   lib/firmware/solana.c                    solana_findTokenRecipientOwner     2 call site(s)
   lib/firmware/solana.c                    solana_parseInstrSchema            10 call site(s)

```

## Status as of this handoff

`alpha-merge2` = `41949eaeb`. **32 regressions outstanding**, down from 40.

Done:

- **board / confirm** (batch 1, complete). `calc_str_line_n` and `calc_str_page`
  restored for Hive, but NOT verbatim -- alpha's counted lines in a `uint8_t`,
  which is the 255-newline wrap `0b2f08185` fixed. develop's `uint32_t` walk was
  generalised to take a length instead, so both callers share one implementation
  with the fix in it. `confirm_zcash_address` restored for `fsm_msg_zcash.h`.
  Two obsolete test files removed, with the lost property recorded in
  `board.cpp` rather than silently dropped.

- **clearsign handlers**. `fsm_msgEthereumTxMetadata` and
  `fsm_msgLoadClearsignSigner` restored -- `messagemap.def` dispatches both, so
  their absence is a build break. Plus `ethereum_signing_isInProgress`, which
  they depend on.

- **`random_buffer`**, guarded `EMULATOR && !__APPLE__`. Not a general
  definition: trezor-crypto declares it weak and GNU/MinGW ld will not extract a
  weak definition from a static archive, breaking the Linux .so and Windows .dll.

## The remaining 32, classified

24 are called from `lib/` and must be restored. 8 are referenced only by tests,
so the test is removed or retargeted.

Clusters, heaviest first:

| file | symbols | note |
|---|---|---|
| `storage.c` | 8 | PIN KDF V18/V19 readers/writers, Zcash Orchard keys, seed fingerprint. **Storage-format code -- a wrong merge here corrupts wallets, not screens. Do this one first and slowly.** |
| `thorchain.c` / `mayachain.c` | 7 | asset/denom/signer validators |
| `solana.c` | 1 real + 6 test-only | `solana_parseInstrSchema` is the real one |
| `osmosis.c`, `transaction.c`, `reset.c`, `zxliquidtx.c`, `thortx.c` | 6 | |
| `ethereum.c` | 1 test-only | `ethereum_eip712_is_domain_primary_type` |

## Gate limitations -- read before trusting it

The gate **over-reports**. It does not evaluate `#if` guards and does not look
inside `deps/`, so a platform-guarded definition (`random_buffer`) or a vendored
one reads as missing. Check by hand before restoring; two such cases have
already come up.

It also cannot see whether a restored function still *behaves* correctly against
develop's surrounding code -- it only checks that a definition exists. Restoring
a symbol is the start of the check, not the end.

## Suggested order

Batch by subsystem, one PR each into alpha, gate after every batch:

1. **board / confirm** -- `confirm_sm.c`, `font.c`, `app_confirm.c`. Everything
   else depends on the confirm layer. Note `calc_str_page` is used by
   `fsm_msg_hive.h`, so alpha's paging helpers must survive even though
   develop's renderer-backed pager replaces alpha's `confirm_body_split`.
2. **EVM / EIP-712** -- `ethereum.c`, `eip712.c`, `ethereum_contracts/*`
3. **THORChain / Maya** -- and their `fsm_msg_*`
4. **Solana / Osmosis / Tendermint** -- the schema layer is the largest piece
5. **reset / storage / rng** -- dice entropy, PIN KDF versions
6. **CI / build / tests** -- already unioned on `alpha-merge2` and validated

## Decisions already made

- **develop's pagination wins.** alpha paginated via `calc_str_page`, a second
  model of the screen; develop measures with `draw_string()`'s own walk. #428
  was reopened three times through exactly that seam.
- **CMakeLists stays 7.15.0.** alpha is the 7.15 line.
- **gitleaks install: alpha's**, which pins and verifies a sha256.
- **FW_VERSION detection: develop's**, which fails closed rather than defaulting.
- **CI invariants: union** -- alpha's Action-SHA/builder-digest checks plus
  develop's RNG source checks.

## Reproducing the gate

```
# 1. baseline every function alpha defined
python3 - <<'PY'
import subprocess, re, json
OLD='681df4a0a'
files=subprocess.run(['git','ls-tree','-r','--name-only',OLD,'lib/','include/'],
                     capture_output=True,text=True).stdout.split()
syms={}
for f in files:
    if not f.endswith(('.c','.h')): continue
    src=subprocess.run(['git','show','%s:%s'%(OLD,f)],capture_output=True,text=True).stdout
    fn=set(re.findall(r'^[A-Za-z_][\w \*]*\s+\**(\w+)\s*\([^;]*\)\s*\{', src, re.M))
    if fn: syms[f]=sorted(fn)
json.dump(syms, open('/tmp/alpha_syms.json','w'))
PY

# 2. after resolving, anything still referenced but undefined is a regression
```

## Submodules

Already reconciled per `BRANCHING-SOP.md` -- alpha pins fork masters:

- `BitHighlander/device-protocol` master `8bf32ed` (NEAR + Hive + Clearsign, no
  MessageType collisions)
- `BitHighlander/python-keepkey` master `8c1492b` (7.15 line + 7.14.2 tests)

That part is done and does not need redoing.

## Also found, unrelated but worth fixing

`unittests/firmware/thorchain.cpp` and `mayachain.cpp` exist in the tree but
were **not in `unittests/firmware/CMakeLists.txt`** on either branch, so their
tests never compiled or ran. Added to the sources list on `alpha-merge2`.
