# Alpha audit SOP: cycle until zero, then switch models, then upstream

Goal: highly reviewed code. Every line of `alpha` is audited by independent
readers, every finding is adversarially verified, everything real is fixed on
`alpha` in one pass, and the cycle repeats until a full pass returns nothing.
Only then does the work move to `develop` and upstream (see
`docs/release/BRANCHING-SOP.md` for the branch rules).

## The loop

```
audit(alpha) -> verify(findings) -> fix(alpha) -> green -> audit again
   ... until a full pass returns 0 findings
   -> switch the auditing model, run the loop again until 0
   -> stage to develop, PR upstream
```

Never upstream from a branch that has not survived a zero-finding pass on at
least two different models. A model tends to miss the same class of bug every
time; a second model is the cheapest independent reviewer we have.

## 1. Audit: every surface, in units

One auditor per unit, reading the real files in full on the exact SHA under
audit. Units are the signing paths (one per chain), plus: storage, setup
ceremony, PIN/passphrase, U2F/CTAP2, authenticator, crypto/RNG/BIP85,
clearsign metadata, confirm/display, board I/O, JSON/FSM core. ~25 units cover
the ~30k LOC of `lib/firmware` + `lib/board`.

Each auditor is told the invariants it is checking, not what to find:

- **display-vs-signed**: every signed field is shown or the tx is refused.
- **fail closed**: formatting/bounds failure aborts, never blanks or truncates.
- **memory safety**: host-controlled sizes bounded by the nanopb `.options`.
- **secret hygiene**: keys/seeds scrubbed on every exit path.
- **dead surface**: unreachable code is deleted, not left latent.

Findings carry `severity` (P1 signs something the user did not approve; P2
disclosure gap or bypass; P3 hygiene/latent), `file`, `line`, `description`,
`exploit`, `remediation`. Auditors also return a coverage note saying what they
read and what they verified as SOUND, so a clean unit is evidence, not silence.

## 2. Verify: refute before you fix

Every finding goes to 2 verifiers (1 for P3) whose default verdict is NOT REAL.
A verifier flips only on a concrete trace from attacker input to wrong outcome
at the audited SHA. Survivors are tiered CONFIRMED / PLAUSIBLE; anything whose
verifiers did not run is UNVERIFIED and is re-verified before fixing, never
dropped.

The 2026-09-01 run: 36 raw -> 29 survivors -> 21 confirmed. The refutations
were mostly "the code is exactly as described but unreachable on alpha" -- that
class is the reason this step exists.

## 3. Fix: one pass on alpha

- Group findings by file so fixers never touch the same file concurrently.
- Smallest correct diff. Disclosure never weakens. Fail closed.
- Every non-trivial fix adds one gtest to the existing suite that fails before
  and passes after. No new frameworks.
- Refuted findings are recorded in the PR body with the refutation, not fixed.
- Dead code named by a finding is deleted if nothing references it.
- Build gate: `firmware-unit` + `board-unit` all green, cppcheck zero warnings,
  CI matrix green on the fork.

Local build recipe: `docs/release/ALPHA-MERGE-HANDOFF.md`, plus
`-DKK_CLEARSIGN_ALPHA_ROOT=1` in both C and CXX flags or the three
`ClearsignRoot.*` tests fail. `deps/python-keepkey` needs its nested
`keepkeylib/eth/ethereum-lists` submodule for the token table; init it
individually, not `--recursive`.

## 4. Re-audit

Run step 1 again on the new tip. Also run a diff review of everything the
fix pass changed, with the same verify step. Loop until both return nothing.

## 5. Switch models

Repeat steps 1-4 with a different model doing the auditing and verifying.
Record which models produced the zero pass in the PR body.

## 6. Then upstream

Only after two clean passes: stage to `develop` per `BRANCHING-SOP.md` and PR
upstream. The upstream PR body cites the audit passes.

## Keep the evidence

Workflow results in `/tmp` are ephemeral and were lost once. Before the session
ends, write the ranked findings and verdicts to
`docs/security/audits/<date>-alpha-<sha>.md` in the repo.
