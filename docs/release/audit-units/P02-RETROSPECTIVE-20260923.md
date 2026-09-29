# P02 retrospective: passing tests did not prove the disclosure claim

## Verdict

This was an assistant audit failure. The relevant source and a host test demonstrating the alternative disclosure path were available during the review. Model capability, green CI, inherited code and the reviewer's effort setting do not excuse the miss. The assistant should have found the contradiction before saying implementation/verification was complete.

Reviewed candidate: `5a59d8a5edcf78be56c969f15aea8afcfd9afa3d`, PR #855. Copilot review `5288422597` reported eight inline findings plus additional body notes. This retrospective inspects the frozen source; it does not claim a production-device exploit or that the proposed fixes below have already been implemented.

## What the evidence actually establishes

1. `lib/firmware/reset.c`: MIXED mode calls `show_mnemonic_pages(mnemonic_from_data(int_entropy, 32), ...)` after consent. The pager copies the displayed words into `current_words`. `reset_get_word()` returns that buffer.
2. `lib/firmware/fsm_msg_debug.h`: omits `reset_entropy` when its length is zero, but independently copies `reset_get_word()` into `reset_word`. It also serializes the displayed canvas into `layout` and exposes other sensitive debug fields, including stored mnemonic and node data.
3. `unittests/host/test_p02_transport.py`: the new dice test checks only `reset_entropy` at the initial consent prompt, then cancels. It never enters the entropy-word pages or asserts anything about `reset_word`, `layout`, or later ceremony stages.
4. The pinned `deps/python-keepkey/tests/test_msg_resetdevice.py` explicitly collects `read_reset_word()` during MIXED entropy pages and reconstructs the device entropy from the words. This directly contradicts interpreting absence of one byte field as absence of disclosure.
5. `docs/security/7.14.3-bitcoin-only-dice-audit-sop.md` permits deliberate on-device entropy words but also contains broad language about absence of any disclosure path. That ambiguity needed resolution, not a passing checkbox.
6. `KK_DEBUG_LINK` defaults OFF; the emulator cache enables it. The debug handler is guarded by `DEBUG_LINK`. Actual shipping-artifact exposure requires a build/endpoint check. A confirmed debug-path disclosure is not proof of production compromise.

## Why I missed it

| Failure | What happened | Consequence |
| --- | --- | --- |
| Narrowed the invariant to the edited field | Reviewed `reset_get_int_entropy()` instead of following the entropy value through every representation and output | A BIP-39 encoding of the same value escaped the review |
| Stopped at the first phase | Tested the consent prompt and cancelled immediately | The test could not observe the later entropy-word disclosure |
| Used a fix-shaped oracle | Negative control proved the old raw field was exposed and the new raw field was hidden | It proved that change, not the broader confidentiality property |
| Failed to challenge the harness | Existing successful dice tests intentionally consumed entropy words over DebugLink | The same harness both demonstrated the leak and helped produce a green result |
| Treated merge provenance as sufficient confidence | Imported a predecessor fix, verified its direct behavior and preserved other interactions | The security claim introduced by that fix was not independently re-derived |
| Confused breadth with coverage | Reported large passing test counts, hashes, screenshots and repeated CI | Reproducibility was strong; the critical property oracle was incomplete |
| Overstated completion | Said implementation/verification were complete with local and hosted checks green | The status implied semantic closure that the evidence did not establish |

This is not merely a missing checklist item. The SOP already requires tracing invariants and matching evidence to scope. I failed to apply that requirement. The process should nevertheless make this specific failure harder to repeat.

## Proposed SOP changes

### 1. Require a security contract table before implementing a fix

For each sensitive value, record origin, observer/attacker, build variant, workflow phase, allowed outputs, forbidden outputs and equivalent representations. For this case the value is the device draw, not a protobuf field name; representations include bytes, words, derived values where reversible, logs and screen pixels.

Explicitly distinguish production transport, privileged diagnostic interfaces and intended on-device disclosure. Contradictory assumptions block closure. Do not retroactively redefine the policy merely to make the candidate pass.

### 2. Require an independent attempt to falsify every security closure claim

After implementing and testing, ask: if this exact fix is present, how else can the original invariant still fail? Trace another representation, a later phase, a second callback and a variant. This can be a separate review pass without another external review request. A larger model or more reviewers is not a substitute for this task definition.

### 3. Map changed security-sensitive entry paths to observed assertions

List every added timer renewal and rejection boundary, its actual dispatch path, positive progress case, stalled/invalid case and executed test ID. Shared-helper tests cover shared logic; they do not establish that every handler calls the helper at the correct point. This addresses the seven timer coverage findings and the body notes about real USB callback paths.

### 4. Tighten status language

Use separate statuses for implemented, targeted behavior verified, integration verified, adversarial contract checks verified, external review delivered, findings dispositioned and release accepted. A test count never substitutes for a property-level coverage statement. If the next phase or alternate representation is untested, record that exact gap.

### 5. Add stop rules for evidence churn

Once reproducibility and required gates are established, do not repeatedly polish or regenerate receipts while a semantic contract remains unchecked. Changes in predecessor code invalidate affected properties, even when the inherited fix already had a review or green CI.

## Proposed harness changes

| Component | Concrete requirement | How it catches this miss |
| --- | --- | --- |
| Ceremony phase driver | Advance through consent, every MIXED entropy page, dice entry, digest display, backup, abort and restart; observe before and after transitions | Prevents a consent-only test from representing the whole ceremony |
| Output policy oracle | Inspect all relevant debug/normal response fields and the availability of screen capture under the agreed trust model | Detects bytes hidden in one field but readable through words or pixels |
| Sensitive-data provenance | Use known test entropy supplied through an isolated test fixture; derive expected words for assertions without relying on the transport being tested to disclose the secret | Removes the circular dependence between the oracle and the prohibited output |
| Production configuration gate | Check the actual production configuration/artifact and verify debug message/endpoint behavior; explicitly cover full and Bitcoin-only | Separates diagnostic behavior from shipping exposure |
| Targeted mutation controls | Independently re-enable raw bytes, word exposure or forbidden screen capture; skip a phase observation; remove a handler's renewal | A surviving relevant mutation prevents closure of that property |
| Handler/transport boundary matrix | Exercise actual initial and continuation dispatch for each changed chain/reset path and actual main/debug USB receive callbacks, including short/error/no-data cases | Detects missing call sites and callback-specific regressions that helper-only tests miss |

Do not blindly suppress every debug field: the existing diagnostic protocol deliberately exposes sensitive state. First make the intended trust boundary explicit. If dice entropy is forbidden to DebugLink, protecting only `reset_word` is insufficient while its screen image remains available; the fixture and capture path must be reconciled too. If DebugLink is a trusted test-only observer, the documents must say so and production exclusion must be verified. Either policy needs explicit evidence, not an accidental mixture.

## Immediate priority

1. Reconcile the disclosure contract and reproduce the MIXED page path in a focused regression before changing the implementation.
2. Enumerate all equivalent output paths, including the screen image, and implement/test the agreed boundary.
3. Add behavior-level timer tests for all changed entry paths; verify invalid/polling traffic cannot renew.
4. Re-run the affected gates and revise the readiness claim only after the property matrix is complete.
5. Preserve the one-run review budget. A second Copilot request requires new owner authorization.

The concrete lesson: I should have proved what an observer can learn across the ceremony, rather than proved that a particular response field became empty.

## Remediation

The owner approved the stricter ceremony privacy contract. See
[P02 internal round 2](P02-INTERNAL-ROUND2-20260923.md) for implemented SOP,
harness, code changes and the separate validation/review statuses.
