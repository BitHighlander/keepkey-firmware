# Block 10 bounded completion handoff

The active thread goal authorizes three initial Copilot requests, one split into
at most two units if needed, then three requests per resulting unit. Stop on
unsuccessful exhaustion. No recursive split. This supersedes the prior prohibition
only after agents 1 and 2 finish and their final changes are integrated and audited.
No requests have been made by agent3. Canonical machine ledger is
`docs/release/audit-claims/715-10/review-budget-20260927.json` in the main repository.

## Current checkpoint and required next work

The prior combined report is a frozen snapshot at e42ed4687ece35a6fc7ba6cd5fe9f015a63b4bf6,
with tests executed on runtime source 6309633ec6eb9a6a64e8173dff949c3f8e1c5166.
It is not the final combined audit or inventory. Agent2's later documentation-only
historical reconciliation ca3b2d8d6 is merged. The workflow now identifies Python
PR #121, whose live head 41af909341965c81b8afadd38f299d6f929089af matches the gitlink;
the former #120 link identified the previous companion. This affects generated
report provenance, not runtime code, and needs final hosted artifact validation.

1. Obtain completed immutable agent1 and agent2 handoffs. Agent1 is currently
   preparing two review units for six report/preflight findings. Do not consume
   its mutable working tree as accepted source or issue reviews on its behalf.
2. Merge final predecessors into the isolated integration branch. Review all
   source, dependency, workflow and receipt differences; preserve the separate
   INT-09-002 account-slot parser fix and both-product regressions.
3. Validate affected gates using genuine combined XML, then complete final
   native/host/ARM/resource and preflight obligations with explicit carry-forward
   for unchanged code. Reconcile all owned skips and negative controls.
4. Freeze source/PDF/evidence with the final complete immutable inventory and
   inspect rendered pages. Confirm each finding has an evidenced disposition.
5. Stage a scoped code-bearing block 10 PR against the final block 9 predecessor;
   preserve existing historical PRs and avoid force-push. Check live adjacent
   base/head, CI and artifact identities before spending the first review request.
6. Use the registered-request ledger for the authorized review loop. Resolve
   findings only after verified fixes, read every review body/inline thread, and
   require a fresh current-head clean review with zero unresolved threads. Count
   any companion request in the applicable budget. Split only once if required;
   retain complete coverage and finding mappings. Stop when the allowed budget
   fails, rather than silently creating more units or requests.
7. Update the canonical master/claim and final handoff after the completion audit.
   Local audit/review completion does not grant physical-device acceptance,
   product promotion, a develop merge, or release publication.
