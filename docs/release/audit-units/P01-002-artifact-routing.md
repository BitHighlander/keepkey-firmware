# P01-002: route each 7.14.3 audited ARM variant into packaging

Affected source: de0251bbdb286ccdc786a5513ebc94bddd890e3f,
.github/workflows/release.yml. Origin: existing assembly integration defect.
Status: reproduced and fixed; canonical integration pending.

The evidence step emits arm_full_artifact and arm_bitcoin_artifact. The job
exports only arm_artifact, which is never emitted. Both matrix packaging jobs
therefore receive an empty artifact name rather than their validated ARM inputs.
Ordinary firmware CI does not execute the tag-triggered packaging workflow.

Export both real outputs and select the correct one using each matrix row's
arm_output key. Keep exact-commit evidence verification and the two-variant
requirement; do not use a fallback that could substitute a full artifact for a
missing Bitcoin-only artifact.

Validation executes the actual embedded artifact-selection Python with synthetic
artifact metadata, then resolves producer/job/matrix bindings. Before the fix,
the valid fixture fails on the unproduced arm_artifact output. After the fix,
both variants resolve their own exact names. Missing, duplicate and expired
variant fixtures all refuse. actionlint (including shellcheck) and diff checks
pass. No tag or release was created.

7.14.2 emits and consumes its single arm_artifact consistently. 7.15 uses a
separate build workflow rather than this audited-input routing. This finding is
specific to the 7.14.3 two-variant integration.
