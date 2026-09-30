# P06-005: reject unsupported Ripple memo on full 7.14.3

Base: 0292e7fa2 (permanent displayed-address host assertion pin).

The pinned protocol exposes RippleSignTx.memo, but this release's full
serializer has no memo implementation. Replaying the original skipped host
memo assertion signs successfully without the supplied memo and fails the
serialized memo suffix assertion. Silently dropping a routing memo is not an
acceptable success for an unsupported feature.

Reject nonempty memos with Failure_SyntaxError before PIN authorization or key
derivation. Empty/absent memo behavior is unchanged. Memo support stays in 7.15;
Bitcoin-only does not expose Ripple. 7.14.2's pinned protocol has no memo member,
so this guard cannot simply be copied there.

The rejection host test plus ordinary signing and invalid-fee tests all pass.
All 190 full native tests pass; Bitcoin-only recompilation succeeds (handler
excluded). Reproduce via P00 rehearsals/ripple_unsupported_memo.py against
build-native-full/bin/kkemu. It owns isolated storage and forces UDP.

Permanent host CI coverage, combined integration and full audit remain pending.
