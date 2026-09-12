# Revoke signing at low-level storage authorization boundaries

Reconcile audited e601d2df8 behavior: direct low-level PIN revocation, wallet wipe,
and key destruction abort active workflows. Soft session clearing preserves an
authorized signing flow. The reproducer on 7.15 showed signing remained active
before this shared fix. Both paths are tested on this exact 7.14.2 candidate.

All 39 focused FSM, storage, and passphrase tests pass. This native build uses
PB_NO_PACKED_STRUCTS for host compatibility; ARM and integration validation remain
required before updating the canonical product again. Prior canonical CI success
at c71f2a026 does not close this newly reconciled teardown gap.
