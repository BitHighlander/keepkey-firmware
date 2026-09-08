# Revoke signing at low-level storage authorization boundaries

Reconcile the previously audited `e601d2df8` teardown behavior. Direct callers of
`session_clear_impl(..., true)` bypassed the public wrapper and left Bitcoin
signing active. Wiping storage and clearing keys also now abort active workflows.
A soft session clear preserves signing, as required by existing authorized flows.

The regression starts a real signing session and exercises both low-level paths.
The FSM suite covers signing-state accessors, Zcash abort, and runtime metadata
signer revocation at the relevant boundaries. All focused FSM, storage, and
passphrase-transition tests pass in the reconstructed 7.15 product.

Final combined product validation remains required.
