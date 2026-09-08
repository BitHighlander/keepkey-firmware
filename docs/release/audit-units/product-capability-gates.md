# Execute the actual canonical 7.15 capability contract

The host suite inherited RC18-based version gates that skipped implemented 7.15
requirements. The pinned companion now exercises provider additivity, runtime
trust teardown, Solana LUT attestation, omitted EVM chain IDs, recovery word
validation, and the entropy audit budget. The report requires Solana LUT coverage
from 7.15. The selected suite passes 154 tests, with one intentionally RC18-only
case skipped. The entropy and three liquidity cases also pass.

The old blanket Uniswap emulator skip was stale. Add/remove liquidity vectors
complete with explicit AdvancedMode authorization and retain their deterministic
signature expectations. Unlimited approval is disabled by the current product
policy, so its legacy vector now requires the exact terminal refusal rather than
a signature. No firmware behavior changes are included in this validation unit.

Remaining expected skip classes are alternate build/transport coverage, explicitly
disabled structured EIP-712, unimplemented structured TRON input and XRP memo,
legacy error-policy variants, the emulator PIN-timeout limitation, and the absent
burned-storage-version case. Full native and host runs, CI variant coverage and
physical-release limitations must be recorded separately. Local owned-emulator
power-cycle checks cover lifetime evidence unavailable to separate-container CI.
