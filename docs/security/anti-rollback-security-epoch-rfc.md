# RFC: OTP-backed firmware security epochs

Status: design required; no production implementation is authorized by this
document.

## Security invariant

After a device accepts an official firmware image in security epoch `N`, no
officially signed image with an epoch lower than `N` may be installed or booted.
A power loss must leave the device able to boot either the previous accepted
image or the new accepted image; it must never advance the floor before the new
image has passed all integrity and signature checks.

Semantic versions are not the monotonic value. Patch and release-candidate
numbers are allowed to move independently; the security epoch advances only
when an older signed image must be permanently revoked.

## Why ordinary flash is insufficient

The bootloader can erase and rewrite application flash, and the attacker in
this threat model is deliberately installing an older valid image. A floor
stored beside mutable firmware or normal storage can be restored with the old
image and does not establish monotonicity.

The STM32F2 OTP region exposes sixteen 32-byte blocks. Current source assigns
manufacturing data to block 0, model data to block 1, and hardware entropy to
block 3. Before choosing any remaining block, manufacturing images and all
shipping board revisions must be audited; absence of a source reference is not
proof that a factory process never programmed it.

## Proposed representation

Reserve one audited OTP block as a 256-step unary counter. Epoch `N` is encoded
by programming the first `N` bits from 1 to 0. The decoded epoch is the length
of the contiguous programmed prefix.

Reject the OTP state if a programmed bit appears after an unprogrammed bit.
This catches torn or non-canonical values instead of interpreting them as a
lower floor. Do not lock the block after each update; the OTP 1-to-0 property is
the monotonic mechanism.

The signed application metadata needs a dedicated epoch field covered by the
existing firmware signatures. Reusing undocumented `meta_flags` bits is only
acceptable after confirming every bootloader generation parses and signs the
same bytes. A new metadata format with an explicit compatibility version is
preferred.

## Update state machine

1. Parse the candidate metadata without trusting it.
2. Verify image bounds, hash, and the complete 3-of-N signature policy.
3. Decode the current OTP floor and reject malformed OTP.
4. Reject `candidate_epoch < floor` before erasing the installed image.
5. Write the candidate while preserving the existing storage-protection
   contract.
6. Re-read and verify the flashed image from flash.
7. If `candidate_epoch > floor`, program and verify each required OTP bit.
8. Install the application magic only after image and epoch verification.
9. At every boot, reject an installed image whose epoch is below the OTP floor.

Unsigned/user-approved firmware must never advance the official floor. The RFC
must decide whether such firmware may boot at all once a floor is active; either
choice needs an explicit user-facing recovery story.

## Fault-injection requirements

- Accumulate signature results and validate sentinels as the current verifier
  does; do not add a single skippable epoch branch after signature validation.
- Read the OTP floor more than once with independent control-flow checks before
  an irreversible write.
- Verify every programmed bit and halt on disagreement.
- Ensure a glitch cannot turn malformed OTP into epoch zero.
- Include the epoch in the host-visible bootloader features and release
  evidence so operators can diagnose state without trusting firmware.

## Compatibility and rollout

This requires a bootloader campaign. Application-only deployment cannot protect
devices whose installed bootloader ignores epochs.

1. Inventory bootloader versions in the field and their update paths.
2. Prototype with a non-production test block on sacrificial devices.
3. Ship epoch-aware bootloader code with floor zero and no OTP advancement.
4. Confirm update, downgrade, unsigned-firmware, storage-preservation, and
   recovery behavior on each hardware revision.
5. Audit factory OTP contents and permanently reserve the selected block.
6. Only a later release may advance epoch one.

## Required tests

- candidate epoch below/equal/above floor;
- malformed non-contiguous OTP patterns;
- exhausted 256-step counter;
- signature failure with a higher claimed epoch;
- unsigned firmware with a higher claimed epoch;
- hash mismatch after flash write;
- power loss before erase, during image write, after image verification, during
  OTP programming, and before application magic installation;
- boot of an installed image below the floor; and
- recovery-mode behavior when no eligible application remains.

The implementation PR must include a negative control showing that removing the
floor comparison permits a signed lower-epoch image.
