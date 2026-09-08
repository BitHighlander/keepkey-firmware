# P01-003: firmware-only packaging with accurate manifest names

Product: 7.14.3. Base: 747e800fa. Origin: existing release-workflow behavior.
Status: reproduced and fixed; canonical integration pending.

The packaging step selected bootloader.bin from the audited build and included it
in the firmware release's wildcard assets. The firmware signing checklist does
not define a bootloader rollout; the current 7.15 pipeline explicitly excludes
bootloaders from firmware publication. Keep that same product boundary here.
Separately, hashes were emitted using unversioned names before renaming the
binaries, so HASHES named files that the draft release never attached.

Remove the bootloader mapping and rename, restrict staged binary/ELF assets to
firmware names, and rename firmware before generating HASHES. Preserve the exact
presign evidence and audited source/binary checks already in this workflow.

Rehearsal executes the actual prepare, rename, hash and asset-copy steps over
synthetic audited inputs that include a bootloader. Before the fix the prepare
step copies bootloader.bin; the step order also hashes before renaming. After
the fix only firmware/evidence assets are staged, every manifest filename exists,
and each whole-file SHA-256 matches its staged bytes. Both 7.14.3 variants and the
7.14.2 full variant pass. Only GNU stat's filesize spelling is adapted when this
rehearsal runs on Darwin. actionlint and diff checks pass. No tags, signing,
publication or flashing were performed. The generated manifest explicitly labels its hashes as unsigned presign evidence;
the release checklist requires signature verification and manifest regeneration
from the final signed binaries. Those are manual release gates, not checks
claimed as executed by this presign packaging rehearsal.
