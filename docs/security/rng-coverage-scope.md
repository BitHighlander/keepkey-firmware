# RNG coverage scope, and the bootloader gate

Carried out of `rc28-open-findings-handoff.md` when that document was dropped
from the 7.15 release PR. The handoff was a working record -- per-PR state,
build recipes, findings already closed -- and none of that belongs in a
release. These two sections do: shipping code points at the first, and the
second is a hard gate on a release that has not happened yet.

Cited from `include/keepkey/rand/rng_health.h` and `lib/firmware/storage.c`.

**Read the STOP section as a forward gate, not a description of 7.15.** It was
written when `random32()` consulted the RNG verdict; that was descoped, and in
this tree `random32()` does no such check and cannot abort. `tools/bootloader/`
is byte-identical to develop apart from one include-path line. The hazard needs
BOTH the checked path made default AND a bootloader cut — neither is in 7.15.
## Post-7.15 security project: RNG coverage, RedPallas, degraded-RNG recovery

These three are one project, not three tickets, because each answer changes the
others. All were built during RC28 and deliberately descoped.

**1. Coverage is opt-in, and the list is short.** #366 ships six draws that
call `random_buffer_checked()` by name (see `rng_health.h`). Everything else,
including all of `deps/`, is unchecked exactly as on develop. A new key-material
draw inherits nothing.

**2. RedPallas is the reason that matters.** `redpallas.c:281` draws the Orchard
signing nonce with a bare `random_buffer()`, and `s = r + c*rsk` means two
signatures sharing `r` disclose the spend authorization key. Uncovered on
develop and uncovered in 7.15 — not a regression, but the highest-value gap.

**3. Inverting the default was built and rejected — read this before rebuilding
it.** Making `random32()` checked covers every dependency by construction, and
the attempt failed for reasons that are properties of the system, not of the
patch:

- ECDSA blinding runs on the VERIFY path. `curve_to_jacobian()` randomizes a Z
  coordinate on every point operation, so `ecdsa_verify_digest()` would abort on
  a failed verdict — and `keepkey_main.c:177` calls `signatures_ok()` before
  `kk_board_init()`. The firmware would not boot, with no message.
- Making blinding draw raw does NOT fix that. `generate_k_random()` loops
  `while (bn_is_zero(k) || !bn_is_less(k, prime))`, so a source stuck at zero
  hangs instead of aborting.
- The raw-blinding patch is only safe while `USE_RFC6979=1`. Under a different
  configuration the same switch controls the real ECDSA signing nonce. A
  comment is not a guard, and `rng_health.c` opens by warning against exactly
  this class of assumption.
- The bootloader reaches the same code through `signatures_ok()`, so any of
  this in a bootloader is a brick with no recovery path.

**The prerequisite is a defined degraded-RNG recovery mode** spanning firmware
and bootloader crypto: what a device does when its generator has failed, such
that it still boots, still verifies firmware, still signs with RFC6979 (which
needs no entropy) to move funds out, and still refuses to mint new key material.
Until that exists, inverting the default converts a degraded device into a dead
one.

**The rejected crypto branch has been deleted.** `BitHighlander/trezor-firmware`
carried `fix/blinding-draws-raw`, which made blinding draw raw behind a
`KK_BLINDING_RANDOM32` macro. It was removed rather than left unmerged so that
nobody repins to it later on the strength of its commit message, which argued a
case the loop condition above disproves. The approach is recorded here; the
branch is not.

---

## STOP — hard gate on the NEXT BOOTLOADER RELEASE

**Not an RC28 item. Do not fix it in an RC28 PR. Do not build and ship a
bootloader from this tree until it is fixed.**

`tools/bootloader/main.c` draws its stack canary through `random32()`, which
#366 made consult the RNG health verdict and `abort()`. The bootloader also
reaches nothing else through the gate — `signatures_ok()` was cleared by the
crypto-fork blinding patch — but that one call is enough:

> A device whose RNG has failed would abort inside the bootloader. It could not
> verify firmware, boot, or accept a replacement image. That is an
> unrecoverable brick, in the one component that exists to recover from
> everything else.

**Why it is not being fixed now.** A firmware release does not update anyone's
bootloader; devices keep the one they have. So this cannot reach an RC28 user,
and the fix would mean shipping bootloader changes reviewed under a firmware
deadline — landing in a bootloader release months later with the reasoning long
gone. Bootloader edits were reverted for exactly that reason;
`tools/bootloader/main.c` is byte-identical to develop.

**What to do when the bootloader is next cut.** Either give the canary
`random32_raw()` — it protects nothing an attacker can predict their way past —
or build kkrand for the bootloader with the gate compiled out so it cannot
return by someone adding a caller. Both were prototyped and reverted; see the
history of this branch. Then check the built ELF, because "nothing calls it" has
already failed twice in this module:

    arm-none-eabi-objdump -d bin/bootloader.elf > /tmp/bl.asm
    awk '/^[0-9a-f]+ </{fn=$2} /bl.*<random32>/{print fn}' /tmp/bl.asm | sort -u
    # must print nothing

---
