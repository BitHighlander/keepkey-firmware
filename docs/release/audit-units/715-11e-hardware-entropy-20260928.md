# Block 11e: verified first-boot hardware entropy

Date: 2026-09-28. Auditor: Claude (Opus 5.5). Isolated checkout: `/private/tmp/kk715-11e`. Immediate target: fork `audit/715-11d-future-storage-guards-20260928` at `0c08ce9ef4869269922c4c0b62f7ac069d7c81ea` (PR #883). Carried unit content: commit `63789e539`, the seven 11e paths unchanged from cumulative PR #877 head `5334f77c351373a900d67d908a467e5f3e08b551`. Audit repair: commit `6fb90ed71`. Final containing head and hosted CI belong in the PR body.

## 1. Scope and source reconciliation

`flash_collectHWEntropy()` runs once per boot in signed firmware, before privileges drop and before `kk_board_init()`. When the OTP randomness block is unlocked it draws 32 bytes, programs them, and locks the block forever; the bytes feed the PIN KDF salt through `flash_readHWEntropy()`. The carried unit (Copilot finding 4118361277) makes every failure halt before DRBG/storage can use erased or partial OTP bytes: a rejected draw, a rejected or unverified write, a failed lock, or a failed read of a locked block. Unsigned firmware keeps its documented fixed `0x3C` entropy. The emulator branch is unchanged.

The seven paths match the split map exactly: `lib/board/keepkey_flash.c`, `unittests/board/CMakeLists.txt`, the two `hardware_stubs` headers, and `hw_entropy.cpp` / `hw_entropy_probe.{c,h}`. The probe compiles the real device branch of `keepkey_flash.c` on the host, with only register, OTP, RNG and halt dependencies substituted.

## 2. Audit finding: a halted first boot could never boot again

OTP programming only clears bits. The carried code halted when verification or the lock failed, but left the block unlocked with whatever bytes had been programmed. The next boot saw an unlocked block, drew *fresh* entropy, and programmed it over the non-erased bytes. The result is the AND of the two draws, so verification failed and the device halted again, on every later boot, for every signed firmware containing the guard. Triggers: power loss between programming and lock, a partially programmed block, or a lock that did not take effect. The bootloader is unaffected, so this is loss of the firmware rather than a hard brick, but no signed update could recover it.

The unit tests missed this because the probe modelled an OTP write as `memcpy` and every test booted exactly once.

Repair (`6fb90ed71`): on an unlocked block, read it first, keep bytes already programmed, and program only erased (`0xFF`) bytes, one byte at a time. Then verify the whole block, lock, and verify the lock as before. Kept bytes came from an earlier checked draw. Security is unchanged: code able to program OTP before the lock already runs privileged. The probe now ANDs bits per byte like the device, a reboot helper carries OTP and lock state across boots, and two tests cover recovery:

- `ProgrammedButUnlockedBlockIsKeptAndLocked`: a fully programmed, unlocked block is locked as is, with zero writes.
- `InterruptedFirstBootCompletesOnNextHealthyBoot`: after a partial write, a rejected lock, or a dropped lock halts the first boot, the next healthy boot completes and locks (16, 0 and 0 writes).

## 3. Verification

Local Docker is unresponsive on this host, so the full emulator unit suites and cppcheck could not run locally. They run in the hosted CI recorded in the PR (`make xunit` emits `board.xml`). The entropy tests were compiled natively from this checkout's pinned sources with `-Wall -Werror` and linked against pinned googletest.

| Local check | Result |
| --- | --- |
| `HardwareEntropy` suite at `6fb90ed71` | 9 of 9 pass |
| Negative control: same tests, unfixed `keepkey_flash.c` from `5334f77c3` | 4 fail: both recovery tests and the two updated write/read counts |
| clang-format 20 on changed files | Clean |
| Preflight (`PREFLIGHT_BASE=0c08ce9ef`) | All checks pass except cppcheck, which was not run (Docker unresponsive) |

Evidence archive `715-11e-controls-20260928.tgz` binds the fixed and control JUnit XML/logs and the preflight log. Physical-device behavior is not claimed. The recovery path is exercised only in the host probe; hardware OTP programming faults were not injected.
