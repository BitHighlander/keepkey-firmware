# Firmware-only scope repair, 2026-09-09

## Decision and candidate identities

The storage durability remediation crossed the bootloader exclusion through
shared find_active_storage(), generation/CRC metadata and the protection-marker
handoff. B02 scope acceptance is withdrawn. Restore the pre-durability protocol
instead of expanding the bootloader audit. No develop merges or Copilot requests.

| Product | Pre-durability source | Corrected audit head / PR | Canonical status |
| --- | --- | --- | --- |
| 7.14.2 | 02349bf77 | 8c13ed24f / #754 | fa2898664 still contains withdrawn B02 until validated correction lands |
| 7.14.3 | 8ef50c146 | 0fe01bc1b / #755 | 47eae604e unchanged; corrected staged assembly pending |
| 7.15 | 77f50c016 | bd5e509cd / #756 | f20c2497a unchanged; corrected staged assembly pending |

For each corrected head, lib/board/memory.c, include/keepkey/board/memory.h,
include/keepkey/board/keepkey_board.h and tools/{bootloader,blupdater,bootstrap}
match its named pre-durability predecessor exactly. lib/board/keepkey_flash.c,
unittests/board/board.cpp and storage_passphrase.cpp are also restored to that
predecessor. Firmware storage.c matches except the independently retained
uint32_t version classifier on 7.14.3/7.15. No pending-record or snapshot-hook
implementation remains. Signing fixes and unrelated firmware hardening remain.

7.14.3 retains its emulator-only CRC model correction; the hardware branch is
unchanged. The earlier emulator sector erase correction remains on all products.
Host pins remain unchanged: CRC fixture support is optional and all existing
migration tests also pass with restored unframed storage. P03-011 and its native
high-bit version regression remain. P03-009 and P03-010 no longer apply to this
candidate's removed framed/pending format.

## Shared-consumer boundary

This is a scoped restoration, not a claim that every historical shared-library
change yields an identical bootloader binary. Beyond the restored storage paths,
the staged histories include shared messages/USB rejection and buffer cleanup,
7.14.3 debug confirmation acknowledgement, and emulator-only flash/CRC/UDP work.
Those retain their firmware findings and tests; the release-wide consumer audit
must not infer bootloader acceptance from them. No new bootloader consumer changes
were made to implement this repair. No bootloader artifact is published or flashed.

## Unresolved original finding

P03-STORAGE-POWER-INTERRUPTION: the legacy erase-before-replacement commit window
remains a confirmed, unresolved finding. The coupled durability remediation is
excluded by owner direction and preserved on historical audit branches #730–#732,
with snapshot/replay evidence #746–#748. This is an explicit remediation deferral,
not a fix, risk waiver, or permission to declare the release clean. Reconsider any
firmware-only solution as a separate bounded proposal preserving the excluded
bootloader contract. P03-010's introduced pending-version defect disappears with
the removed feature; P03-011's pre-existing unsigned-classification fix stays.

## Validation

Fresh serial builds and native suites pass on all corrected source trees:
7142 firmware 163 / board 19; 7143 full 198 / board 17, BTC 98 / board 17;
715 full 508 / board 14, BTC 100 / board 14. Removed counts correspond to the
withdrawn durability tests; no applicable failure was skipped.

Full pinned-host suites pass: 7142 434/47; 7143 full 537/218 and BTC 309/446;
715 full 727/30 and BTC 314/443 (pass/skip). Existing skip counts are unchanged.
Logs: /private/tmp/<variant>-scope-repair-{build,firmware-unit,board-unit}.log,
<variant>-scope-repair-host-preflight.{log,xml}. Exact-head CI/ARM and artifact
verification remain pending; predecessor CI cannot certify these corrections.

Canonical corrections will be forward commits after validation, retaining the
withdrawn work in history and independent audit branches. No force push or develop
merge is necessary. None of the three whole-release audits is complete.
