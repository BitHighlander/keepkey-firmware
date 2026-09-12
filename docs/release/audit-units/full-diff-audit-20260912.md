# Full-diff audit of the 7.14.2 candidate

Every changed file of this candidate was reviewed against its base, in
subsystem-sized chunks, by reviewers that had the base version, the current
file and the ability to grep callers. Findings rated P1 or P2 were then
re-checked by three independent reviewers along separate lines of attack --
is the path reachable, does the consequence matter on a shipped release, is it
already covered -- and a finding survived only when at least two of the three
failed to refute it.

Status of each finding below:

- **FIXED** -- corrected on this line, with a test where a seam exists. Where
  a control build was possible, the unfixed code was built and the test
  confirmed to fail against it; where no seam exists, the test or the commit
  message says so rather than implying coverage.
- **refuted on re-check** -- the re-check found the claim does not hold on
  this head. No change made.
- **open** -- real, not addressed in this pass. Each is named so a reader can
  weigh it rather than discover it.
- **triaged by reading** -- P3, read and judged not to warrant a change in a
  release pass. Not individually re-checked by the three-reviewer process.


Counts: 31 fixed, 5 refuted on re-check, 0 open, 9 triaged by reading (45 findings touching this line).


## Fixed

- **F001** (P2, `lib/firmware/app_confirm.c`) — Removing kk_strupr(title) does not show proto verbatim: layout uppercases every title
- **F002** (P3, `include/keepkey/board/layout.h`) — layout_debuglink_watermark() deleted but bootloader still calls it under DEBUG_LINK
- **F004** (P3, `lib/firmware/eos.c`) — AdvancedMode gates are tested only through identity-function seams
- **F005** (P1, `lib/firmware/recovery_cipher.c`) — Auto-lock now aborts an in-progress recovery after 10 cumulative minutes regardless of host activity
- **F006** (P2, `lib/firmware/fsm_msg_ripple.h`) — New RIPPLE_MAX_DROPS check refuses XRP payments above 100,000 XRP that release firmware previously signed correctly
- **F008** (P2, `unittests/board/board.cpp`) — Board.Crc32CoversTheFinalByteOfTheV17Record claims a storage_commit CRC fix that is not in the tree; the last byte of the V17 record is still outside the commit-verify CRC
- **F009** (P2, `lib/firmware/storage.c`) — Every PIN entry now aborts the staged setup ceremony; dry-run recovery fails on PIN-protected devices
- **F010** (P2, `lib/firmware/mayachain.c`) — MAYAChain deposit amounts now render at 0 decimals (1 CACAO shows as 10000000000 MAYA.CACAO)
- **F011** (P1, `lib/firmware/home_sm.c`) — Auto-lock now aborts an actively streaming signing/recovery session because idle_time is never reset by message traffic
- **F012** (P3, `lib/firmware/home_sm.c`) — Auto-lock during a Bitcoin/Ethereum stream shows the screensaver for one second, then bounces back to the home screen
- **F013** (P3, `lib/firmware/solana.c`) — Priority-fee screen understated the ceiling: builtin instructions get 3,000 CU, not the 200,000 the quote assumed
- **F014** (P3, `unittests/firmware/fsm.cpp`) — Auto-lock during a stalled signing un-blanks the screen one tick later; test asserts only the signing flag
- **F015** (P3, `lib/firmware/ethereum_contracts/thortx.c`) — THORChain EVM deposit: every structural memo refusal is reported as a user cancel and is un-signable on any setting
- **F016** (P2, `lib/firmware/ethereum_contracts/thortx.c`) — Native-asset THORChain deposit screen shows the calldata amount, which the router ignores; msg.value is what moves
- **F017** (P2, `lib/firmware/ethereum_contracts/thortx.c`) — Deposit-shaped calldata to ANY contract on ANY chain is clear-signed without AdvancedMode; the pinned pyk test that claims otherwise passes for an unrelated reason
- **F018** (P3, `lib/firmware/ethereum_contracts/thortx.c`) — amountStr[41] cannot hold an unknown-token raw amount >= 1e28, so common memecoin deposits are refused as 'cancelled'
- **F019** (P3, `lib/firmware/ethereum_contracts/zxliquidtx.c`) — removeLiquidityETH screen labels the LP-token `liquidity` word with the pool token's ticker and decimals
- **F020** (P3, `lib/firmware/fsm_msg_ethereum.h`) — process_ethereum_xfer leaves the derived to_address_n private key in the shared scratch on its error returns
- **F021** (P3, `lib/board/layout.c`) — DEBUG_LINK device build no longer links: bootloader still calls deleted layout_debuglink_watermark()
- **F023** (P2, `lib/board/confirm_sm.c`) — confirm_address_with_custom_layout keeps a renderer that silently drops the tail of addresses longer than one row; the comment's wrap claim is false
- **F024** (P3, `lib/board/confirm_sm.c`) — Mnemonic rows copied into an un-zeroed stack buffer in confirm_constant_power_subpage_take()
- **F029** (P3, `.gitmodules`) — python-keepkey tracking branch does not contain the pinned commit; --remote silently rewinds the pin (raised on 7.14.3; this line carried the same defect)
- **F035** (P3, `lib/firmware/ethereum.c`) — TRANSFER amount screen can show a stale WAN ticker left by an earlier request (raised on 7.14.3; this line carried the same code)
- **F100** (P2, `include/keepkey/board/layout.h`) — layout_debuglink_watermark() removed on 7.14.2/7.14.3 but its bootloader call site was left behind — the DEBUG_LINK device build no longer compiles, and debug-link firmware is no longer visibly marked
- **F106** (P2, `docs/release/7.14.2-COMBINED-CANDIDATE.md`) — Release docs stop before the last five commits: host pin claim is false at head and a signing-policy change has no receipt
- **F114** (P3, `.github/workflows/ci.yml`) — Presign evidence stamps a hard-coded python-keepkey PR URL that no longer matches the pinned submodule, and nothing verifies it
- **F155** (P2, `unittests/board/board.cpp`) — Crc32CoversTheFinalByteOfTheV17Record asserts a 2572-byte flash_temp that 7.14.2's storage.c does not have
- **F196** (P3, `lib/firmware/signing.c`) — sig_with_hashtype[73] is one byte too small for the size it is written for, so the OOB write it was added to remove is only prevented by the separate cap (raised on 7.15; this line carried the same code)
- **F216** (P2, `lib/firmware/ethereum_contracts/thortx.c`) — 7.14.2 leaves thor_isThorchainTx unpinned: any mainnet contract with the deposit selector gets the THORChain clear-sign UX and suppresses both the value screen and the AdvancedMode gate
- **F234** (P2, `docs/release/7.14.2-COMBINED-CANDIDATE.md`) — Candidate receipt still claims storage durability (preserve-old-record / generation+CRC framing) that was removed from the tree
- **F235** (P2, `docs/release/7.14.2-PRODUCT-ASSEMBLY.md`) — Every recorded host/python-keepkey pin is contradicted by the tree; the RC's actual pin is in no release document


## Refuted on re-check

- **F003** (P3, `include/pb.h`) — ONEOF and REPEATED_FIXED_COUNT field macros not updated for the new bytes_capacity member
- **F007** (P3, `lib/firmware/signing.c`) — Multisig quorum and 72-byte signature gates have no native test; the only test was deleted and never restored
- **F022** (P3, `lib/board/confirm_sm.c`) — Pager splits tokens (amounts/addresses/words) across pages at arbitrary character boundaries
- **F105** (P2, `docs/release/7.14.2-COMBINED-CANDIDATE.md`) — Release receipt still credits the candidate with storage-durability behavior that was removed from the tree
- **F236** (P3, `docs/release/7.14.2-COMBINED-CANDIDATE.md`) — New signing-policy refusal (invalid multisig quorum) is in the RC but in no release document

## Triaged by reading (P3)

- F025 (`include/pb.h`) — pb_field_t gained bytes_capacity but PB_ONEOF_*/PB_ANONYMOUS_ONEOF_*/PB_REPEATED_FIXED_COUNT initializers were not extended (descriptor fields shift)
- F042 (`unittests/firmware/thorchain.cpp`) — Oversize-memo fixture is rejected by the printable-text check, not by the 256-byte length cap it claims to test
- F115 (`.github/workflows/release.yml`) — Base-image cache in release.yml `test` is dead after the digest pin: docker load cannot restore a repo digest
- F116 (`.github/workflows/ci.yml`) — protoc is restored from a mutable Actions cache with no checksum, unlike every other pinned download in this diff
- F117 (`.github/workflows/mirror-base-image.yml`) — New mirror workflow documents a ci.yml consumer and fallback that do not exist, and cannot mirror the digest-pinned base
- F118 (`scripts/emulator/python-keepkey-tests.sh`) — Retry-staleness guard clears only screenshots; stale junit.xml from a previous run survives in the shared volume
- F119 (`.github/workflows/release.yml`) — Draft release no longer attaches the bootloader binary
- F238 (`include/keepkey/board/layout.h`) — layout_debuglink_watermark() deleted on 7.14.2/7.14.3 while the bootloader still calls it — KK_DEBUG_LINK device build fails, and the debug-build indicator is gone
- F240 (`docs/release/7.14.2-COMBINED-CANDIDATE.md`) — 7.14.2 receipt asserts the host pin is unchanged while the release head advances it 20 commits

## Re-checked at head

- F238 — `layout_debuglink_watermark()` is declared in `layout.h` and defined in
  `layout.c` at this head, so the DEBUG_LINK device image links again. The
  finding was raised against the head that deleted it.
