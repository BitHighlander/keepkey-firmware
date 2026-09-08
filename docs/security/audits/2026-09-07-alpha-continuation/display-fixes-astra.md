# Display audit fixes (independent verification and implementation)

Base: ed65a0ce9 with concurrent authorized audit fixes. Own-file pre-fix snapshots are under `/private/tmp/display-before/` with original relative paths. No builds or commits performed; root serializes builds. clang-format 20 and git diff --check passed before the final additional pager test (that test was also formatted).

## Findings

- C3-025 / C3-036 / C3-069 CONFIRMED. QR-side address bodies use x=69, y=27 and 140px width (Osmosis actually uses 160px); font height10 + padding4 allows only two complete rows. Nano starts at20 and gets three rows, but its full 65-character widest-case address also overflows. Host validator, Hive STM, TON and other long addresses reach these wrappers. Existing generic completeness check only covers the standard layout. Added a real draw_string_fits probe for the actual custom geometry, and a wrapper that falls back to standard paged text if incomplete. Custom QR layouts are never paged, so QR fragments cannot be presented as full addresses. XPUB uses the same protection. Overlong source strings are refused before formatting, rather than handing a truncated copy to the generic source-warning path.
- C3-039 CONFIRMED independently. Wide 106-character UA exceeds three 225px rows at y14. Added confirm_zcash_address_text(desc,address), used by confirm_zcash_address before its full QR step. ROOT MUST replace the direct custom-layout call in fsm_msg_zcash.h with this wrapper (root notified). It falls back to the full standard text pager and cancellation on any page refuses approval.
- C3-028 CONFIRMED. nano_bip32_to_string used a 27-bit mask despite accepting 31-bit hardened account indexes. Mask corrected to 0x7fffffff. No derivation/policy changes.
- C3-067 CONFIRMED by inspection of recovered finding, OUTSIDE FILE OWNERSHIP; root notified to fix signed_metadata.c/token formatter and tests. No changes made to metadata.
- C3-070 CONFIRMED independently. layout_has_icon flag persists after icon confirmation and U2F bypasses confirm_screen while measuring BODY_WIDTH. layoutU2FDialog now resets to no-icon geometry before both measuring and drawing.
- C3-071 CONFIRMED independently. Seed prefix copies remain on stack across return; page_body_confirm's one-page return and page-cap path bypassed full cleanup. Seed probe is now scrubbed on all exits after a copy. Every generic pager return routes through cleanup of both buffers. Added final fits guards before all page displays, including the one-page case: page_take can return1 for an impossible glyph and that must fail closed rather than approving a blank page. No static SRAM added.
- C3-072 CONFIRMED for unknown-ID collapse and unconditional assumed divisibility. Property3 indivisibility was NOT independently established through primary registry data (registry endpoints returned403), so no MAID scale is asserted. Per root preference, protocol-defined divisible OMNI/tOMNI preserve readable amounts with checked bn_format_uint64 and explicit numeric property ID. All remaining Simple Send properties show the exact numeric ID, full integer raw amount, and `Divisibility unknown`; they never imply decimals/ticker. Unsupported messages retain exact byte review. Valid Simple Send decoding now checks the full marker/version/type prefix.
- C3-073 CONFIRMED independently by whole-tree lib/include/unittests/tools caller search. Removed dead confirm_constant_power varargs wrapper, encrypt/decrypt message wrappers, erc_token/no_bold output wrappers, no_title_no_bold layout, layout_tx_info declaration, AGGRO_UNDEFINED_FN-only layout_remove_animation, and NO_WIDTH. Final caller search returned no remnants.

## Regression tests

Existing files only; no CMake changes needed:

- unittests/firmware/seed_display.cpp: `SeedDisplayBodyFits.AddressLayoutsShowCompleteTextWhenQrTextWouldClip` compares actual final canvas bytes and consumed decisions with the complete standard pager across widest Cosmos/Osmosis/Hive/TON/Nano/XPUB vectors. This observes production wrapper behavior, not just a duplicated font width model.
- `AddressSourceOverflowIsRefusedBeforeApproval`: confirms rejection without consuming a decision for a BODY_CHAR_MAX address.
- `WideUnifiedAddressRequiresEveryTextPage` (ZCASH_PRIVACY): rejects second-page cancellation and compares approved final framebuffer/page decisions with full standard pagination.
- `U2fDrawGeometryDoesNotInheritPreviousConfirmIcon`: finds a body that fits normal width and overflows icon width, then requires identical real framebuffer output after stale icon state.
- `OmniShowsPropertyAndAmountWithoutInventingUnits`: compares actual Omni confirmation framebuffer and decision count to independently specified text for protocol currencies, property3, property31, and UINT32_MAX with UINT64_MAX amount.
- `PagerRejectsACharacterThatCannotBeRendered`: constrains the real canvas to a width where no glyph fits, requires false and no consumed approval; catches the old one-page early-return bypass.
- unittests/firmware/nano.cpp: `Nano.AccountLabelsRetainAllUnhardenedIndexBits` pins indexes0, bit27, bit28, bit30, all31bits.

Existing exhaustive seed split/coverage tests remain. Seed stack scrub and static cleanup evidence is source/control-flow based; no undefined reads of dead stack frames or new test-only secret storage were introduced. Root should run firmware-unit/board-unit and serialized ARM gate. Tests that reference newly added APIs cannot be compiled wholesale against the baseline without retaining those additive probe/wrapper declarations; for direct before tests, preserve the additive probe and restore old wrapper behavior, or use the baseline-independent U2F/Nano/Omni/pager tests.

## Primary Omni evidence

Full primary sources downloaded for review, not just search excerpts:

- https://raw.githubusercontent.com/OmniLayer/spec/master/OmniSpecification.adoc saved `/private/tmp/omni-spec.txt`, SHA256 b024641e62e1593d79a5662c343a863dc54ccd68284119dfe137e03b9e81c088. Number-of-coins definition lines299-311 specifies eight decimal places for divisible properties, integer count for indivisible properties; Simple Send lines716-758 carries version/type/property/amount but no divisibility flag.
- https://raw.githubusercontent.com/OmniLayer/omniapi/master/www/index.html saved `/private/tmp/omni-api-primary.html`, SHA256 cbd70383151eed8fae75744f8f3af9465faf97aa4c7bec2b8038546d37a6c8cb. Official API response examples mark property1 OMNI and property2 T-OMNI `divisible:true`.
- https://raw.githubusercontent.com/OmniLayer/omnicore/master/src/omnicore/sp.cpp saved `/private/tmp/omni-sp.txt`, SHA256 7ab35bcb5699afc83f2af8c577f1c315c8b74f330ab3189dd2e5326655b80dbc. isPropertyDivisible consults property database; Simple Send payload alone does not establish arbitrary property divisibility.

Known remaining scope note: generic confirm_helper SOURCE truncation still has the pre-existing explicit hold-to-continue path. These address wrappers refuse source overflow directly. Other callers of the generic custom-layout API remain outside this selected address fix and should receive normal re-audit.
