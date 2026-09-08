# Bounded adversarial review: MakerDAO C3-007/008 and RNG C3-064

Read-only review; no source edits, builds, or test execution. Compared the supplied before snapshots with current production source, read MakerDaoProxy tests and the new register harness, and followed caller cancellation/amount-display paths.

## Verdict

No remaining bypass found in the reviewed MakerDAO C3-007/008 changes or the final RNG production diff (including root's subsequent addition of SECS/CECS to the clean-status mask). Root's test execution and RNGEN-instrumentation follow-up remain separate evidence; this review does not claim to have run them.

## MakerDAO

- `isProxyCall` bounds the received chunk before reading the selector/head, requires the unique dynamic offset64, bounds uint256 length to32bits then to the actual available bytes, requires selector+whole32-byte arguments, and requires exactly the padded extent with zero padding. Since inner_size<=available<=the protobuf backing array, inner_size+31 cannot overflow. The subtraction of header_size is after the minimum-size guard.
- `hasProxiedParams` independently requires the dynamic length to equal4+32*the recognized method's argument count. This closes the original shortened-delegatecall attack: the device cannot display a third argument while the proxy sends only the first two.
- If malformed proxy encoding makes isProxyCall false, direct-method parsing cannot accidentally accept the execute selector: none of the recognized direct selectors is1cff79cd. The same message is revalidated by makerdao_confirmMakerDAO, so directly invoking the confirmation API does not bypass recognition.
- `confirmProxyCall` checks a20-byte outer recipient and canonical embedded-address high bytes, then displays msg->to using the full checksum address. It separately preserves the existing embedded target review. A false answer propagates through ethereum_contractConfirmed to ethereum_signing_abort; it does not fall back to another permissive path.
- The outer-address string is42characters in a43-byte buffer; checksum output fits. Standard confirmation pagination guards its actual display geometry.
- Collateral check: although MakerDAO Open's operation screen is terse, ethereum.c still unconditionally displays attached native value in layoutEthereumFee. The new outer-recipient review therefore binds the funds destination, while native amount and operation approval remain distinct gates.
- Root's tests distinguish missing outer review using consumed decisions and separately reject outer recipient and operation approval. Canonical ABI tests cover undersized/oversized/UINT32_MAX declared lengths, incorrect offset, nonzero padding, and truncated physical extent. Source inspection covers the high256-bit length/offset rejection and method-specific length equality.

No additional required MakerDAO change found. Optional test improvement: compare the actual first framebuffer for two different outer recipients; the current screen-count test detects a missing screen but would not itself detect displaying the embedded target twice. The reviewed source does use msg->to correctly.

## RNG

- The transient branch now latches the boot-lifetime error, increments the bounded restart budget, and calls reset_rng instead of merely clearing SEIS/CEIS. reset_rng clears RNGEN, clears sticky status, reenables RNGEN, and discards the first ready word.
- If no word appears during reset_rng's bounded wait, rng_discard_pending remains true and random32 discards the first later ready word before returning another. This also covers the fault+DRDY case; a buffered fault word cannot be returned through the changed transient path.
- Root subsequently broadened the clean-status branch to require SEIS,CEIS,SECS,CECS all clear. That closes the defensive active-error-only state observed in the initial mock's persistent scenario, which otherwise spun without entering retry recovery after sticky bits were cleared.
- Persistent and recurring transient faults exhaust the restart budget into fail-closed wfi. Recovery does not clear the software error latch, so opted-in health-checked key generation continues refusing this source for the boot.
- No recursion was reintroduced. Reset/discard remains direct register access; new/last's repeat suppression still requires a fresh unequal output.

Test review feedback delivered to root:

1. The first persistent mock scenario repeatedly asserted only SECS after the reset cleared SEIS, exposing the missing active-bit clean-status check; root fixed production and reported allfive cases pass.
2. The first mock recorded only reads/results/latch, so a broken implementation that discarded a word without actually toggling RNGEN could also pass. Root is adding CR transition instrumentation to require disable/re-enable. That strengthened harness should be reviewed/run before declaring the hardware-restart property covered by the regression.

Primary-source limit: root supplied the RM0033 section20.3.1 restart/discard requirement. Independent attempts to retrieve https://www.st.com/resource/en/reference_manual/cd00225773.pdf failed (web tool rejected PDF>10MB; direct ST download timed out). Accordingly this report verifies code against the supplied manual contract and does not claim independent full-PDF inspection.

## Reviewed source identities

- makerdao.c SHA256: 3fc6319e31c17a1b0a235fd18882c3bee755f108f5141e715ff15fa4bce4ca95
- rng.c final production SHA256: 7d30e4949db1d21ec81bf726c054ae8a6a711b0f2d92192fc362ed259b0f34a7
- unittests/firmware/ethereum.cpp SHA256: aa69a94a472e513683545b5a9b574d19db11a9482dd6a99cf7503ad8ebec489d
- Initial tools/check_rng_fault_recovery.py SHA256 (before planned RNGEN transition assertions): 055183c9c6d191da1eae640d62354e6e718ca70224a73d2d1de0a746ff176fe5

Scope: the targeted proxy parsing/recipient disclosure and transient RNG recovery. Existing generic amount-too-large sentinel behavior, arbitrary-contract semantic trust, and unrelated RNG consumers are not claimed clean by this bounded review.
