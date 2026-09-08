# P01 cryptography gate and signature-tool review (7.15)

Reviewed all changed implementation in `tools/check_pallas_api_boundary.py`,
`tools/check_pallas_ct_disassembly.py` and `scripts/release/verify-signatures.py`
at the frozen a18317f88 product head. P01-006 corrects the disassembly input
failure in PR #677; no crypto source changed.

- API gate: inspected function extraction, comment stripping, required/forbidden
  tokens and every named caller. Current source passes. In-memory mutations
  replacing secret multiplication with the public API, removing nonce-context
  wipe and replacing the rk-validating signing entrypoint each fail. The files
  were not modified for these fixtures.
- Disassembly: inspected symbol/instruction parsing, required multiplier calls
  inside the backwards loop, canary exception, CT symbol scan and forbidden
  instructions. Re-ran against full and Bitcoin-only CI 34283763680 ARM ELFs.
  Both pass. P01-006 negative fixtures reject absent decoded evidence and the
  wrong product; full mode rejects a missing multiplier symbol.
- Signature tool: compared offsets, key indices, distinct-key check and digest
  span against memory.h and signatures_ok(). All five current validity bytes
  are 0xff; no currently expired key is accepted differently. The public-key
  header is parsed at runtime and malformed input raises failure. Actual
  self-test passes with disposable keys: valid signatures accepted; corruption,
  duplicate/out-of-range indices, wrong signer and nonzero placeholders refused.
  The publication checklist invokes cryptographic verification before structural
  signed-manifest generation. No production signing or publication occurred.

These are regression gates, not complete proofs. API token presence does not
prove control-flow dominance, data classification or wiping on every exit.
Backward branches require source confirmation that their bounds are independent
of secrets; the disassembly gate also does not prove memory access independence.
Those obligations remain P08 and dependency review. Host signature verification
is not the bootloader fault-injection or installed-key-state audit; it agrees
with the current ordinary signature verification contract.
