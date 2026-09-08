# Alpha audit continuation

User authorization: continue firmware audits using all available models and merge reviewed fixes into BitHighlander/keepkey-firmware alpha. No upstream publication is in scope.

Baseline: `ed65a0ce9bbfd06d58a30a834f5245e86310a794` after the first cycle-3 EIP-712 fixes. Original recovered findings remain in `../2026-09-07-alpha-71ba84436-cycle3.md`.

## Validation state

- Original cycle-3 workflow did not finish every adversarial verifier; missing votes are not clean findings.
- First continuation commit: 595 firmware / 21 board tests passed, then 41 streamed EIP-712 tests passed after one additional positive regression.
- Second batch: seven new session regressions failed before the fix; the combined storage/session/Cosmos-family/authenticator/EIP-712 group passed 151 tests after the central fix.
- Final combined second batch passed all 623 firmware tests and 25 board tests. All 38 changed C translation units passed cppcheck with zero findings, and the three transport files passed again after follow-up cleanup. Both new ARM gates, bitcoin-only unit variant and integration remain pending.
- No zero-finding full-surface pass has yet completed on the final SHA. This is an in-progress ledger, not a clean-audit attestation.

## Additional findings during continuation

- EIP-712 inner fixed dimensions were unchecked; initial patch also exposed reversed multidimensional traversal. Fixed declared-dimension enforcement and Solidity bracket order; asymmetric and mixed fixed/dynamic tests passed in the combined suite.
- Root seed cache ignored usePassphrase changes; independent plain/hidden derivation regression failed before and passes after.
- OTP counter encoded only 32 bits; now parses/encodes full uint64 and bounds countdown to 30 seconds. Independent HMAC vectors and malformed inputs passed in the combined suite.
- Nano/GetPublicKey derivation label failure siblings now refuse rather than displaying an empty label.
- Transient hardware RNG faults previously dismissed as non-host-triggerable are treated as relevant for the hardware wallet: restart/discard and active-bit checking fixed; five real-provider mock-register cases fail before and pass after, including RNGEN transition assertions.
- KeepKey compatibility crypto header reused the upstream guard and hid complete curve declarations; changed to a unique guard with the canonical header included.

## Recovered report dispositions

| ID | Prior verdict | Continuation state |
|---|---|---|
| C3-001 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-002 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-003 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-004 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-005 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-006 | REFUTED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-007 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-008 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-009 | REFUTED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-010 | CONFIRMED | Fixed and validated in ed65a0ce9 |
| C3-011 | CONFIRMED | Fixed and validated in ed65a0ce9 |
| C3-012 | CONFIRMED | Fixed and validated in ed65a0ce9 |
| C3-013 | REFUTED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-014 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-015 | REFUTED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-016 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-017 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-018 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-019 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-020 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-021 | REFUTED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-022 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-023 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-024 | REFUTED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-025 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-026 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-027 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-028 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-029 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-030 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-031 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-032 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-033 | REFUTED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-034 | REFUTED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-035 | CONFIRMED | Protocol cleanup and matching client/options integration in progress |
| C3-036 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-037 | REFUTED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-038 | CONFIRMED | Unused firmware formatter removed; protocol cleanup in progress |
| C3-039 | UNVERIFIED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-040 | REFUTED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-041 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-042 | REFUTED | Dead firmware wrappers removed; separate public crypto API cleanup under independent review (no reachable exploit established) |
| C3-043 | REFUTED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-044 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-045 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-046 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-047 | REFUTED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-048 | UNVERIFIED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-049 | UNVERIFIED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-050 | REFUTED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-051 | UNVERIFIED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-052 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-053 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-054 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-055 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-056 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-057 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-058 | REFUTED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-059 | REFUTED | Current exploit/deadness refutation in transport report; retain necessary production/fuzz surfaces |
| C3-060 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-061 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-062 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-063 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-064 | REFUTED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-065 | REFUTED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-066 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-067 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-068 | REFUTED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-069 | UNVERIFIED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-070 | UNVERIFIED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-071 | UNVERIFIED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-072 | UNVERIFIED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-073 | UNVERIFIED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-074 | UNVERIFIED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-075 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-076 | REFUTED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-077 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-078 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-079 | UNVERIFIED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-080 | REFUTED | Current exploit/deadness refutation in transport report; retain necessary production/fuzz surfaces |
| C3-081 | REFUTED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-082 | REFUTED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |
| C3-083 | CONFIRMED | Remediation/hygiene implemented; combined full-feature unit suite passed; device/integration gates pending |

## Independent models used so far

| Model | Bounded contribution |
|---|---|
| gpt-5.6-sol | Storage re-verification and remediation |
| gpt-5.6-terra | Cosmos-family and CTAP/transport verification/fixes |
| gpt-5.5 | EIP-712, EOS/Solana and dead-code verification/fixes |
| gpt-5.6-luna | Companion Python CI and ancestry/reconciliation |
| gpt-6-astra | Display, Bitcoin/Zcash fixes; MakerDAO/RNG verification |

These bounded tasks do not substitute for final full-surface audits. All final passes must identify the same exact commit and complete their verifier coverage.

## Final local checkpoint

- Both MakerDAO proxy regressions and three fixed-array EIP-712 regressions fail on original implementations and pass after restoration; the dynamic-outer positive control passes both versions.
- All five register-level RNG cases fail before and pass after the fix. The harness compiles the actual non-emulator provider, verifies RNGEN disable/re-enable transitions, and exercises immediate/deferred discard plus bounded recurring/persistent failures. Hardware guidance: [ST RM0033](https://www.st.com/resource/en/reference_manual/cd00225773.pdf), section 20.3.1.
- Raw main/debug/U2F receive buffers are scrubbed after callbacks and short packets. Tiny decoding no longer makes a stack copy, clears its output on malformed input, and immediately scrubs unsolicited ACKs while U2F owns the interface. The real UDP tiny-poll regression passes.
- Python fork master `c403e866c53a85cbee91cb8750265085f2506b49` contains reviewed reconciliation, STEEM wire expectations, explicit ABI validation and multidimensional device test. Current-firmware CI references still require the ordered follow-up pin to this firmware batch.
- Firmware protocol pin is fork master `bee6cdd624905d6b5bcc54a05fc3deb24242483d`; the unchanged organization URL was verified to serve the exact object. No URL redirect was needed.
- The EIP-712 stale memory-margin comment and DEBUG_LINK definedness mismatch are corrected. The previous full ARM reserve was only24 bytes above the minimum; device gates are mandatory and unchanged.
