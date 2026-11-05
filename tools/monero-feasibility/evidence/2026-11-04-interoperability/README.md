# Public interoperability inputs and historical findings

[host.json](host.json) now contains only the public `reference` object consumed
by the default runners: 96 independently generated address/output/key-image
vectors, pinned Core provenance, public fixture mnemonics and anchor checks.
The complete reference values are retained; verbose host execution and
mutation report wrappers are omitted. This file is test input, not a current
execution attestation.

The historical native emulator run passed 2,823 checks across those 96 cases
and four BIP-39/SLIP-0010 paths, with unchanged simulated flash. An instrumented
ARM trace was discarded after memory-write instrumentation altered execution;
the same eight-case ELF passed 271 checks without hooks. A complete corrected
96-case ARM execution was not established by that stage. Prepared unsigned
self-test images were not flashed; hardware timing and stack results remain
unmeasured.

Generated native/host/ARM reports, discarded traces and OLED copies are
omitted from this PR. [INTEROPERABILITY.md](../../INTEROPERABILITY.md) provides
the reference, sanitizer, mutation, ARM and native-emulator reproduction
commands. The [alpha summary](../2026-11-04-alpha/summary.json) records the
current full-wallet and receive-only native builds. No physical-device or
production-readiness claim follows from these results.
