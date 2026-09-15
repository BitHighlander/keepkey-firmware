# P06-006: permanent unsupported-memo rejection coverage

Base firmware: 06d84f561. Host pin:
0f4c839db56767eac43c9c7be8a2e2b589667b49, fork host PR #80.

Adds the permanent 7.14.3 full-feature test requiring Failure_SyntaxError for
a nonempty Ripple memo. Earlier versions, Bitcoin-only and 7.15 (which supports
memos) are gated out. Rejection, ordinary signing and invalid-fee tests pass
against the rebuilt full emulator using isolated storage and forced UDP.
The exact host commit is fetchable through the configured submodule URL.

No firmware source changes. Combined CI and complete Ripple audit remain open.
