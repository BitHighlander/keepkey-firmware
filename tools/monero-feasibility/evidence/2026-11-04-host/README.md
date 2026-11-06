# Official CLI/RPC host integration results

The historical offline local-chain run passed nine stages and 87 assertions.
Stock Monero v0.18.5.4 wallet RPC operated a watch-only wallet, imported
emulator key-image proofs, and the stock daemon accepted/mined two
emulator-authorized transactions, including spending change. A subsequent
address-display/live-session run passed 92 assertions.

Both runs used published disposable fixtures and an offline `fakechain`
daemon with no peers. They did not use a public chain, existing user wallet
or physical device. These results do not establish an STM32 signer or
production readiness. The current native firmware rebase results are in the
[alpha summary](../2026-11-04-alpha/summary.json).

## Retained regression inputs

[fixtures/](fixtures/) contains three encrypted public wallet-export requests
and their expected ABI plans: base output, subaddress output and reversed
four-input selection. The fixture producer `make-fixture.cpp` is retained.
All fixture keys are published test material. No user wallet or faucet seed
is included.

`verify_host_adapter.py` consumes the request JSON and expected `*-plan.bin`
files directly. It regenerates adapter replies and tests exact plans/output
metadata, authenticated-container tampering and spend-key-field rejection.
The old replies are redundant expected-output copies and are omitted.

Historical build/result/wire JSON, encrypted run outputs, transaction blobs,
version logs, copied drivers and display captures are omitted from this PR.
[HOST.md](../../HOST.md) contains commands to reproduce the adapter regression
and complete private-chain integration, regenerating those artifacts in a
new output directory. The current implementation is `host_emulator.py`;
source snapshots are not additional runtime dependencies.
