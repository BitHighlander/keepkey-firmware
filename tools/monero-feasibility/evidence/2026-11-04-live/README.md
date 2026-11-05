# Historical live private-chain session

The completed local-chain address-display run passed nine stages and 92
checks. The emulator handled actual 540/541 address display, full address/QR
review, and two daemon-confirmed spends including change reuse. It used a
published disposable seed on an offline private `fakechain`, with no peers.
No real XMR, existing user wallet or physical device was involved.

This records a completed experiment, not a running service or current health
check. Mutable PIDs, RPC URLs, address snapshots, transaction copies and OLED
captures are intentionally omitted from the review branch.

[HOST.md](../../HOST.md) gives the `host_emulator.py --keep-running` command
that regenerates these outputs. The [host notes](../2026-11-04-host/README.md)
identify retained public regression inputs, and the [alpha summary](../2026-11-04-alpha/summary.json)
records the current firmware rebase results. Mainnet-generated private wallet
data belongs outside the repository; see [PRIVATE_MAINNET.md](../../PRIVATE_MAINNET.md).
