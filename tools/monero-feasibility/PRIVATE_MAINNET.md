# Fresh private wallet and mainnet receiving monitor

`private_mainnet.py` creates a new emulator wallet through ordinary
`ResetDevice` with 256-bit strength, checked OS device randomness and fresh
32-byte OS host entropy. It does not load a test mnemonic or read the generated
mnemonic. The ordinary backup pages are automatically acknowledged; no paper
mnemonic backup is claimed.

The script saves only authenticated, encrypted flash outside the repository
and temporary directories. A dedicated native macOS Keychain entry supplies
its AES-256-GCM key. It then exits the provisioning process and starts another
process which decrypts the flash, initializes the emulator without
`LoadDevice`, and requires the same mainnet address. Public address checksums
and the exported view key's public point are checked independently before the
address is released. No outgoing transaction operation is implemented here.

This remains a DebugLink-enabled software emulator using research Monero
handlers. It provides no hardware-wallet isolation. Use small test amounts.

## Private transport and storage

- `private_transport.py` owns a locked 1 MiB flash buffer. Memory locking must
  succeed before initialization and generation. It never requests DebugLink
  state, captures screenshots, saves frames or writes a protocol transcript.
  It sends button acknowledgements/decisions without reading seed screens.
- Firmware setup frames are drained and discarded. Shutdown joins the firmware
  thread, wipes its transport/display state and clears owned host buffers;
  a shutdown timeout retains memory rather than freeing live flash.
- `private_keystore.py` uses native Security.framework APIs, a separate service
  and exact wallet account. No encryption key is placed in a command argument.
  Access denial fails closed; existing Keychain keys are never overwritten.
  AES-GCM authenticates the wallet ID, envelope version and selected backend.
- The default login-Keychain backend trusts the creating Python interpreter.
  It is not hardware-backed or isolated from other scripts using that
  interpreter. Data Protection is an explicit separate backend requiring
  appropriate host entitlements; no automatic downgrade occurs.
- Private directories are mode 0700 and encrypted files mode 0600. Atomic
  writes and a second encrypted flash copy protect against incomplete writes.
  Both copies depend on the same Mac's Keychain key and are not independent
  offline recovery backups. No mnemonic sidecar is created.
- Python and crypto libraries may retain temporary memory copies. These
  controls do not establish complete process-memory erasure.

## Receiving-only monitoring

The restored emulator exports its view credentials through message 542 after
the normal consent flow. Those credentials and a random watch-wallet password
are sealed separately. Stock `monero-wallet-rpc` runs as a local view-only
wallet; the monitor verifies that requesting a spend key is refused.

The remote node is untrusted. Its HTTPS certificate is first checked for CA
trust and hostname by Python, then its exact leaf fingerprint is pinned in
the stock wallet client. Certificate verification is never disabled. Remote
nodes receive block/status requests, not private view or spend keys.
The current allowlist is [Seth](https://sethforprivacy.com/about/#mainnet) and
[Triplebit](https://www.triplebit.org/monero/); independent public chain
checkpoints are compared before provisioning.

Local RPC binds to loopback and uses generated Digest credentials kept in a
private file. Requests retain their TCP connection because Monero scopes its
authentication nonce to that connection. Public status exposes incoming
transactions, balances and sync height, with no credentials or private keys.
The monitor has no signing, transfer or relay methods.

## Run

First use non-sensitive dummy data to test native Keychain encryption:

```sh
python3 tools/monero-feasibility/private_keystore.py --self-test --backend login
```

Create a fresh wallet; the default private root is
`~/Library/Application Support/KeepKey/MoneroEmulator/`:

```sh
python3 tools/monero-feasibility/private_mainnet.py create \
  --library /path/to/research/libkkemu.dylib \
  --core-library /path/to/independent/core-reference.dylib
```

The result prints only the public address, private storage location and
restoration status. Keep that directory and its Keychain entry. The prototype
library paths/builds must remain available or be rebuilt to reopen the
emulator later.

Start the receiving monitor using that returned directory and the verified
official host binaries from [HOST.md](HOST.md):

```sh
python3 tools/monero-feasibility/private_watch.py \
  --wallet-dir '/path/to/private/wallet-directory' \
  --bin-dir /path/to/verified/monero/bin
```

`mainnet-watch.json` records current sync state and incoming transactions.
SIGINT/SIGTERM stops the monitor and its local RPC process. Existing watch
wallets are opened with the sealed password and never silently replaced.
No generated mainnet wallet files, addresses, credentials or seed data belong
in the experiment's checked-in public evidence.
