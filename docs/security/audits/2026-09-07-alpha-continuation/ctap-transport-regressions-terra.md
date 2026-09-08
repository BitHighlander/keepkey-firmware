# CTAP/U2F transport emulator regressions

## Checkpoint

The emulator-only regression patch is stable for the serialized build. It extends the existing transport fixes without changing device-only interfaces or adding device SRAM. `git diff --check` passed and every touched file was formatted with clang-format 20. No shared build was run.

## Added live-path coverage

- `U2F.UserPresenceRejectsInitAndForeignCommandsWithoutChangingChannel`
  starts a real CTAP2 `authenticatorReset` CBOR request through `u2fhid_read()`. At the live user-presence point, the emulator hook injects a broadcast `CTAPHID_INIT` and a competing `CTAPHID_PING` on the active channel. The test captures the actual transport output and verifies both packets receive `ERR_CHANNEL_BUSY` and the CTAP response remains on the original CID. This proves INIT neither replaces the reader nor rotates the active CID during consent.
- `USBRX.MainPacketsStayTinyWhileU2fOwnsUserPresence`
  installs a normal production protobuf map handler, proves a normal main packet reaches it when USB tiny mode is inactive, then proves the same packet is queued as a tiny message and does not invoke the handler while U2F owns tiny mode.
- `USBRX.DebugPacketsStayTinyWhileU2fOwnsUserPresence`
  provides the equivalent DEBUG_LINK-only coverage when that target is enabled.

The hooks are compiled under `EMULATOR` only. Device builds retain the ordinary HID endpoint path and gain no callback pointer or static allocation.

## Proposed serialized test filter

```sh
build-emu/bin/firmware-unit --gtest_filter='U2F.UserPresenceRejectsInitAndForeignCommandsWithoutChangingChannel:USBRX.MainPacketsStayTinyWhileU2fOwnsUserPresence:USBRX.DebugPacketsStayTinyWhileU2fOwnsUserPresence:CTAP2CBOR.TextValidationRejectsTruncatedUtf8'
```

When DEBUG_LINK is disabled, GoogleTest simply has no matching debug test and runs the remaining filter entries.

## Final read-only review of revised tiny flow

Reviewed root's post-test-failure revision without source edits.

- The replacement USBRX assertions are stronger and correctly scoped. Before `usbTinyActive()` routing, the second valid Initialize dispatches normally and `dispatch_count` becomes 2. With the fix, it is decoded as tiny input, produces no failure, and cannot invoke the registered normal/debug handler. Restoring `fsm_init()` prevents the test map from leaking to later tests.
- `handle_tiny_rx()` correctly discards unsolicited decoded acknowledgements whenever U2F owns tiny mode and no `wait_for_tiny_msg`/`check_for_tiny_msg` consumer is active. It retains the result only while `msg_tiny_flag` is active, which preserves existing PIN/passphrase confirmation behavior.
- Removing the stack-local 64-byte copy from `msg_read_tiny()` is safe for the synchronous callback lifetime and removes a redundant sensitive copy. Existing decoded buffer wipes now cover success, decode failure, and unsolicited U2F input.

Residual hygiene observations reported to root:

1. `msg_read_tiny()` clears `msg_tiny` after validating the packet prefix and declared length. A malformed 64-byte prefix/length packet during an active tiny poll returns before that wipe. Prior paths normally leave the global zeroed, but clearing at function entry would make the invariant unconditional.
2. The device `main_rx_callback` static confidential 64-byte packet buffer still retains raw `PassphraseAck` payload bytes after callback return. This is pre-existing and separate from the decoded/tiny-copy cleanup; whether to wipe the receive buffer is a broader USB input-buffer lifetime decision.

No control-flow regression or new retained decoded secret was found in the revised logic itself. `git diff --check` passed. No build was run in this review.
