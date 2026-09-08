# CTAP/U2F and transport audit fixes

Worktree: `/Users/highlander/WebstormProjects/keepkey-stack/projects/keepkey-firmware-alphafix` at audit start `ed65a0ce9`.

Pre-fix source snapshots were saved in `/private/tmp/keepkey-ctap-transport-pre-fix-terra/`.

## Fixed findings

- **C3-056 (confirmed):** CTAPHID_INIT could run while a CBOR command was blocked for user presence, overwrite the active reader state, and rotate the active channel ID. `u2f.c` now marks the synchronous CBOR command in flight, rejects INIT with `ERR_CHANNEL_BUSY` while it is active, leaves the active CID unchanged, and terminates the user-presence loop if the command changes. The generated INIT CID is local until the normal INIT assignment.
- **C3-057 (confirmed):** a resident credential `user.name` longer than storage could be truncated in the middle of a UTF-8 sequence. Creation now rejects an overlong/non-text name through `copy_text`. Assertion encoding omits a corrupt legacy name and uses a matching CBOR map count.
- **C3-058 (defense-in-depth):** the reported branch was not an externally confirmed persistence issue, but the ephemeral make-credential private key is now scrubbed before returning from authenticator-data encoding failure.
- **C3-074 (confirmed):** main or debug-link packets could be dispatched normally during U2F/CTAP user presence because only the message tiny flag, rather than U2F's USB tiny state, controlled routing. `usbTinyActive()` exposes the existing state without new SRAM; both main and DEBUG_LINK receivers now use the tiny parser while U2F owns it. The emulator UDP implementation has the same query.
- **C3-075 / C3-077 (confirmed):** decoded protobuf contents remained in a static transport buffer after every dispatch path. The buffer is now `CONFIDENTIAL` and is wiped on decode failure, invalid mapping, and normal handler return.
- **C3-078 (confirmed):** the static tiny decoded message remained after copying into the waiting caller. It is wiped immediately after that handoff.

## Refuted / retained

- **C3-059 / C3-080:** RAW dispatch is live in the bootloader USB flasher (`tools/bootloader/usb_flash.c`), and CTAP CBOR helpers are used by the firmware fuzzer. They were not deleted.
- **C3-076:** the USART debug compile branch is not reachable in the production configuration reviewed. No debug transport removal was made here because it was outside the owned CTAP/USB receive path and needed separate configuration-wide review. DEBUG_LINK remains supported and is now protected by tiny routing.

## Regression coverage

- Added `CTAP2CBOR.TextValidationRejectsTruncatedUtf8`, which fails against a permissive UTF-8 encoder predicate and verifies the new validation helper accepts complete and rejects truncated multi-byte UTF-8.
- The U2F INIT/CID and main-channel-interleaving changes require the serialized firmware transport/integration build to exercise hardware-style receive callbacks; they were statically traced because the emulator's U2F TX intentionally asserts and cannot execute the device user-presence loop.

## Validation performed

- `/opt/homebrew/opt/llvm@20/bin/clang-format -i` on every touched source, header, and test file.
- `git diff --check` passed.
- No shared build or test command was run, per serialized-build instruction.
