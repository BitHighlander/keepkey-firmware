# P06-002: Ripple displayed-address response (7.14.2)

Base: e546d99798a5e7dbc54ad5fe43b040a2806c8291.

Confirmed against this release's pinned host suite: with screenshot capture,
show_display returns an empty address rather than the known public test vector.
DebugLinkGetState reuses the shared response arena during confirmation.
Keep the address in a local MAX_ADDR_SIZE buffer through confirmation, then
populate the response. The local buffer also matches ripple_getAddress's bound.
Cancellation still clears the derived node and returns failure.

The P00 ripple_display_response.py rehearsal fails before and passes after;
all 155 native firmware tests pass. The reproduction forces UDP and owns an
isolated emulator; no physical hardware used. Production DEBUG_LINK-off failure
was not established. ARM/host integration, permanent older-suite assertion and
full Ripple audit remain pending.
