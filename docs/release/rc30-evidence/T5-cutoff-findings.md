# T5 — Cut Off pre-screen (#428/#481/#482), hardware round

Device: 7.14.2, variant KeepKey, device_id 39353036114736342A004600, AdvancedMode=False.
Vehicle: `Ping` with `button_protection` — `fsm_msgPing` -> `confirm(..., "Ping", "%s", msg->message)`.

## PASS — boundary and wire protocol

| body | ButtonRequests | result |
|---|---|---|
| 100 ch | 1 | one screen, no warning |
| 117 ch | 1 | three full rows, no warning |
| 118 ch | 2 | CUT OFF — boundary is 118 |
| 119 ch | 2 | CUT OFF |
| 255 ch | 2 | CUT OFF |

- **#481 confirmed on hardware.** Boundary is 118, not 119. A clipped final glyph
  no longer reports as fitting (`draw.c:213-219`).
- **#482 confirmed on hardware.** The Cut Off screen emits its own ButtonRequest
  (`code=1`, ButtonRequest_Other). An auto-approving host can no longer deadlock.
- No false positives at 100 or 117.

## FINDING 1 — "Hold to view it anyway" discloses nothing

`confirm_sm.c:441` re-draws the SAME truncated body after the warning:

    return confirm_screen(request_title, request_body, ...);

`request_body` is unchanged and the generic `confirm()` path has no pager. The
byte-exact pager (`confirm_bytes()`, with n/m counters) exists only for the three
SignMessage handlers. So the hidden text stays hidden and the second hold buys
the user nothing.

The screen tells the user it is about to disclose the remainder, and does not.
Either the copy is wrong or the pager is missing. Wrong copy on a consent screen.

## FINDING 2 — the second consent is satisfied by the RELEASE of the first

Three runs, varying only when the host's ButtonAck for BR2 lands:

| run | ack timing | hands off after hold #1 | result |
|---|---|---|---|
| carry-over | immediate | yes | **Success @ 1.602s** |
| no-ack control | never sent | yes | silence 15s (screen is gated) |
| delayed-ack | +5s | yes | silence 15s (screen waits) |

Immediate ack completes; ack delayed past the bounce window does not. The press
edge therefore arrives shortly after the user releases hold #1.

**Mechanism.** `keepkey_button.c` has no debounce. EXTI is `EXTI_TRIGGER_BOTH`
and `buttonisr_usr()` decides press vs release from the GPIO level at interrupt
time. A mechanical release bounces low and dispatches `on_press_handler`.
`confirm_screen()` resets `state_info` to HOME and re-registers handlers
(`confirm_sm.c:198-220`), so screen 2 is armed and accepts that bounce as a
fresh press out of HOME, then runs its own hold timer to completion.

**Consequence.** #482 added a second ButtonRequest so the user would be asked to
consent to a body the device admits it cannot fully display. On hardware that
second consent can be satisfied by the physical release of the first hold. The
user holds once and both screens pass.

**Why CI cannot see this.** The emulator has no bounce and no physical button;
`keepkey_button_up()` is `return false` under EMULATOR. Only a hardware round
finds it — this is the case for keeping the hardware gate.

## Proposed fix (not yet applied)

Require the button to be observed UP before a confirm screen accepts a press.
Local to confirm_sm.c, no driver change, no timing constant:

- at `confirm_screen()` init: `state_info.armed = keepkey_button_up();`
- in `handle_screen_press()`: ignore the press unless `si->armed`
- in `handle_screen_release()`: `si->armed = true;`

A screen that opens while the button is still down (or bouncing) refuses presses
until a genuine release is seen. Costs one bool and two branches.

## Reproduce

    cd deps/python-keepkey/tests
    PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python python3 cutoff_428_carryover.py   # Success ~1.6s
    PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python python3 cutoff_428_noack.py       # silence
    PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python python3 cutoff_428_delayack.py    # silence

Replug between runs; `hwpreflight.idle_or_die()` refuses to start on a dirty device.

## Trap recorded

An aborted run leaves a ButtonRequest queued that SURVIVES into the next session,
and the next run answers it silently — observed live as BR1 returning code=4
instead of the Ping's own code=23. Every test in this plan needs the first-code
assertion or it can be invalidated by whatever ran before it.
