# OLED Screenshot System — Proof & Reference

Proven working 2026-03-27 on alpha branch, commit `22def600`.
BIP-39 rejection test passes with OLED screenshot: "Word not in wordlist".

## Proof

```
$ KEEPKEY_SCREENSHOT=1 SCREENSHOT_DIR=/tmp/bip39-proof \
  pytest -v -x -s -k "test_invalid_bip39_word_rejected"

test_msg_recoverydevice_cipher.py::TestDeviceRecovery::test_invalid_bip39_word_rejected
[SCREENSHOT] OK: .../btn00000.png (2048 bytes layout)
[SCREENSHOT] OK: .../btn00001.png (2048 bytes layout)
PASSED
Session complete: 2 PNGs captured
```

**btn00001.png**: Warning triangle + "Word not in wordlist" + "DEBUG_LINK" watermark.
256x64 monochrome OLED capture from KeepKey emulator via DebugLink.

## 4 Components That Must All Be Present

### 1. Firmware: Canvas Layout Packing

**File**: `lib/firmware/fsm_msg_debug.h` (alpha `22def600`)

Lines 49-74 — `fsm_msgDebugLinkGetState()`:
```c
// Line 53: CRITICAL — only animate if queue active (22def600)
if (is_animating()) {        // guard added in 22def600
  force_animation_start();
  animate();
}
display_refresh();           // Line 57

// Lines 62-74: pack 256x64 canvas into 2048-byte 1bpp layout
Canvas *c = display_canvas();
if (c && c->buffer) {
  resp->has_layout = true;
  resp->layout.size = 2048;
  // ... bit-pack loop ...
}
```

**Why `is_animating()` matters**: Without the guard, `force_animation_start() + animate()` runs unconditionally. This overwrites static layouts (warning screens, address displays) with stale animation frames. Static content is already on the canvas — animating destroys it.

- `is_animating()` defined: `include/keepkey/board/layout.h:121`, `lib/board/layout.c:614`
- `force_animation_start()` defined: `lib/board/layout.c:707`
- `animate()` defined: `lib/board/layout.c:580`
- `display_canvas()` defined: `lib/board/keepkey_display.c:281` (returns static `&canvas`)
- `canvas_buffer` defined: `lib/board/keepkey_display.c:44` (static array, always valid)

### 2. Proto: Layout Field Size

**File**: `include/keepkey/transport/messages.options:112`
```
DebugLinkState.layout    max_size:2048
```

MUST be 2048, not 1024. The OLED is 256x64 pixels = 256 × (64/8) = 2048 bytes in 1bpp.
With `max_size:1024`, nanopb silently drops the field — client gets 0 bytes.

**Commit history**: Was 1024 on develop/p0 (broke all screenshots). Fixed to 2048 on alpha and backported to p0 in `b7d82f03`.

### 3. Emulator Build: DEBUG_LINK

**File**: `cmake/caches/emulator.cmake:2`
```cmake
set(KK_DEBUG_LINK ON CACHE BOOL "")
```

`fsm_msgDebugLinkGetState()` is inside `#if DEBUG_LINK` (fsm_msg_debug.h:1).
Without this, the handler doesn't compile — DebugLink returns nothing.

**Build command** (native macOS ARM64):
```bash
eval "$(pyenv init -)" && pyenv shell 3.10.15
export PATH="/Users/highlander/nanopb-0.3.9.4/nanopb-nanopb-0.3.9.4/generator:/opt/homebrew/Cellar/protobuf@21/21.12_1/bin:$PATH"
rm -rf build-emu && mkdir build-emu && cd build-emu
PB_NO_PACKED_STRUCTS=1 cmake -C ../cmake/caches/emulator.cmake .. \
  -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_POLICY_VERSION_MINIMUM=3.5
make -j$(sysctl -n hw.ncpu)
```

**Toolchain requirements**:
- pyenv Python 3.10 (not system Python)
- protoc 3.21.12 at `/opt/homebrew/Cellar/protobuf@21/21.12_1/bin/protoc`
- nanopb 0.3.9.4 at `/Users/highlander/nanopb-0.3.9.4/nanopb-nanopb-0.3.9.4/generator/`
- `PB_NO_PACKED_STRUCTS=1` (required for ARM64 alignment)
- nanopb proto files must be regenerated with protoc 3.21 (not 33.0)

**Binary output**: `build-emu/bin/kkemu` (~1.3 MB)

### 4. Python: Screenshot Capture

**Submodule pin** (alpha): `deps/python-keepkey` @ `374af2b` on `BitHighlander/python-keepkey`
**`.gitmodules` URL**: `https://github.com/BitHighlander/python-keepkey.git`

#### Global flag — `keepkeylib/client.py:61`
```python
SCREENSHOT = os.environ.get('KEEPKEY_SCREENSHOT', '') == '1'
```
Module-level global, evaluated at import time. Set via `KEEPKEY_SCREENSHOT=1` env var.

#### Capture method — `keepkeylib/client.py:463-502`
```python
def _capture_oled(self):
    if not SCREENSHOT:
        return
    if not self.debug:
        print("[SCREENSHOT] SKIP: no debug link", file=sys.stderr)
        return
    try:
        layout = self.debug.read_layout()
        if not layout or len(layout) < 1024:
            print("[SCREENSHOT] SKIP: layout too small (%d bytes)" % ...)
            return
        # ... convert 1bpp to 8bpp, write PNG ...
        print("[SCREENSHOT] OK: %s (%d bytes layout)" % ...)
    except Exception as e:
        print("[SCREENSHOT] ERROR: %s" % e, file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
```

#### Trigger — `keepkeylib/client.py:504-509` (DebugLinkMixin)
```python
def callback_ButtonRequest(self, msg):
    self._capture_oled()           # Line 509 — BEFORE pressing button
    if self.auto_button:
        self.debug.press_button(self.button)
    return proto.ButtonAck()
```
Called by `KeepKeyDebuglinkClient` (MRO: ProtocolMixin → DebugLinkMixin → BaseClient).
NOT called by `call_raw()` — only by `call()` which processes callbacks.

#### Per-test directories — `tests/conftest.py:17-49`
```python
if os.environ.get('KEEPKEY_SCREENSHOT') == '1':
    # Patches KeepKeyTest.setUp to set per-test screenshot dirs
    # screenshots/{module}/{test_name}/btn00000.png
    self.client.screenshot_dir = screenshot_dir
    self.client.screenshot_id = 0
```

#### Fail-fast gate — `tests/conftest.py:54-63`
```python
def pytest_sessionfinish(session, exitstatus):
    if os.environ.get('KEEPKEY_SCREENSHOT') != '1':
        return
    # Count PNGs, exit 1 if zero
    print("FATAL: KEEPKEY_SCREENSHOT=1 but 0 PNGs captured. ...")
    session.exitstatus = 1
```

## BIP-39 Rejection Test

**File**: `deps/python-keepkey/tests/test_msg_recoverydevice_cipher.py:170-208`

```python
def test_invalid_bip39_word_rejected(self):
    # Start cipher recovery with enforce_wordlist=True
    ret = self.client.call_raw(proto.RecoveryDevice(...))

    # Enter "zz" via cipher — not a BIP-39 word
    # ... character entry loop ...

    # Complete word with space
    ret = self.client.call_raw(proto.CharacterAck(character=' '))

    # Line 201: Firmware rejects immediately — no ButtonRequest
    self.assertIsInstance(ret, proto.Failure)
    self.assertIn("Word not found", ret.message)    # Line 202

    # Line 206-208: Manual screenshot capture after rejection
    import os as _os
    if _os.environ.get('KEEPKEY_SCREENSHOT') == '1' and self.client.debug:
        self.client._capture_oled()
```

**Key insight**: Firmware sends `Failure_SyntaxError` directly, NOT `ButtonRequest`.
The test calls `_capture_oled()` manually after the Failure to capture the OLED state.
The `is_animating()` guard (commit `22def600`) ensures the static warning screen
("Word not in wordlist") is NOT overwritten by animations when DebugLink reads the canvas.

## CI Pipeline Reference

### Docker files
- `scripts/emulator/Dockerfile` — builds emulator (cmake + make)
- `scripts/emulator/python-keepkey.Dockerfile` — test runner (`ENTRYPOINT ["/bin/sh", ...]`)
- `scripts/emulator/docker-compose.yml` — healthcheck (`python3 urllib`, NOT curl)
- `scripts/emulator/bridge.py` — Flask proxy with `/health` endpoint
- `scripts/emulator/python-keepkey-tests.sh` — test runner with fail-fast gate

### CI workflow — `.github/workflows/ci.yml`
- `if: ${{ !cancelled() }}` on `python-integration-tests` job
- `docker cp` with container ID logging (no `2>/dev/null || true`)
- `oled-screenshots` artifact upload with `if-no-files-found: warn`

### Branch triggers
```yaml
branches: [master, develop, alpha, p0, 'feat/**', 'feature/**', 'fix/**', 'release/**', 'hotfix/**']
```

## Commit Reference

| Commit | Branch | What |
|--------|--------|------|
| `22def600` | alpha | `is_animating()` guard in fsm_msg_debug.h |
| `428fa948` | alpha | fail-fast gate in test script |
| `b53f61cb` | alpha | pre-flight diagnostic + pytest -s |
| `b7d82f03` | p0 | messages.options max_size 1024→2048 |
| `41994ce9` | p0 | canvas layout packing (ported from alpha) |
| `b3c3385a` | p0 | fail-fast gate (cherry-pick from alpha) |
| `374af2b` | BitHighlander/python-keepkey | screenshot debug logging + conftest gate |

## Running Locally

```bash
# 1. Checkout alpha
cd projects/keepkey-firmware && git checkout alpha

# 2. Init submodules
git submodule update --init --recursive deps/python-keepkey
git submodule update --init deps/crypto/trezor-firmware deps/device-protocol

# 3. Build emulator (see toolchain requirements above)
# ... cmake + make ...

# 4. Start emulator
rm -f emulator.img && build-emu/bin/kkemu &

# 5. Run BIP-39 rejection test with screenshots
cd deps/python-keepkey/tests
KEEPKEY_SCREENSHOT=1 SCREENSHOT_DIR=/tmp/screenshots \
  pytest -v -x -s -k "test_invalid_bip39_word_rejected"

# 6. Verify
find /tmp/screenshots -name '*.png' -ls
# btn00001.png = "Word not in wordlist" OLED capture
```
