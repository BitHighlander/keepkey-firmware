# CI OLED Screenshot Pipeline

Captures KeepKey OLED display screenshots from the emulator during CI test runs and uploads them as artifacts.

**Status**: Working as of 2026-03-27 (run 23673308446 on BitHighlander/keepkey-firmware alpha)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  GitHub Actions Runner (ubuntu-latest)                      │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Docker Compose (scripts/emulator/docker-compose.yml)│    │
│  │                                                     │    │
│  │  ┌──────────┐  healthcheck   ┌──────────────────┐   │    │
│  │  │  kkemu   │◄──────────────│  python-keepkey   │   │    │
│  │  │          │  depends_on:   │                  │   │    │
│  │  │ emulator │  service_      │ pytest + capture │   │    │
│  │  │ binary   │  healthy       │                  │   │    │
│  │  │          │                │ writes PNGs to   │   │    │
│  │  │ UDP:11044│◄──main────────│ /kkemu/test-     │   │    │
│  │  │ UDP:11045│◄──debug───────│  reports/         │   │    │
│  │  │ TCP:5000 │  (DebugLink)  │  screenshots/    │   │    │
│  │  │ (bridge) │                │                  │   │    │
│  │  └──────────┘                └──────────────────┘   │    │
│  │                                    │                │    │
│  │                              shared volume:         │    │
│  │                              test-reports           │    │
│  └─────────────────────────────────────────────────────┘    │
│           │                                                 │
│     docker cp                                               │
│           │                                                 │
│           ▼                                                 │
│  test-reports/screenshots/*.png                             │
│           │                                                 │
│     upload-artifact@v4                                      │
│           │                                                 │
│           ▼                                                 │
│  Artifact: oled-screenshots (90 day retention)              │
└─────────────────────────────────────────────────────────────┘
```

## How Screenshots Are Captured

### Firmware Side (C)

**File**: `lib/firmware/fsm_msg_debug.h`

`fsm_msgDebugLinkGetState()` handles `DebugLinkGetState` messages:

1. Calls `force_animation_start()` + `animate()` + `display_refresh()` to ensure pending animations render
2. Gets the 256x64 grayscale canvas via `display_canvas()`
3. Packs it into 1bpp layout (2048 bytes): each byte holds 8 vertical pixels, LSB = top
4. Sets `resp->layout.size = 2048` and sends `DebugLinkState` response

**Proto constraint**: `messages.options` line 112: `DebugLinkState.layout max_size:2048`

### Python Side (keepkeylib)

**File**: `deps/python-keepkey/keepkeylib/client.py`

`_capture_oled()` is called from `callback_ButtonRequest()` BEFORE pressing the button:

1. Checks `KEEPKEY_SCREENSHOT` env var == `'1'`
2. Checks `self.debug` link exists
3. Calls `self.debug.read_layout()` → sends `DebugLinkGetState` over debug transport (UDP:11045)
4. If layout >= 1024 bytes, converts 1bpp → 8bpp grayscale rows
5. Writes 256x64 PNG to `screenshot_dir/btn%05d.png`

### Test Framework

**File**: `deps/python-keepkey/tests/conftest.py`

Patches `KeepKeyTest.setUp()` to create per-test screenshot directories:
```
screenshots/{module}/{test_name}/btn00000.png
screenshots/{module}/{test_name}/btn00001.png
```

## Critical Files

| File | Role |
|------|------|
| `.github/workflows/ci.yml` | CI orchestration, docker compose, artifact upload |
| `scripts/emulator/docker-compose.yml` | Container orchestration with healthcheck |
| `scripts/emulator/Dockerfile` | Builds emulator binary (cmake + clang) |
| `scripts/emulator/python-keepkey.Dockerfile` | Test runner container |
| `scripts/emulator/python-keepkey-tests.sh` | Test execution script (Phase 1 screenshots, Phase 2 full suite) |
| `scripts/emulator/bridge.py` | Flask HTTP→UDP proxy with `/health` endpoint |
| `scripts/emulator/run.sh` | Starts bridge.py (background) + emulator binary |
| `deps/python-keepkey/keepkeylib/client.py` | `_capture_oled()` screenshot capture |
| `deps/python-keepkey/tests/conftest.py` | Per-test screenshot directory setup |
| `deps/python-keepkey/tests/config.py` | Transport config (UDP for emulator) |
| `include/keepkey/transport/messages.options` | nanopb constraints (`max_size:2048`) |
| `lib/firmware/fsm_msg_debug.h` | Firmware DebugLinkGetState handler |

## Fragile Points (Lessons Learned)

These were discovered over 50+ CI runs. Each one silently breaks screenshots with zero error output unless you know what to look for.

### 1. Docker Healthcheck (CRITICAL)

**Problem**: `depends_on: kkemu` only ensures container start ORDER, not service READINESS. Tests start before the emulator binary is listening on UDP.

**Symptom**: Tests timeout or fail with no screenshot output at all. `_capture_oled()` is never called because no `ButtonRequest` is ever received.

**Fix**: `docker-compose.yml` must have a healthcheck on `kkemu` and `depends_on: condition: service_healthy`.

**Trap**: `curl` is NOT installed in `kktech/firmware:v15`. Use `python3 urllib`:
```yaml
healthcheck:
  test: ["CMD-SHELL", "python3 -c \"import urllib.request; urllib.request.urlopen('http://localhost:5000/health')\" || exit 1"]
```

Requires `/health` endpoint in `bridge.py`.

### 2. Shell Compatibility (CRITICAL)

**Problem**: `python-keepkey.Dockerfile` uses `ENTRYPOINT ["/bin/sh", ...]`. The test script MUST be `/bin/sh` compatible.

**Will break**:
- `${PIPESTATUS[0]}` — bash-only, causes `syntax error: bad substitution`
- `{ cmd; } | tee` — causes `syntax error: unexpected "}"`
- `#!/bin/bash` — may not exist in the image

**Safe patterns**:
```sh
# Capture exit code without PIPESTATUS:
cmd 2>&1 | tee logfile || true

# Export env vars separately (not inline with complex pipes):
export KEEPKEY_SCREENSHOT=1
export SCREENSHOT_DIR=/path
pytest ...
```

### 3. pytest-timeout Not Installed

**Problem**: `--timeout=120` causes `pytest: error: unrecognized arguments`.

**Fix**: Don't use `--timeout`. The emulator tests are fast (~1s each). If something hangs, the CI job timeout (30 min) will catch it.

### 4. Phase 1 Test Selection (CRITICAL)

**Problem**: The `-k` filter must match tests that actually EXIST and RUN on a BTC-only emulator.

**Will NOT work** (all SKIPPED on BTC-only build):
- `test_bip85` — requires `GetFeatures.capabilities` check
- `test_solana_get` — Solana not compiled in
- `test_tron_get` — Tron not compiled in
- `test_ton_get` — TON not compiled in

**Will work** (triggers `ButtonRequest` → `_capture_oled()`):
- `test_wipe_device` — always works, 2 button prompts = 2 screenshots
- `test_get_address` (from `test_protection_levels`) — works but no `ButtonRequest`

**Best smoke test**: `-k "test_wipe_device"` — fast, reliable, proves the entire pipeline.

### 5. `_capture_oled()` Silent Exception Swallowing

**Problem**: Upstream `keepkeylib/client.py` has `except Exception: pass` in `_capture_oled()`. If screenshots fail, you get ZERO diagnostic output.

**Fix**: Pin to fork branch `fix/screenshot-debug` on `BitHighlander/python-keepkey` which adds:
```
[SCREENSHOT] OK: /path/btn00000.png (2048 bytes layout)
[SCREENSHOT] SKIP: no debug link
[SCREENSHOT] SKIP: layout too small (0 bytes)
[SCREENSHOT] ERROR: <exception with traceback>
```

**To switch back to upstream later**: Change `.gitmodules` URL back to `keepkey/python-keepkey` and update submodule pin.

### 6. `if: ${{ !cancelled() }}` on python-integration-tests Job (CRITICAL)

**Problem**: ARM firmware builds (build-arm-firmware, build-arm-firmware-btc-only) share the `needs` chain. If ARM builds fail, GitHub Actions CANCELS the python-integration-tests job by default.

**Symptom**: Python tests show as "cancelled" even though they have nothing to do with ARM compilation. No screenshots, no test results.

**Fix**: Add `if: ${{ !cancelled() }}` to the python-integration-tests job so it runs regardless of ARM build failures.

### 7. docker cp Extraction

**Problem**: Original code used `2>/dev/null || true` which silently swallows extraction failures.

**Symptom**: Screenshot upload succeeds with an empty artifact (no warning).

**Fix**: Log the container IDs, remove stderr suppression, add file listing:
```yaml
PY_CONTAINER=$(docker compose ps -a -q python-keepkey)
echo "python-keepkey container: $PY_CONTAINER"
docker cp "$PY_CONTAINER":/kkemu/test-reports/. ./test-reports/ || echo "WARN: docker cp failed"
find ./test-reports/screenshots -name '*.png' | wc -l
```

### 8. Layout Size 0 Bytes

**Problem**: `_capture_oled()` gets `layout` with 0 bytes from `DebugLinkGetState`.

**Root causes**:
- `display_canvas()` returns canvas with null buffer (display not initialized)
- Firmware compiled without `DEBUG_LINK` — `fsm_msgDebugLinkGetState` not registered
- Test ran before any screen was rendered (no `layoutHome()` called yet)

**Diagnosis**: Look for `[SCREENSHOT] SKIP: layout too small (0 bytes)` in stderr (requires fork pin).

### 9. conftest.py Module Name Detection

**Problem**: `conftest.py` derives the screenshot subdirectory from the test ID. If it can't parse the module name, it uses `unknown/`.

**Symptom**: Screenshots appear in `screenshots/unknown/test_name/` instead of `screenshots/module/test_name/`. Not a functional issue but messy.

### 10. Emulator Debug Port (UDP 11045)

**Problem**: The debug transport (port 11045) does NOT respond to raw UDP probes. Sending `DebugLinkGetState` as raw bytes to the port times out — the emulator expects the full protobuf wire format through its transport layer.

**Symptom**: A "verify debug link" probe wastes 60s and always fails.

**Fix**: Don't probe port 11045 directly. The debug transport is tested implicitly when `_capture_oled()` calls `self.debug.read_layout()` through the proper python transport stack.

## Environment Variables

| Variable | Set In | Value | Purpose |
|----------|--------|-------|---------|
| `KEEPKEY_SCREENSHOT` | test script | `1` | Enables `_capture_oled()` in client.py |
| `SCREENSHOT_DIR` | test script | `/kkemu/test-reports/screenshots` | Base directory for PNG output |
| `KK_TRANSPORT_MAIN` | test script | `kkemu:11044` | Emulator main UDP (docker hostname) |
| `KK_TRANSPORT_DEBUG` | test script | `kkemu:11045` | Emulator debug UDP (docker hostname) |

## Debugging Checklist

When screenshots don't appear in CI artifacts:

1. **Check if python-integration-tests was cancelled** — look for `if: ${{ !cancelled() }}` on the job
2. **Check if emulator built** — look for `make -j` success in docker build logs
3. **Check if healthcheck passed** — look for `healthy` in container logs, or `unhealthy` → fix healthcheck
4. **Check if emulator responded** — look for `Emulator ready` in test output
5. **Check Phase 1 test results** — look for PASSED vs SKIPPED. All SKIPPED = wrong `-k` filter
6. **Check `[SCREENSHOT]` lines** — requires fork pin. Look in captured stderr or `screenshot-debug.log`
7. **Check docker cp** — look for container IDs and file count in extraction step
8. **Check artifact upload** — `if-no-files-found: warn` will flag empty uploads

## Local Testing

```bash
# Build emulator locally (macOS ARM64)
cd /path/to/keepkey-firmware
eval "$(pyenv init -)"
pyenv shell 3.10.15
cmake -C cmake/caches/emulator.cmake . -DCMAKE_BUILD_TYPE=Debug
make -j

# Run emulator
./bin/kkemu &

# Run screenshot test
cd deps/python-keepkey/tests
KEEPKEY_SCREENSHOT=1 \
SCREENSHOT_DIR=/tmp/screenshots \
pytest -v -x -k "test_wipe_device" 2>&1

# Check results
find /tmp/screenshots -name '*.png' -ls
```

## Version History

| Date | Change | CI Runs |
|------|--------|---------|
| 2026-03-27 | Initial working pipeline | ~50 runs to diagnose |
| Key fix | `if: !cancelled()` prevents ARM failures from killing python tests | |
| Key fix | `python3 urllib` healthcheck (curl not in image) | |
| Key fix | sh-compatible script (no bash-isms) | |
| Key fix | `-k "test_wipe_device"` (BTC-only compatible) | |
| Key fix | Fork pin for `[SCREENSHOT]` debug logging | |
