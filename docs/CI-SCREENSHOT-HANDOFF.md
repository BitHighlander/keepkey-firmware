# CI Screenshot Pipeline — Agent Handoff Guide

Status: WORKING on alpha (run 23673308446 produced 4 PNGs). Needs to be landed on p0/develop.

## What Works (Proven)

The complete pipeline runs end-to-end when these conditions are met:

1. **Emulator builds with DEBUG_LINK=ON** (`cmake/caches/emulator.cmake` line 2)
2. **python-keepkey has `_capture_oled()` with the PNG writer** (any version ≥ `4ed90c7`)
3. **Test script sets `KEEPKEY_SCREENSHOT=1`** and `SCREENSHOT_DIR=...`
4. **Tests trigger `callback_ButtonRequest`** which calls `_capture_oled()`
5. **`test_wipe_device` is the proven smoke test** — always triggers 2 ButtonRequests

## The 3 Things That Must Be True for Screenshots

```
1. python-integration-tests job must RUN    → if: ${{ !cancelled() }}
2. Emulator must be READY before tests      → healthcheck or wait loop
3. Test must trigger ButtonRequest          → -k "test_wipe_device"
```

If any of these fail, you get 0 PNGs with no error.

## Current Branch State

| Branch | .gitmodules python-keepkey URL | Pin | Has CI fixes | Screenshots work? |
|--------|-------------------------------|-----|-------------|-------------------|
| `alpha` | BitHighlander/python-keepkey | `4f34e35` (debug logging) | YES (all fixes) | YES (proven) |
| `feat/ci-screenshot-docs` | BitHighlander/python-keepkey | `4f34e35` | YES (all fixes) | Should work (not tested) |
| `p0` | keepkey/python-keepkey | `4ed90c7` (upstream) | NO | NO (missing CI fixes) |
| `develop` | keepkey/python-keepkey | varies | NO | NO (missing CI fixes) |
| `upstream/master` | keepkey/python-keepkey | `f1dd2b6` | NO | NO |

## What p0 Needs (Minimum Viable)

Apply these changes to p0 (PR #180 `feat/ci-screenshot-docs → p0` already has them):

### 1. ci.yml — 3 changes

```yaml
# A. Add !cancelled() guard (line ~386)
python-integration-tests:
  needs: [check-submodules, secret-scan]
  if: ${{ !cancelled() }}  # <-- ADD THIS

# B. Add screenshot upload step (after "Upload Python test results")
- name: Upload OLED screenshots
  uses: actions/upload-artifact@v4
  if: always()
  with:
    name: oled-screenshots
    path: test-reports/screenshots/
    retention-days: 90
    if-no-files-found: warn

# C. Replace silent docker cp with visible extraction
# REMOVE:  docker cp "$(docker compose ps -a -q python-keepkey)":/kkemu/test-reports/. ... 2>/dev/null || true
# ADD:
PY_CONTAINER=$(docker compose ps -a -q python-keepkey)
echo "python-keepkey container: $PY_CONTAINER"
docker cp "$PY_CONTAINER":/kkemu/test-reports/. ${{ github.workspace }}/test-reports/ || echo "WARN: docker cp failed"
find ${{ github.workspace }}/test-reports/screenshots -name '*.png' 2>/dev/null | wc -l
```

### 2. python-keepkey-tests.sh — Replace entire file

The working version uses:
- Emulator wait loop (nc UDP probe OR python3 socket probe)
- Phase 1: `KEEPKEY_SCREENSHOT=1 pytest -v -x -k "test_wipe_device"`
- Screenshot count reporting
- Phase 2: full suite without screenshots

**Critical**: Must be `/bin/sh` compatible. NO bash-isms:
- NO `${PIPESTATUS[0]}`
- NO `{ cmd; } | tee`
- NO `#!/bin/bash`

### 3. docker-compose.yml — Add healthcheck (OPTIONAL but recommended)

```yaml
kkemu:
  healthcheck:
    test: ["CMD-SHELL", "python3 -c \"import urllib.request; urllib.request.urlopen('http://localhost:5000/health')\" || exit 1"]
    interval: 3s
    timeout: 3s
    retries: 20
    start_period: 10s
python-keepkey:
  depends_on:
    kkemu:
      condition: service_healthy
```

Requires `/health` endpoint in `bridge.py`:
```python
@app.route('/health')
def health():
    return Response('{"status":"ok"}', status=200, mimetype='application/json')
```

**TRAP**: `curl` is NOT in `kktech/firmware:v15`. Must use `python3 urllib`.

### 4. python-keepkey fork pin (OPTIONAL but recommended for debugging)

To get `[SCREENSHOT] OK/SKIP/ERROR` diagnostic output:
```
.gitmodules: url = https://github.com/BitHighlander/python-keepkey.git
submodule pin: 4f34e35 (fix/screenshot-debug branch)
```

The upstream code at `4ed90c7` ALSO works for screenshots — it just has `except Exception: pass` so failures are silent.

## The 10 Traps (Ordered by Pain Caused)

### 1. `if: ${{ !cancelled() }}` missing → job cancelled by ARM failures
ARM builds fail on alpha (Zcash protos, const qualifiers). Without `!cancelled()`, python tests get cancelled. You see "cancelled" status with zero artifacts. **Fix: always add the guard.**

### 2. `-k` filter selects tests that SKIP on BTC-only emulator → 0 ButtonRequests
BIP85, Solana, Tron, TON tests all SKIP because the emulator is BTC-only. Only `test_wipe_device` and basic BTC tests run. If your `-k` filter only matches multi-chain tests, you get 0 screenshots. **Fix: always include `test_wipe_device`.**

### 3. `except Exception: pass` in `_capture_oled()` → silent failure
If `debug.read_layout()` returns empty bytes, or PNG write fails, or any exception — swallowed. Zero output. Tests still pass. **Fix: use fork pin for debug logging, or accept upstream and rely on screenshot count check.**

### 4. `curl` not in Docker image → healthcheck fails → "unhealthy" → tests never start
`kktech/firmware:v15` has Python but NOT curl. **Fix: `python3 -c "import urllib.request; urllib.request.urlopen(...)"`**

### 5. `/bin/sh` not bash → script syntax errors
`python-keepkey.Dockerfile` uses `/bin/sh`. `PIPESTATUS`, brace groups, bashisms all fail. **Fix: test your script with `dash` or `busybox sh`.**

### 6. `--timeout=120` → pytest-timeout not installed
**Fix: don't use it. CI job timeout (30 min) is the safety net.**

### 7. `docker cp ... 2>/dev/null || true` → extraction failures invisible
**Fix: log container ID, remove stderr suppression, count files after.**

### 8. Debug link UDP port (11045) doesn't respond to raw probes
Sending raw `DebugLinkGetState` bytes to UDP 11045 times out. The emulator expects proper protobuf framing through the transport layer. **Fix: don't probe port 11045 directly. Test it implicitly via pytest.**

### 9. `layout too small (0 bytes)` → emulator display not initialized
If the test runs before any screen is rendered (before `layoutHome()`), the canvas is empty. The wipe test avoids this because `setUp()` calls `wipe_device()` which renders a confirmation screen.

### 10. Branch triggers missing → CI doesn't run on push
Develop's `ci.yml` didn't have `alpha`, `p0`, or `feat/**` in the branch list. **Fix: add them.**

## Debugging When Screenshots Are 0

```
Step 1: Was python-integration-tests cancelled?
  → Check job status. If cancelled, add if: !cancelled()

Step 2: Did the emulator Docker image build?
  → Look for "make -j" success or "ERROR" in build logs

Step 3: Did tests actually run?
  → Look for "PASSED" or "FAILED" in Phase 1 output
  → If all SKIPPED, fix the -k filter

Step 4: Did _capture_oled() run?
  → If using fork pin: look for [SCREENSHOT] lines in stderr
  → If using upstream: no way to tell (silent pass)

Step 5: Were files extracted from Docker?
  → Look for container ID logging and file count
  → "Screenshot PNGs: N" should be > 0

Step 6: Was the artifact uploaded?
  → Look for "Artifact oled-screenshots has been successfully uploaded"
  → If "Warning: No files were found", the path was empty
```

## Local Docker Test (Fastest Verification)

```bash
cd /path/to/keepkey-firmware
cd scripts/emulator
docker compose up --build python-keepkey
# Wait for it to finish, then:
docker cp "$(docker compose ps -a -q python-keepkey)":/kkemu/test-reports/screenshots/. /tmp/screenshots/
find /tmp/screenshots -name '*.png' -ls
```

If this produces PNGs locally but not in CI, the issue is in ci.yml (job cancellation, docker cp, artifact upload).

## File Reference

| File | What to check |
|------|--------------|
| `.github/workflows/ci.yml:~386` | `if: !cancelled()` on python-integration-tests |
| `.github/workflows/ci.yml:~412` | docker cp with logging (no `2>/dev/null || true`) |
| `.github/workflows/ci.yml:~428` | Upload OLED screenshots step exists |
| `scripts/emulator/python-keepkey-tests.sh` | `/bin/sh` shebang, `-k "test_wipe_device"`, `KEEPKEY_SCREENSHOT=1` |
| `scripts/emulator/docker-compose.yml` | healthcheck on kkemu, `service_healthy` condition |
| `scripts/emulator/bridge.py` | `/health` endpoint exists |
| `scripts/emulator/python-keepkey.Dockerfile` | `/bin/sh` entrypoint (NOT bash) |
| `deps/python-keepkey/keepkeylib/client.py:~463` | `_capture_oled()` method |
| `deps/python-keepkey/tests/conftest.py:~11` | `KEEPKEY_SCREENSHOT` check |
| `include/keepkey/transport/messages.options:112` | `DebugLinkState.layout max_size:2048` |
| `cmake/caches/emulator.cmake:2` | `KK_DEBUG_LINK ON` |
