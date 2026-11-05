#!/usr/bin/env python3
"""Run ordinary regression suites beside the exact full Monero emulator.

The four CI screenshot tests execute the supplied dylib with fresh anonymous
flash. Native suites use its unchanged kkfirmware archive from the same build,
and run in new scratch directories so setup() cannot open an existing wallet.
These suites do not establish exhaustive coin or physical-device coverage.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
FW = HERE.parents[1]
NATIVE_SUITES = ("firmware-unit", "board-unit", "crypto-unit", "zcash-display-unit")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def junit(path):
    cases = ET.parse(path).getroot().findall(".//testcase")
    return {
        "tests": len(cases),
        "failures": sum(case.find("failure") is not None for case in cases),
        "errors": sum(case.find("error") is not None for case in cases),
        "skipped": sum(case.find("skipped") is not None or case.get("status") == "notrun"
                       for case in cases),
        "classes": sorted({case.get("classname", "") for case in cases}),
        "cases": [{"class": case.get("classname", ""), "name": case.get("name", ""),
                   "status": ("failed" if case.find("failure") is not None else
                              "error" if case.find("error") is not None else
                              "skipped" if case.find("skipped") is not None or case.get("status") == "notrun"
                              else "passed")} for case in cases],
    }


def screenshot_worker(out):
    # Import the pinned dependency from this worktree, ahead of editable installs.
    tests = FW / "deps/python-keepkey/tests"
    sys.path[:0] = [str(tests), str(tests.parent / "keepkeylib"), str(tests.parent)]
    os.chdir(tests)
    import pytest
    from keepkeylib.debuglink import DebugLink
    from keepkeylib.client import _write_png

    frames = []
    current = {"test": None}
    original = DebugLink.read_layout

    def capture(debug):
        layout = bytes(original(debug))
        if len(layout) != 2048:
            raise RuntimeError("CI screenshot capture must contain exactly 2048 OLED bytes")
        stem = "layout-%03d" % len(frames)
        raw, png = out / (stem + ".bin"), out / (stem + ".png")
        raw.write_bytes(layout)
        rows = [bytes(255 if layout[x + (y // 8) * 256] & (1 << (y % 8)) else 0
                      for x in range(256)) for y in range(64)]
        png.write_bytes(_write_png(str(png), 256, 64, rows))
        frames.append({"test": current["test"], "raw_path": raw.name,
                       "raw_sha256": sha(raw), "png_path": png.name,
                       "png_sha256": sha(png), "width": 256, "height": 64})
        return layout

    class Capture:
        def pytest_runtest_setup(self, item):
            current["test"] = item.nodeid

    DebugLink.read_layout = capture
    try:
        code = pytest.main(["test_dylib_screenshot.py", "-v", "--tb=short",
                            "--junit-xml=" + str(out / "junit.xml")], plugins=[Capture()])
    finally:
        DebugLink.read_layout = original
        (out / "frames.json").write_text(json.dumps(frames, indent=2) + "\n")
    return int(code)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--screenshot-worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    build, library, out = args.build.resolve(), args.library.resolve(), args.output.resolve()
    if args.screenshot_worker:
        return screenshot_worker(out)
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        parser.error("output directory must be empty")
    cache_path = build / "CMakeCache.txt"
    cache = {}
    for line in cache_path.read_text().splitlines():
        if not line or line.startswith(("#", "//")) or "=" not in line:
            continue
        key, value = line.split("=", 1)
        cache[key.split(":", 1)[0]] = value
    required = ("KK_EMULATOR", "KK_BUILD_DYLIB", "KK_DEBUG_LINK", "KK_MONERO_EMULATOR_RESEARCH",
                "KK_MONERO_KEY_IMAGE_PROTOCOL", "KK_MONERO_CORE_SIGNING")
    if any(cache.get(key) != "ON" for key in required) or cache.get("KK_BITCOIN_ONLY") != "OFF":
        parser.error("requires the regular full Core-enabled Monero research build")
    if Path(cache["CMAKE_HOME_DIRECTORY"]).resolve() != FW or not library.is_relative_to(build):
        parser.error("library and CMake build must belong to this firmware worktree")
    archives = list(build.rglob("libkkfirmware.a"))
    if len(archives) != 1:
        parser.error("expected one already-built kkfirmware archive")
    archive = archives[0]
    core_link = Path(cache["KK_MONERO_CORE_LINK_CMAKE"])
    core_import = re.search(r'IMPORTED_LOCATION "([^"]+)"', core_link.read_text())
    if not core_import:
        parser.error("pinned native Core link must identify its imported library")
    core_library = Path(core_import.group(1))
    core_hash = sha(core_library)
    env = dict(os.environ)
    # Dylib selection prevents physical-device enumeration and allocates erased
    # anonymous flash. Standard CI's public test root is used for its fixtures.
    env.update(KK_TRANSPORT="dylib", KK_DYLIB=str(library),
               KK_CLEARSIGN_TEST_ROOT="02de9231b2094433235532fb1932e324a2c7304195e12e610c675cccbbd606dae7")
    env.pop("KEEPKEY_SCREENSHOT", None)
    env.pop("KEEPKEY_SCREENSHOT_TESTS", None)
    env.pop("KEEPKEY_UDP_PORT", None)  # Native confirmation fixtures use 11044.
    env["PYTHONPATH"] = os.pathsep.join([str(FW / "deps/python-keepkey/keepkeylib"),
                                         str(FW / "deps/python-keepkey")])
    env["PATH"] = os.pathsep.join([str(Path(sys.executable).parent),
                                    str(Path(cache["NANOPB_DIR"]) / "generator"), env["PATH"]])
    steps = []

    def run(command, name, cwd, timeout=600):
        start = time.monotonic()
        print(name, flush=True)
        with (out / (name + ".log")).open("w") as log:
            log.write(json.dumps([str(x) for x in command]) + "\n")
            log.flush()
            try:
                completed = subprocess.run([str(x) for x in command], cwd=cwd, env=env,
                                           stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
                code = completed.returncode
            except subprocess.TimeoutExpired:
                log.write("\nTimed out after %s seconds\n" % timeout)
                code = 124
        steps.append({"name": name, "command": [str(x) for x in command], "cwd": str(cwd),
                      "returncode": code, "elapsed_seconds": time.monotonic() - start,
                      "log": name + ".log"})
        return code

    # Use one aggregate dependency graph. Multiple top-level make targets each
    # rerun the always-built token generator and can rebuild the common archive
    # between links. Freeze identities only after this single build completes.
    configure_code = run(["cmake", "-S", FW, "-B", build], "native-configure", out)
    build_code = run(["cmake", "--build", build, "--target", "monero-emulator-compatibility", "-j8"],
                     "native-build", out)
    original_library_hash, original_archive_hash = sha(library), sha(archive)
    def firmware_objects():
        return {str(path.relative_to(build)): sha(path)
                for path in sorted((build / "lib/firmware/CMakeFiles/kkfirmware.dir").rglob("*.o"))}
    frozen_objects = firmware_objects()
    print(json.dumps({"frozen_library_sha256": original_library_hash,
                      "frozen_firmware_archive_sha256": original_archive_hash}), flush=True)
    native = []
    if build_code == 0:
        for name in NATIVE_SUITES:
            # Existing native fixtures hardcode 11044/11045. Refuse an occupied
            # pair rather than interacting with an independently running emulator.
            sockets = []
            try:
                for port in (11044, 11045):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sockets.append(sock)
                    sock.bind(("127.0.0.1", port))
            finally:
                for sock in sockets:
                    sock.close()
            scratch = out / name
            scratch.mkdir()
            binary = build / "bin" / name
            report = scratch / "junit.xml"
            # The full alpha firmware suite already takes about 12 minutes in
            # ordinary CI; retain its controls instead of timing out at ten.
            code = run([binary, "--gtest_output=xml:" + str(report)], name, scratch,
                       timeout=1200 if name == "firmware-unit" else 600)
            result = junit(report) if report.exists() else {"tests": 0, "failures": 0, "errors": 1, "skipped": 0}
            native.append({"name": name, "returncode": code, "binary": str(binary),
                           "binary_sha256": sha(binary), "junit": str(report.relative_to(out)),
                           "junit_sha256": sha(report) if report.exists() else None, **result})
    screenshots = out / "dylib-screenshots"
    screenshots.mkdir()
    worker = [sys.executable, Path(__file__).resolve(), "--build", build, "--library", library,
              "--output", screenshots, "--screenshot-worker"]
    screenshot_code = run(worker, "dylib-screenshots", screenshots)
    screenshot_xml = screenshots / "junit.xml"
    screenshot_result = junit(screenshot_xml) if screenshot_xml.exists() else {"tests": 0, "errors": 1}
    frames = json.loads((screenshots / "frames.json").read_text()) if (screenshots / "frames.json").exists() else []
    objects = firmware_objects()
    unchanged = (sha(library) == original_library_hash and sha(archive) == original_archive_hash and
                 sha(core_library) == core_hash and objects == frozen_objects)
    passed = (screenshot_code == 0 and screenshot_result["tests"] == 4 and len(frames) > 0 and
              configure_code == 0 and build_code == 0 and len(native) == len(NATIVE_SUITES) and
              all(item["returncode"] == 0 and item["tests"] > 0 and not item["failures"] and not item["errors"]
                  for item in native) and unchanged and bool(objects))
    report = {
        "schema_version": 1, "status": "pass" if passed else "fail",
        "firmware_commit": subprocess.check_output(["git", "-C", str(FW), "rev-parse", "HEAD"], text=True).strip(),
        "library": str(library), "library_sha256": original_library_hash,
        "same_artifact_unchanged": unchanged,
        "build_directory": str(build), "cmake_cache_sha256": sha(cache_path),
        "configuration": {key: cache.get(key) for key in (*required, "KK_BITCOIN_ONLY", "CMAKE_BUILD_TYPE")},
        "firmware_archive": str(archive), "firmware_archive_sha256": original_archive_hash,
        "firmware_object_sha256": objects,
        "core_link_cmake": str(core_link), "core_link_cmake_sha256": sha(core_link),
        "core_library": str(core_library), "core_library_sha256": core_hash,
        "dylib_screenshot_suite": {"returncode": screenshot_code, "junit": "dylib-screenshots/junit.xml",
                                  "junit_sha256": sha(screenshot_xml) if screenshot_xml.exists() else None,
                                  "frames": frames, **screenshot_result},
        "native_suites": native, "steps": steps,
        "source_sha256": {str(path.relative_to(FW)): sha(path) for path in [
            Path(__file__), HERE / "commands-overlay.cmake", FW / "deps/python-keepkey/tests/test_dylib_screenshot.py",
            FW / "deps/python-keepkey/keepkeylib/transport_dylib.py", FW / "unittests/firmware/CMakeLists.txt"]},
        "scope": "Exact full dylib: four standard CI screenshot/transport tests. Ordinary native suites: unchanged firmware objects/archive from that same build; these are separate executables, not dylib transaction tests.",
        "exhaustive_coin_coverage": False, "physical_device_accessed": False,
        "wallet_data": "fresh anonymous dylib flash; native setup uses new per-suite scratch directories; public fixtures only",
        "production_ready": False,
    }
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "output": str(out), "library_sha256": original_library_hash,
                      "dylib_tests": screenshot_result.get("tests", 0),
                      "native_tests": {item["name"]: item["tests"] for item in native}}, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
