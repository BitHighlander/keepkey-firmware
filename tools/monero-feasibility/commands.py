#!/usr/bin/env python3
"""Build an opt-in native emulator and test Monero address messages over HID."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
FW = HERE.parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reference", type=Path, default=HERE / "evidence/2026-11-04-interoperability/host.json")
    parser.add_argument("--core-library", type=Path, required=True,
                        help="Independently built pinned Monero Core reference library")
    args = parser.parse_args()
    root, out = args.toolchain_root.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        parser.error("output directory must be empty; preserve earlier evidence")
    env = dict(os.environ)
    env.pop("KK_CLEARSIGN_TEST_ROOT", None)
    env["PATH"] = os.pathsep.join([str(root / "pyk-venv/bin"),
                                    str(root / "nanopb/generator"), env["PATH"]])

    def run(command, log):
        with (out / log).open("w") as stream:
            stream.write(json.dumps(list(map(str, command))) + "\n")
            stream.flush()
            result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, env=env)
        if result.returncode:
            raise RuntimeError(f"command failed; see {out / log}")

    configuration = ["-DKK_EMULATOR=ON", "-DKK_BUILD_DYLIB=ON", "-DKK_DEBUG_LINK=ON",
         "-DKK_BITCOIN_ONLY=OFF", "-DCMAKE_BUILD_TYPE=Debug",
         "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
         "-DCMAKE_C_FLAGS=-DPB_NO_PACKED_STRUCTS=1",
         "-DCMAKE_CXX_FLAGS=-DPB_NO_PACKED_STRUCTS=1",
         f"-DNANOPB_DIR={root / 'nanopb'}", f"-DPROTOC_BINARY={root / 'protoc351/bin/protoc'}"]
    build = out / "build"
    run(["cmake", "-S", str(FW), "-B", str(build), *configuration,
         f"-DCMAKE_PROJECT_KeepKeyFirmware_INCLUDE={HERE / 'commands-overlay.cmake'}",
         "-DKK_MONERO_EMULATOR_RESEARCH=ON"], "configure.log")
    run(["cmake", "--build", str(build), "--target", "kkemulator_dylib", "-j8"], "build.log")
    header = build / "monero-research/messages-monero-research.pb.h"
    if "pb_callback_t" in header.read_text():
        raise RuntimeError("research protobuf must use bounded fields")
    libraries = list(build.rglob("libkkemu.dylib" if sys.platform == "darwin" else "libkkemu.so"))
    if len(libraries) != 1:
        raise RuntimeError("expected one research libkkemu")
    library = libraries[0]
    run([sys.executable, str(HERE / "commands/test_crypto.py"),
         "--reference", str(args.reference.resolve()),
         "--core-library", str(args.core_library.resolve()),
         "--output", str(out / "crypto")], "crypto.log")
    run([sys.executable, str(HERE / "commands/test_wire.py"),
         "--library", str(library), "--reference", str(args.reference.resolve()),
         "--core-library", str(args.core_library.resolve()),
         "--output", str(out / "wire")], "wire.log")
    result = json.loads((out / "wire/result.json").read_text())
    if result.get("status") != "pass":
        raise RuntimeError("wire test did not pass")
    # A paired ordinary emulator proves the wire capability is opt-in.
    ordinary = out / "default-build"
    run(["cmake", "-S", str(FW), "-B", str(ordinary), *configuration], "default-configure.log")
    run(["cmake", "--build", str(ordinary), "--target", "kkemulator_dylib", "-j8"], "default-build.log")
    ordinary_libraries = list(ordinary.rglob("libkkemu.dylib" if sys.platform == "darwin" else "libkkemu.so"))
    if len(ordinary_libraries) != 1:
        raise RuntimeError("expected one ordinary libkkemu")
    run([sys.executable, str(HERE / "commands/test_wire.py"),
         "--library", str(ordinary_libraries[0]), "--expect-unsupported",
         "--output", str(out / "default-wire")], "default-wire.log")
    control = json.loads((out / "default-wire/result.json").read_text())
    crypto = json.loads((out / "crypto/result.json").read_text())
    if control.get("status") != "pass" or crypto.get("status") != "pass":
        raise RuntimeError("negative control or sanitizer checks did not pass")
    inputs = [Path(__file__), HERE / "commands-overlay.cmake",
              *[p for p in (HERE / "commands").rglob("*")
                if p.is_file() and "__pycache__" not in p.parts],
              FW / "lib/firmware/fsm.c", FW / "lib/firmware/messagemap.def"]
    report = {
        "schema_version": 1, "status": "pass", "wire": result,
        "crypto": crypto, "default_build_negative_control": control,
        "execution": "native KeepKey libkkemu, real protobuf dispatch and HID packet rings",
        "firmware_commit": subprocess.check_output(["git", "-C", str(FW), "rev-parse", "HEAD"], text=True).strip(),
        "crypto_commit": subprocess.check_output(["git", "-C", str(FW / 'deps/crypto/trezor-firmware'), "rev-parse", "HEAD"], text=True).strip(),
        "shared_library_sha256": hashlib.sha256(library.read_bytes()).hexdigest(),
        "reference_sha256": hashlib.sha256(args.reference.read_bytes()).hexdigest(),
        "core_library_sha256": hashlib.sha256(args.core_library.read_bytes()).hexdigest(),
        "source_sha256": {str(p.relative_to(FW)): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in sorted(set(inputs))},
        "physical_device_accessed": False, "production_ready": False,
    }
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": "pass", "output": str(out), "wire": result}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
