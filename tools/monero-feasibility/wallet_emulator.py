#!/usr/bin/env python3
"""Build and verify the complete bounded Monero wallet experiment in libkkemu.

All signing inputs are synthetic, all seeds are public fixtures, and no
transaction is mined, relayed or broadcast. No physical device is accessed.
"""
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
    parser.add_argument("--engine-link", type=Path,
                        help="core-link.cmake emitted by build_core.py")
    parser.add_argument("--receive-only", action="store_true",
                        help="Build address/watch/key-image support without the native Core signing dependency")
    parser.add_argument("--core-library", type=Path, required=True,
                        help="Independent reference.py crypto library")
    parser.add_argument("--reference", type=Path,
                        default=HERE / "evidence/2026-11-04-interoperability/host.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--build-only", action="store_true")
    args = parser.parse_args()
    if not args.receive_only and not args.engine_link:
        parser.error("--engine-link is required unless --receive-only is selected")
    root, out = args.toolchain_root.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        parser.error("output directory must be empty")
    env = dict(os.environ)
    env.pop("KK_CLEARSIGN_TEST_ROOT", None)
    env["PATH"] = os.pathsep.join([str(root / "pyk-venv/bin"),
                                    str(root / "nanopb/generator"), env["PATH"]])

    def run(command, name):
        print(name, flush=True)
        with (out / (name + ".log")).open("w") as log:
            log.write(json.dumps(list(map(str, command))) + "\n")
            log.flush()
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, env=env)
        if result.returncode:
            raise RuntimeError(f"failed: {out / (name + '.log')}")

    configuration = ["-DKK_EMULATOR=ON", "-DKK_BUILD_DYLIB=ON", "-DKK_DEBUG_LINK=ON",
                     "-DKK_BITCOIN_ONLY=OFF", "-DCMAKE_BUILD_TYPE=Debug",
                     "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
                     "-DCMAKE_C_FLAGS=-DPB_NO_PACKED_STRUCTS=1",
                     "-DCMAKE_CXX_FLAGS=-DPB_NO_PACKED_STRUCTS=1",
                     f"-DNANOPB_DIR={root / 'nanopb'}",
                     f"-DPROTOC_BINARY={root / 'protoc351/bin/protoc'}"]
    build = out / "build"
    research_configuration = ["-DKK_MONERO_EMULATOR_RESEARCH=ON", "-DKK_MONERO_KEY_IMAGE_PROTOCOL=ON",
                              f"-DKK_MONERO_CORE_SIGNING={'OFF' if args.receive_only else 'ON'}"]
    if not args.receive_only:
        research_configuration.append(f"-DKK_MONERO_CORE_LINK_CMAKE={args.engine_link.resolve()}")
    run(["cmake", "-S", str(FW), "-B", str(build), *configuration,
         f"-DCMAKE_PROJECT_KeepKeyFirmware_INCLUDE={HERE / 'commands-overlay.cmake'}",
         *research_configuration], "configure")
    run(["cmake", "--build", str(build), "--target", "kkemulator_dylib", "-j8"], "build")
    suffix = "libkkemu.dylib" if sys.platform == "darwin" else "libkkemu.so"
    libraries = list(build.rglob(suffix))
    if len(libraries) != 1:
        raise RuntimeError("expected one complete research libkkemu")
    library = libraries[0]
    if args.build_only:
        print(json.dumps({"built_only": True, "library": str(library), "signing_enabled": not args.receive_only}))
        return

    reports = {}
    common = ["--reference", str(args.reference.resolve()), "--core-library", str(args.core_library.resolve())]
    workflow_tests = [("addresses", "test_wire.py"), ("watch", "test_watch.py"),
                      ("key-images", "test_key_image.py")]
    if not args.receive_only:
        workflow_tests.append(("signing", "test_signing.py"))
    for name, script in workflow_tests:
        run([sys.executable, str(HERE / "commands" / script), "--library", str(library),
             *common, "--output", str(out / name)], name)
        reports[name] = json.loads((out / name / "result.json").read_text())
        if reports[name].get("status") != "pass":
            raise RuntimeError(f"{name} did not pass")

    if args.receive_only:
        run([sys.executable, str(HERE / "commands/test_signing.py"), "--library", str(library),
             "--expect-unsupported", "--output", str(out / "research-signing-disabled")], "research-signing-disabled")
        reports["research-signing-disabled"] = json.loads((out / "research-signing-disabled/result.json").read_text())

    run([sys.executable, str(HERE / "commands/test_crypto.py"), *common,
         "--output", str(out / "crypto")], "crypto")
    reports["crypto"] = json.loads((out / "crypto/result.json").read_text())
    ordinary = out / "ordinary-build"
    run(["cmake", "-S", str(FW), "-B", str(ordinary), *configuration], "ordinary-configure")
    run(["cmake", "--build", str(ordinary), "--target", "kkemulator_dylib", "-j8"], "ordinary-build")
    ordinary_libraries = list(ordinary.rglob(suffix))
    if len(ordinary_libraries) != 1:
        raise RuntimeError("expected one ordinary libkkemu")
    for name, script in [("ordinary-addresses", "test_wire.py"), ("ordinary-watch", "test_watch.py"),
                         ("ordinary-key-images", "test_key_image.py"), ("ordinary-signing", "test_signing.py")]:
        run([sys.executable, str(HERE / "commands" / script), "--library", str(ordinary_libraries[0]),
             *common, "--expect-unsupported", "--output", str(out / name)], name)
        reports[name] = json.loads((out / name / "result.json").read_text())
    if any(report.get("status") != "pass" for report in reports.values()):
        raise RuntimeError("one of the experiment gates did not pass")

    inputs = [Path(__file__), HERE / "build_core.py", HERE / "commands-overlay.cmake",
              *[p for p in (HERE / "commands").rglob("*") if p.is_file() and "__pycache__" not in p.parts],
              FW / "lib/firmware/fsm.c", FW / "lib/firmware/storage.c", FW / "lib/firmware/messagemap.def"]
    engine_report = args.engine_link.parent / "result.json" if not args.receive_only else None
    report = {
        "schema_version": 1, "status": "pass", "reports": reports,
        "engine": json.loads(engine_report.read_text()) if engine_report else None,
        "signing_enabled": not args.receive_only,
        "firmware_commit": subprocess.check_output(["git", "-C", str(FW), "rev-parse", "HEAD"], text=True).strip(),
        "source_sha256": {str(p.relative_to(FW)): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in sorted(set(inputs))},
        "shared_library": str(library), "shared_library_sha256": hashlib.sha256(library.read_bytes()).hexdigest(),
        "reference_sha256": hashlib.sha256(args.reference.read_bytes()).hexdigest(),
        "independent_core_sha256": hashlib.sha256(args.core_library.read_bytes()).hexdigest(),
        "scope": ("emulator-only addresses, watch export and encrypted key-image sync; transaction signing disabled"
                  if args.receive_only else
                  "emulator-only watch export, encrypted key-image sync and bounded HF16 CLSAG/Bulletproof+ transaction construction using synthetic funding"),
        "physical_device_accessed": False, "transactions_broadcast": False,
        "trezor_signing_protocol_implemented": False, "production_ready": False,
    }
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": "pass", "output": str(out),
                      "stages": list(reports), "production_ready": False}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
