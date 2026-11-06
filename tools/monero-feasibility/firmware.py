#!/usr/bin/env python3
"""Compare full device links, using a local KeepKey toolchain (no flashing)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
FW = HERE.parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    root = args.toolchain_root.resolve()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        parser.error("output directory must be empty")
    prefix = str(root / "gcc10h/bin/arm-none-eabi-")
    env = dict(os.environ)
    env["PATH"] = os.pathsep.join([str(root / "pyk-venv/bin"),
                                    str(root / "nanopb/generator"), env["PATH"]])

    def run(cmd, log):
        with (out / log).open("w") as stream:
            stream.write(json.dumps([str(x) for x in cmd]) + "\n")
            stream.flush()
            result = subprocess.run(cmd, stdout=stream, stderr=subprocess.STDOUT, env=env)
        if result.returncode:
            raise RuntimeError(f"failed: see {out / log}")
        return (out / log).read_text()

    report = {"scope": "full device link only; Monero probe retained but never called",
              "production_ready": False, "profiles": {}}
    for profile, enabled in [("baseline", "OFF"), ("monero", "ON")]:
        print(f"Building {profile} device image", flush=True)
        build = out / profile
        run(["cmake", "-S", str(FW), "-B", str(build),
             "-C", str(FW / "cmake/caches/device.cmake"),
             f"-DCMAKE_C_COMPILER={prefix}gcc", f"-DCMAKE_CXX_COMPILER={prefix}g++",
             f"-DCMAKE_ASM_COMPILER={prefix}gcc", "-DCMAKE_BUILD_TYPE=MinSizeRel",
             "-DCMAKE_POLICY_VERSION_MINIMUM=3.5", "-DKK_BITCOIN_ONLY=OFF",
             f"-DLIBOPENCM3_PATH={root / 'libopencm3'}",
             f"-DNANOPB_DIR={root / 'nanopb'}", f"-DPROTOC_BINARY={root / 'protoc351/bin/protoc'}",
             f"-DCMAKE_PROJECT_KeepKeyFirmware_INCLUDE={HERE / 'firmware-overlay.cmake'}",
             f"-DKK_MONERO_FEASIBILITY={enabled}"], f"{profile}-configure.log")
        run(["cmake", "--build", str(build), "--target", "firmware.keepkey.elf", "-j8"],
            f"{profile}-build.log")
        elf = build / "bin/firmware.keepkey.elf"
        binary = elf.with_suffix(".bin")
        symbols = run([prefix + "nm", "-S", str(elf)], f"{profile}-symbols.txt")
        size = run([prefix + "size", str(elf)], f"{profile}-size.txt")
        text, data, bss = map(int, size.splitlines()[-1].split()[:3])
        def symbol(name):
            match = re.search(r"^([0-9a-fA-F]+) (?:[0-9a-fA-F]+ )?\w " + re.escape(name) + "$", symbols, re.M)
            if not match:
                raise RuntimeError(f"missing {name} symbol")
            return int(match[1], 16)
        if enabled == "ON":
            for name in ["monero_probe", "xmr_generate_key_derivation", "xmr_hash_to_ec", "xmr_gen_c"]:
                symbol(name)
            if re.search(r"\bxmr_random_scalar$", symbols, re.M):
                raise RuntimeError("unexpected Monero RNG helper retained")
        elif re.search(r"\b(?:monero_probe|xmr_generate_key_derivation)$", symbols, re.M):
            raise RuntimeError("baseline unexpectedly contains Monero")
        report["profiles"][profile] = {
            "text": text, "data": data, "bss": bss,
            "binary_bytes": binary.stat().st_size,
            "upload_limit_bytes": 0xA0000 - 39,
            "upload_headroom_bytes": 0xA0000 - 39 - binary.stat().st_size,
            "runtime_sram_reserve_bytes": symbol("_stack") - symbol("_ebss"),
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        }
    report["delta"] = {key: report["profiles"]["monero"][key] - report["profiles"]["baseline"][key]
                       for key in ["text", "data", "bss", "binary_bytes", "runtime_sram_reserve_bytes"]}
    report["firmware_commit"] = subprocess.check_output(
        ["git", "-C", str(FW), "rev-parse", "HEAD"], text=True).strip()
    report["compiler"] = subprocess.check_output([prefix + "gcc", "--version"], text=True).splitlines()[0]
    report["submodule_state"] = subprocess.check_output(
        ["git", "-C", str(FW), "submodule", "status"], text=True).splitlines()
    report["experiment_sha256"] = {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(HERE.iterdir()) if p.suffix in [".py", ".c", ".cmake"]}
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
