#!/usr/bin/env python3
"""Prepare an unsigned public-fixture hardware selftest image. Never flashes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from reference import FIELDS, write_header

HERE = Path(__file__).resolve().parent
FW = HERE.parents[1]
SUBSET = [0, 7, 14, 23, 24, 47, 48, 95]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, type=Path)
    parser.add_argument("--toolchain-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    ref_path = args.reference.resolve()
    ref = json.loads(ref_path.read_text())
    if ref.get("case_count") != 96 or len(ref.get("cases", [])) != 96:
        parser.error("expected the reviewed 96-case public reference matrix")
    if ref.get("fixture_mnemonics_public") != __import__("reference").FIXTURES:
        parser.error("reference must use the fixed public disposable fixtures")
    for name, digest in ref.get("adapter_sha256", {}).items():
        if sha(HERE / name) != digest:
            parser.error(f"reference adapter changed since generation: {name}")
    root, out = args.toolchain_root.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        parser.error("output directory must be empty")
    vectors = out / "vectors"
    vectors.mkdir()
    selected = []
    for index in SUBSET:
        case = dict(ref["cases"][index])
        for field in FIELDS:
            case[field] = bytes.fromhex(case[field])
        selected.append(case)
    write_header(selected, vectors / "interop_vectors.h")
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
            raise RuntimeError(f"command failed; see {out / log}")
        return (out / log).read_text()

    build = out / "build"
    run(["cmake", "-S", str(FW), "-B", str(build),
         "-C", str(FW / "cmake/caches/device.cmake"),
         f"-DCMAKE_C_COMPILER={prefix}gcc", f"-DCMAKE_CXX_COMPILER={prefix}g++",
         f"-DCMAKE_ASM_COMPILER={prefix}gcc", "-DCMAKE_BUILD_TYPE=MinSizeRel",
         "-DCMAKE_POLICY_VERSION_MINIMUM=3.5", "-DKK_BITCOIN_ONLY=OFF", "-DKK_DEBUG_LINK=OFF",
         f"-DLIBOPENCM3_PATH={root / 'libopencm3'}", f"-DNANOPB_DIR={root / 'nanopb'}",
         f"-DPROTOC_BINARY={root / 'protoc351/bin/protoc'}",
         f"-DCMAKE_PROJECT_KeepKeyFirmware_INCLUDE={HERE / 'hardware-overlay.cmake'}",
         "-DKK_MONERO_HARDWARE_SELFTEST=ON", f"-DKK_MONERO_VECTOR_DIR={vectors}"], "configure.log")
    run(["cmake", "--build", str(build), "--target", "firmware.keepkey.elf", "-j8"], "build.log")
    elf = build / "bin/firmware.keepkey.elf"
    binary = elf.with_suffix(".bin")
    symbols = run([prefix + "nm", "-S", str(elf)], "symbols.txt")
    sizes = run([prefix + "size", str(elf)], "size.txt").splitlines()[-1].split()
    wrapper = run([prefix + "objdump", "-d", "--disassemble=__wrap_kk_board_init", str(elf)], "wrapper-disassembly.txt")
    paint = run([prefix + "objdump", "-d", "--disassemble=monero_paint_stack", str(elf)], "paint-disassembly.txt")

    def symbol(name):
        match = re.search(r"^([0-9a-fA-F]+) (?:[0-9a-fA-F]+ )?\w " + re.escape(name) + "$", symbols, re.M)
        if not match:
            raise RuntimeError(f"required symbol absent: {name}")
        return int(match[1], 16)
    for name in ["__wrap_kk_board_init", "monero_paint_stack", "monero_hardware_report",
                 "monero_interop_run", "xmr_generate_key_derivation", "xmr_hash_to_ec"]:
        symbol(name)
    if re.search(r"\bxmr_random_scalar$", symbols, re.M):
        raise RuntimeError("unexpected random-scalar helper in selftest")
    if re.search(r"\bbx\s+lr|\bpop[^\n]*\bpc", wrapper):
        raise RuntimeError("hardware wrapper contains a return instruction")
    if not re.search(r"\bbl\b[^\n]*<kk_board_init>", wrapper) or "<monero_interop_run>" not in wrapper:
        raise RuntimeError("wrapper is missing real board initialization or interop execution")
    if re.search(r"\b(?:push|pop|bl|blx)\b", paint):
        raise RuntimeError("stack painter unexpectedly has a frame or callee")
    reserve = symbol("_stack") - symbol("_ebss")
    headroom = 0xA0000 - 39 - binary.stat().st_size
    if reserve < 16384 or headroom < 0:
        raise RuntimeError("hardware experiment fails the real image budgets")
    report = {
        "schema_version": 1, "prepared_only": True, "flashed": False,
        "hardware_result": None,
        "runtime_elapsed_ticks": None, "runtime_stack_highwater_bytes": None,
        "unsigned_test_image": True, "production_ready": False,
        "selected_reference_indices": SUBSET,
        "selected_labels": [case["label"] for case in selected],
        "reference_json_sha256": sha(ref_path),
        "subset_header_sha256": sha(vectors / "interop_vectors.h"),
        "compiler": subprocess.check_output([prefix + "gcc", "--version"], text=True).splitlines()[0],
        "firmware_commit": subprocess.check_output(["git", "-C", str(FW), "rev-parse", "HEAD"], text=True).strip(),
        "image": {"path": str(binary), "sha256": sha(binary), "bytes": binary.stat().st_size,
                  "upload_headroom_bytes": headroom, "runtime_sram_reserve_bytes": reserve,
                  "text": int(sizes[0]), "data": int(sizes[1]), "bss": int(sizes[2])},
        "boundary": "wrap kk_board_init; initialize board, run fixed public vectors, display and loop forever; never resume main into model/storage/USB initialization",
        "startup_caveat": "existing main executes signature checks, hardware entropy collection and FI RNG before the hook; selftest uses no RNG or wallet storage",
        "measurement_caveat": "getSysTime timer ticks, not cycles or calibrated milliseconds; painted thread-stack usage excludes boot/UI and protected handler-stack use, includes sampled interrupt stacking and the interrupt-disable call",
        "source_sha256": {p.name: sha(p) for p in [HERE / name for name in [
            "hardware.py", "hardware-selftest.c", "hardware-stack.S", "hardware-overlay.cmake", "interoperability.c"]]},
    }
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
