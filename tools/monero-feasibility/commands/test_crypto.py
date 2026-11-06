#!/usr/bin/env python3
"""Verify the emulator-only address helper with independent public fixtures.

No network, wallet input, native firmware emulator, or physical device is used.
The Core library is the host adapter built by ../reference.py from pinned
Monero Core source; its exact binary hash is recorded in the result.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
EXPERIMENT = HERE.parent
FW = EXPERIMENT.parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


reference = module("monero_reference", EXPERIMENT / "reference.py")
primitives = module("monero_primitives", EXPERIMENT / "run.py")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def address_for_network(core, spend_public, view_public, network, subaddress):
    prefixes = [42, 63, 36] if subaddress else [18, 53, 24]
    binary = bytes([prefixes[network]]) + spend_public + view_public
    binary += core.hash(binary)[:4]
    encoded = ""
    for offset in range(0, len(binary), 8):
        block = binary[offset:offset + 8]
        value, text = int.from_bytes(block, "big"), ""
        while value:
            value, digit = divmod(value, 58)
            text = reference.ALPHABET[digit] + text
        encoded += text.rjust(reference.BLOCK_WIDTH[len(block)], "1")
    if len(encoded) != 95:
        raise RuntimeError("independent address has unexpected length")
    return encoded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, type=Path,
                        help="Standalone reference.json or recorded host.json")
    parser.add_argument("--core-library", required=True, type=Path,
                        help="Pinned Monero Core adapter built by reference.py")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    ref_path, library, out = args.reference.resolve(), args.core_library.resolve(), args.output.resolve()
    supplied = json.loads(ref_path.read_text())
    ref = supplied.get("reference", supplied)
    if (ref.get("core_commit") != reference.CORE_COMMIT or
            ref.get("core_source_sha256") != reference.CORE_SHA256 or
            ref.get("fixture_mnemonics_public") != reference.FIXTURES or
            ref.get("case_count") != 96):
        parser.error("reference must contain the pinned public 96-case experiment")
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        parser.error("output directory must be empty")
    core = reference.Core(library)
    anchors = reference.known_anchors(core)
    recomputed = reference.make_cases(core)
    serial = [{key: value.hex() if isinstance(value, bytes) else value
               for key, value in case.items()} for case in recomputed]
    if serial != ref["cases"]:
        raise RuntimeError("independently regenerated Core cases differ from supplied reference")

    vectors = []
    seen = set()
    for case in recomputed:
        key = (case["key_seed"], case["major"], case["minor"])
        if key in seen:
            continue
        seen.add(key)
        for network in range(3):
            expected = address_for_network(core, case["sub_spend_public"],
                case["sub_view_public"], network, case["major"] != 0 or case["minor"] != 0)
            if network == 0 and expected != case["address"]:
                raise RuntimeError("mainnet encoding disagrees with the reference address")
            vectors.append({"label": case["label"], "node_key": case["key_seed"],
                            "network": network, "major": case["major"], "minor": case["minor"],
                            "address": expected})
    if len(vectors) != 48:
        raise RuntimeError("expected 48 independent address cases")
    header = ["/* Public generated test fixtures. */", "#include <stdint.h>",
              "typedef struct { uint8_t node_key[32]; uint32_t network, major, minor; const char *address; } monero_address_case;",
              "static const monero_address_case monero_address_cases[] = {"]
    for vector in vectors:
        key = ",".join(f"0x{byte:02x}" for byte in vector["node_key"])
        header.append("  {{" + key + "}," +
                      f"{vector['network']}u,{vector['major']}u,{vector['minor']}u," +
                      json.dumps(vector["address"]) + "},")
    header += ["};", "#define MONERO_ADDRESS_CASES 48u", ""]
    (out / "crypto-vectors.h").write_text("\n".join(header))
    (out / "crypto-check.c").write_bytes((HERE / "crypto-check.c.in").read_bytes())
    (out / "public-vectors.json").write_text(json.dumps([
        {k: v.hex() if isinstance(v, bytes) else v for k, v in vector.items()}
        for vector in vectors], indent=2) + "\n")
    commands = []

    def run(command, label, expected=0, marker=None):
        commands.append(list(map(str, command)))
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0",
                   UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
        process = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, env=env)
        (out / f"{label}.log").write_text(json.dumps(commands[-1]) + "\n" + process.stdout)
        if ((expected == 0 and process.returncode != 0) or
                (expected != 0 and process.returncode == 0) or
                (marker is not None and marker not in process.stdout)):
            raise RuntimeError(f"unexpected compile/run outcome: {out / (label + '.log')}")
        return process.stdout

    defines = [*[f"-D{value}" for value in primitives.DEFINES], "-DEMULATOR",
               "-DKK_MONERO_EMULATOR_RESEARCH=1", "-DBITCOIN_ONLY=0", "-DUSE_MONERO=1"]
    includes = ["-I", str(primitives.CRYPTO), "-I", str(HERE), "-I", str(out)]
    sources = [HERE / "monero_research.c", *[primitives.CRYPTO / s
               for s in primitives.COMMON + primitives.MONERO]]
    executable = out / "crypto-check"
    run([args.cc, "-std=gnu99", "-Os", "-fsanitize=address,undefined",
         "-fno-omit-frame-pointer", *defines, *includes,
         str(out / "crypto-check.c"), *map(str, sources), "-o", str(executable)], "sanitized-build")
    checked = json.loads(run([str(executable)], "sanitized-run"))
    if checked["status"] != "pass" or checked["address_cases"] != 48 or checked["failed_line"]:
        raise RuntimeError("sanitized helper checks did not complete")

    gate_marker = "Monero research commands are limited to the regular firmware emulator"
    guards = {}
    for label, flags, marker in [
        ("no-emulator", ["-DKK_MONERO_EMULATOR_RESEARCH=1", "-DBITCOIN_ONLY=0", "-DUSE_MONERO=1"], gate_marker),
        ("bitcoin-only", ["-DEMULATOR", "-DKK_MONERO_EMULATOR_RESEARCH=1", "-DBITCOIN_ONLY=1", "-DUSE_MONERO=1"], gate_marker),
        ("no-research-selection", ["-DEMULATOR", "-DBITCOIN_ONLY=0", "-DUSE_MONERO=1"], gate_marker),
        ("no-monero-primitives", ["-DEMULATOR", "-DKK_MONERO_EMULATOR_RESEARCH=1", "-DBITCOIN_ONLY=0", "-DUSE_MONERO=0"],
         "Monero research address derivation requires the Monero crypto primitives"),
    ]:
        run([args.cc, "-std=gnu99", *includes, *flags, "-c", str(HERE / "monero_research.c"),
             "-o", str(out / f"{label}.o")], label, expected=1, marker=marker)
        guards[label] = "compile_rejected_by_explicit_guard"
    files = [Path(__file__), HERE / "crypto-check.c.in", HERE / "monero_research.h",
             *sources, EXPERIMENT / "run.py", EXPERIMENT / "reference.py",
             EXPERIMENT / "core-reference.c", *primitives.CRYPTO.rglob("*.h")]
    result = {
        "schema_version": 1, "status": "pass", "scope": "address helper only; no wallet protocol or device access",
        "sanitizers": ["AddressSanitizer", "UndefinedBehaviorSanitizer"], "helper": checked,
        "compile_guards": guards, "core_commit": reference.CORE_COMMIT,
        "core_source_sha256": reference.CORE_SHA256, "core_anchor_checks": anchors,
        "provided_core_library_sha256": sha(library), "reference_json_sha256": sha(ref_path),
        "compiler": run([args.cc, "--version"], "compiler").splitlines()[0],
        "vectors_sha256": sha(out / "crypto-vectors.h"),
        "driver_sha256": sha(out / "crypto-check.c"),
        "source_sha256": {str(p.relative_to(FW)): sha(p) for p in sorted(set(files))},
        "production_ready": False,
    }
    (out / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": "pass", "helper": checked, "compile_guards": guards}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
