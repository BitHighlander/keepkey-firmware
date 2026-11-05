#!/usr/bin/env python3
"""Run independent Monero Core fixture checks on host, optionally ARM emulation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import run as primitives

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--arm-prefix")
    parser.add_argument("--arm-python", default=sys.executable)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        parser.error("output directory must be empty")

    def run(cmd, log, expected=0):
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0",
                   UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
        proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, env=env)
        (out / log).write_text(json.dumps(list(map(str, cmd))) + "\n" + proc.stdout)
        if proc.returncode != expected:
            raise RuntimeError(f"exit {proc.returncode}, expected {expected}; see {out / log}")
        return proc.stdout

    reference = out / "reference"
    run([sys.executable, str(HERE / "reference.py"), "--core-source",
         str(args.core_source.resolve()), "--output", str(reference)], "reference.log")
    sources = [str(primitives.CRYPTO / s) for s in primitives.COMMON + primitives.MONERO]
    flags = ["-std=gnu99", "-Os", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
             *[f"-D{d}" for d in primitives.DEFINES], "-DUSE_MONERO=1",
             "-I", str(primitives.CRYPTO)]

    def build_run(name, source, include, expected=0):
        executable = out / name
        run([args.cc, *flags, "-I", str(include), str(source), *sources,
             "-o", str(executable)], f"{name}-build.log")
        return json.loads(run([str(executable)], f"{name}-run.log", expected))

    host = build_run("host", HERE / "interoperability.c", reference)
    if host["status"] or host["cases"] != 96 or host["failed_line"] or not host["checks"]:
        raise RuntimeError("host reference comparison did not complete all fixtures")
    mutants = out / "mutants"
    mutants.mkdir()
    source = (HERE / "interoperability.c").read_text()
    mutated_recipes = {
        "hash-instead-of-reduce": (
            "expand256_modm(spend, v->key_seed, 32);",
            "xmr_hash_to_scalar(spend, v->key_seed, 32);"),
        "accept-noncanonical-scalar": (
            "iszero256_modm(scalar) || !is_reduced256_modm(scalar)",
            "iszero256_modm(scalar)"),
    }
    mutations = {}
    for name, (before, after) in mutated_recipes.items():
        if source.count(before) != 1:
            raise RuntimeError(f"mutation target changed: {name}")
        changed = mutants / f"{name}.c"
        changed.write_text(source.replace(before, after))
        result = build_run(name, changed, reference, expected=1)
        if result["status"] != 1 or not result["failed_line"]:
            raise RuntimeError(f"mutation was not caught by an assertion: {name}")
        mutations[name] = result
    corrupted = mutants / "bad-key-image"
    corrupted.mkdir()
    vector_text = (reference / "interop_vectors.h").read_text()
    replaced, count = re.subn(r"\.key_image = \{[^}]*\}", ".key_image = {0}", vector_text, count=1)
    if count != 1:
        raise RuntimeError("key-image fixture mutation target changed")
    (corrupted / "interop_vectors.h").write_text(replaced)
    mutations["bad-key-image"] = build_run("bad-key-image", HERE / "interoperability.c",
                                            corrupted, expected=1)
    if not mutations["bad-key-image"]["failed_line"]:
        raise RuntimeError("corrupted key-image fixture was not caught")
    report = {
        "schema_version": 1, "status": "pass", "host": host,
        "mutation_tests": mutations, "arm": {"status": "not_requested"},
        "hardware": {"executed": False, "cycles": None, "stack_high_water_bytes": None},
        "production_ready": False,
        "reference": json.loads((reference / "reference.json").read_text()),
        "host_compiler": run([args.cc, "--version"], "host-compiler.log").splitlines()[0],
        "source_sha256": {
            str(p.relative_to(primitives.FW)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(set([*[HERE / name for name in ["interoperability.c", "interop.py",
                                  "run.py", "reference.py", "core-reference.c"]],
                                  *primitives.CRYPTO.rglob("*.h"),
                                  *[primitives.CRYPTO / s for s in primitives.COMMON + primitives.MONERO]]))},
    }
    if args.arm_prefix:
        run([args.arm_python, str(HERE / "arm_execute.py"), "--vectors",
             str(reference / "interop_vectors.h"), "--output", str(out / "arm"),
             "--arm-prefix", args.arm_prefix, "--timeout-seconds", "600"], "arm.log")
        report["arm"] = json.loads((out / "arm/result.json").read_text())
        if report["arm"]["checks"] != host["checks"]:
            raise RuntimeError("host and ARM assertion counts disagree")
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "host": host,
                      "mutations_caught": list(mutations), "arm": report["arm"].get("status"),
                      "physical_device_executed": False}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
