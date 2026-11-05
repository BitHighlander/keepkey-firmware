#!/usr/bin/env python3
"""Reproducible host vectors and isolated ARM link/stack measurements."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
FW = HERE.parents[1]
CRYPTO = FW / "deps/crypto/trezor-firmware/crypto"
COMMON = [
    "hasher.c", "sha2.c", "sha3.c", "ripemd160.c", "blake256.c",
    "blake2b.c", "groestl.c", "memzero.c", "base58.c",
    "ed25519-donna/curve25519-donna-scalarmult-base.c",
    "ed25519-donna/ed25519-donna-32bit-tables.c",
    "ed25519-donna/ed25519.c",
    "ed25519-donna/curve25519-donna-helpers.c",
    "ed25519-donna/ed25519-donna-basepoint-table.c",
    "ed25519-donna/modm-donna-32bit.c",
    "ed25519-donna/curve25519-donna-32bit.c",
    "ed25519-donna/ed25519-donna-impl-base.c",
]
MONERO = ["monero/xmr.c", "monero/serialize.c", "monero/base58.c"]
DEFINES = ["ED25519_CUSTOMHASH=1", "ED25519_CUSTOMRANDOM=1",
           "ED25519_NO_INLINE_ASM", "ED25519_FORCE_32BIT=1",
           "USE_PRECOMPUTED_CP=0", "USE_KECCAK=1", "USE_CARDANO=0",
           "USE_NEM=0", "USE_GRAPHENE=0", "USE_ETHEREUM=1"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    parser.add_argument("--arm-prefix", help="Path/prefix ending in arm-none-eabi-")
    args = parser.parse_args()
    out = (args.output or Path(tempfile.mkdtemp(prefix="keepkey-monero-"))).resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        parser.error("output directory must be empty (preserve previous evidence)")
    commands = []

    def run(cmd, **kw):
        commands.append([str(x) for x in cmd])
        proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, **kw)
        with (out / "commands.log").open("a") as log:
            log.write(json.dumps(commands[-1]) + "\n" + proc.stdout + "\n")
        if proc.returncode:
            raise RuntimeError(f"command failed ({proc.returncode}): {cmd[0]}\n{proc.stdout}")
        return proc.stdout

    # Reuse all deterministic primitive groups. The excluded final group is a
    # legacy Borromean range proof using RNG; it is not modern tx feasibility.
    header = CRYPTO / "tests/test_check_monero.h"
    text = header.read_text()
    marker = "START_TEST(test_xmr_gen_range_sig)"
    if text.count(marker) != 1 or not text.rstrip().endswith("#endif"):
        raise RuntimeError("upstream test layout changed; review vector selection")
    selected = text.split(marker)[0] + "\n#endif\n"
    groups = re.findall(r"START_TEST\((\w+)\)", selected)
    if len(groups) != 30:
        raise RuntimeError(f"expected 30 deterministic groups, got {len(groups)}")
    selected += f"\n#define SELECTED_VECTOR_GROUPS {len(groups)}\n"
    selected += "static void run_selected_vectors(void) {\n"
    selected += "".join(f"  {name}();\n" for name in groups) + "}\n"
    (out / "selected_vectors.h").write_text(selected)
    flags = ["-std=gnu99", "-Os", "-fno-common", "-ffunction-sections",
             "-fdata-sections", *[f"-D{x}" for x in DEFINES],
             "-I", str(CRYPTO), "-I", str(out)]
    host_sources = [str(CRYPTO / s) for s in COMMON + MONERO]
    # ASan catches memory errors while vectors exercise the 32-bit donna path.
    host_flags = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    run([args.cc, *flags, *host_flags, "-DUSE_MONERO=1", str(HERE / "vectors.c"),
         *host_sources, "-o", str(out / "vectors")])
    env = dict(os.environ, UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1",
               ASAN_OPTIONS="detect_leaks=0")
    host = json.loads(run([str(out / "vectors")], env=env))
    report = {
        "schema_version": 1,
        "firmware_commit": run(["git", "-C", str(FW), "rev-parse", "HEAD"]).strip(),
        "crypto_commit": run(["git", "-C", str(CRYPTO), "rev-parse", "HEAD"]).strip(),
        "host_compiler": run([args.cc, "--version"]).splitlines()[0],
        "host": host, "arm": {"status": "not_requested"},
        "scope": "primitive feasibility only; no wallet derivation compatibility or transaction signing",
        "production_ready": False,
    }
    if args.arm_prefix:
        cc = args.arm_prefix + "gcc"
        size = args.arm_prefix + "size"
        nm = args.arm_prefix + "nm"
        arm = {"compiler": run([cc, "--version"]).splitlines()[0], "profiles": {}}
        for profile, enabled in [("baseline", 0), ("monero", 1)]:
            build = out / profile
            build.mkdir()
            armflags = [*flags, "-mthumb", "-mcpu=cortex-m3", "-msoft-float",
                        "-fstack-usage", "-fstack-protector-strong", f"-DUSE_MONERO={enabled}"]
            sources = [CRYPTO / s for s in COMMON + (MONERO if enabled else [])]
            sources.append(HERE / "probe.c")
            objects = []
            for i, source in enumerate(sources):
                obj = build / f"{i}-{source.stem}.o"
                run([cc, *armflags, "-c", str(source), "-o", str(obj)])
                objects.append(obj)
            elf = build / "probe.elf"
            run([cc, "-mthumb", "-mcpu=cortex-m3", "-msoft-float", "-nostartfiles",
                 "--specs=nosys.specs", "-Wl,--gc-sections,-e,monero_probe",
                 f"-Wl,-Map={build / 'probe.map'}", *map(str, objects), "-o", str(elf)])
            sizes = run([size, str(elf)]).splitlines()[-1].split()
            symbols = run([nm, "-S", "--size-sort", str(elf)])
            (build / "symbols.txt").write_text(symbols)
            frames = []
            for su in build.glob("*.su"):
                for line in su.read_text().splitlines():
                    loc, count, kind = line.rsplit("\t", 2)
                    frames.append({"function": loc.rsplit(":", 1)[-1],
                                   "bytes": int(count), "kind": kind})
            frames.sort(key=lambda x: x["bytes"], reverse=True)
            (build / "stack.json").write_text(json.dumps(frames, indent=2) + "\n")
            arm["profiles"][profile] = dict(zip(["text", "data", "bss"], map(int, sizes[:3])))
            arm["profiles"][profile]["largest_compiled_frames"] = frames[:10]
            retained = [frame for frame in frames if re.search(
                r"\b" + re.escape(frame["function"]) + r"$", symbols, re.M)]
            arm["profiles"][profile]["largest_retained_frames"] = retained[:10]
            if enabled:
                required = ["xmr_generate_key_derivation", "xmr_hash_to_ec", "xmr_gen_c",
                            "xmr_base58_addr_encode_check", "xmr_get_subaddress_secret_key"]
                if any(not re.search(r"\b" + name + r"$", symbols, re.M) for name in required):
                    raise RuntimeError("ARM probe lost a required Monero primitive")
                if re.search(r"\bxmr_random_scalar$", symbols, re.M):
                    raise RuntimeError("unexpected RNG linked into deterministic ARM probe")
        arm["delta"] = {key: arm["profiles"]["monero"][key] - arm["profiles"]["baseline"][key]
                        for key in ["text", "data", "bss"]}
        arm["status"] = "linked_not_executed"
        report["arm"] = arm

    # Record all inputs, including headers, so local edits cannot hide behind a
    # clean parent commit. The generated vector subset is also retained.
    inputs = [*CRYPTO.rglob("*.h"), *[CRYPTO / s for s in COMMON + MONERO],
              *HERE.glob("*.c"), *HERE.glob("*.py"), *HERE.glob("*.cmake"), header]
    report["selected_vectors_sha256"] = hashlib.sha256(selected.encode()).hexdigest()
    report["input_sha256"] = {str(p.relative_to(FW)): hashlib.sha256(p.read_bytes()).hexdigest()
                              for p in sorted(set(inputs))}
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(out), "host": host,
                      "arm_delta": report["arm"].get("delta"), "production_ready": False}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
