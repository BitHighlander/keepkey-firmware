#!/usr/bin/env python3
"""Build and run Monero public fixtures in the actual native KeepKey emulator.

Uses libkkemu's single-threaded FFI lifecycle and HID packet rings. All flash
is a new anonymous 1 MiB buffer; this runner never opens emulator.img or USB.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import reference

HERE = Path(__file__).resolve().parent
FW = HERE.parents[1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise RuntimeError("truncated Features protobuf varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise RuntimeError("oversized Features protobuf varint")


def feature_fields(data):
    fields = {}
    offset = 0
    while offset < len(data):
        key, offset = varint(data, offset)
        field, wire = key >> 3, key & 7
        if wire == 0:
            value, offset = varint(data, offset)
        elif wire == 2:
            length, offset = varint(data, offset)
            value = data[offset:offset + length]
            offset += length
        elif wire in [1, 5]:
            length = 8 if wire == 1 else 4
            value = data[offset:offset + length]
            offset += length
        else:
            raise RuntimeError(f"unsupported Features protobuf wire type {wire}")
        if offset > len(data) or field == 0:
            raise RuntimeError("invalid Features protobuf field")
        fields.setdefault(field, []).append(value)
    return fields


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--toolchain-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    ref_path = args.reference.resolve()
    ref = json.loads(ref_path.read_text())
    if ref.get("fixture_mnemonics_public") != reference.FIXTURES or ref.get("case_count") != 96:
        parser.error("requires the reviewed 96-case disposable public reference")
    for name, expected in ref["adapter_sha256"].items():
        if digest((HERE / name).read_bytes()) != expected:
            parser.error(f"reference adapter changed: {name}")
    root, out = args.toolchain_root.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        parser.error("output directory must be empty")
    vector_dir = out / "vectors"
    vector_dir.mkdir()
    cases = []
    for raw in ref["cases"]:
        case = dict(raw)
        for field in reference.FIELDS:
            case[field] = bytes.fromhex(case[field])
        cases.append(case)
    reference.write_header(cases, vector_dir / "interop_vectors.h")
    if digest((vector_dir / "interop_vectors.h").read_bytes()) != ref["header_sha256"]:
        raise RuntimeError("regenerated fixture header differs from reference")
    derivation_lines = ["/* Fixed public mnemonic/path fixtures from reference.py. */",
                        "#ifndef KEEPKEY_MONERO_DERIVATION_VECTORS_H",
                        "#define KEEPKEY_MONERO_DERIVATION_VECTORS_H", "#include <stdint.h>",
                        "typedef struct { const char *mnemonic; uint32_t account; uint8_t key_seed[32]; } monero_derivation_case;",
                        "static const monero_derivation_case monero_derivation_cases[] = {"]
    for index in [0, 24, 48, 72]:
        fixture = "abandon" if index < 48 else "trezor"
        account = (index // 24) % 2
        expected = ", ".join(f"0x{byte:02x}" for byte in cases[index]["key_seed"])
        derivation_lines.append(f"  {{{json.dumps(reference.FIXTURES[fixture])}, {account}u, {{{expected}}}}},")
    derivation_lines += ["};", "#define MONERO_DERIVATION_CASE_COUNT 4u", "#endif", ""]
    derivation_header = vector_dir / "emulator_derivation_vectors.h"
    derivation_header.write_text("\n".join(derivation_lines))
    env = dict(os.environ)
    env.pop("KK_CLEARSIGN_TEST_ROOT", None)
    env["PATH"] = os.pathsep.join([str(root / "pyk-venv/bin"),
                                    str(root / "nanopb/generator"), env["PATH"]])

    def run(command, log):
        with (out / log).open("w") as stream:
            stream.write(json.dumps([str(x) for x in command]) + "\n")
            stream.flush()
            result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, env=env)
        if result.returncode:
            raise RuntimeError(f"failed: see {out / log}")

    build = out / "build"
    run(["cmake", "-S", str(FW), "-B", str(build), "-DKK_EMULATOR=ON",
         "-DKK_BUILD_DYLIB=ON", "-DKK_DEBUG_LINK=OFF", "-DKK_BITCOIN_ONLY=OFF",
         "-DCMAKE_BUILD_TYPE=Debug", "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
         "-DCMAKE_C_FLAGS=-DPB_NO_PACKED_STRUCTS=1", "-DCMAKE_CXX_FLAGS=-DPB_NO_PACKED_STRUCTS=1",
         f"-DNANOPB_DIR={root / 'nanopb'}", f"-DPROTOC_BINARY={root / 'protoc351/bin/protoc'}",
         f"-DCMAKE_PROJECT_KeepKeyFirmware_INCLUDE={HERE / 'emulator-overlay.cmake'}",
         "-DKK_MONERO_EMULATOR_SELFTEST=ON", f"-DKK_MONERO_VECTOR_DIR={vector_dir}"], "configure.log")
    run(["cmake", "--build", str(build), "--target", "kkemulator_dylib", "-j8"], "build.log")
    libraries = list(build.rglob("libkkemu.dylib" if sys.platform == "darwin" else "libkkemu.so"))
    if len(libraries) != 1:
        raise RuntimeError("expected exactly one built libkkemu shared library")
    library = libraries[0]
    lib = ctypes.CDLL(str(library))
    lib.kkemu_init.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    lib.kkemu_init.restype = ctypes.c_int
    for name in ["kkemu_monero_feasibility", "kkemu_is_running", "kkemu_poll"]:
        getattr(lib, name).restype = ctypes.c_int
    lib.kkemu_write.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    lib.kkemu_write.restype = ctypes.c_int
    lib.kkemu_read.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    lib.kkemu_read.restype = ctypes.c_int
    lib.kkemu_get_display.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int)]
    lib.kkemu_get_display.restype = ctypes.c_void_p
    lib.kkemu_shutdown.argtypes = []
    lib.kkemu_shutdown.restype = None
    if lib.kkemu_monero_feasibility() != -1:
        raise RuntimeError("research entry must reject an uninitialized emulator")
    flash = (ctypes.c_uint8 * (1024 * 1024))()
    ctypes.memset(flash, 0xff, len(flash))
    erased_hash = digest(bytes(flash))
    if lib.kkemu_init(flash, len(flash)) != 0 or lib.kkemu_is_running() != 1:
        raise RuntimeError("actual firmware emulator initialization failed")
    initialized = True

    def features(label):
        request = (b"?##" + (55).to_bytes(2, "big") + bytes(4)).ljust(64, b"\0")
        if lib.kkemu_write(request, 64, 0) != 0:
            raise RuntimeError("GetFeatures ring write failed")
        payload, expected, packets = bytearray(), None, []
        for _ in range(64):
            if lib.kkemu_poll() != 0:
                raise RuntimeError("emulator poll failed")
            packet = ctypes.create_string_buffer(64)
            while lib.kkemu_read(packet, 64, 0) == 64:
                raw = packet.raw
                packets.append(raw.hex())
                if expected is None:
                    if raw[:3] != b"?##" or int.from_bytes(raw[3:5], "big") != 17:
                        raise RuntimeError("GetFeatures did not produce a Features message")
                    expected = int.from_bytes(raw[5:9], "big")
                    if not 0 < expected <= 8192:
                        raise RuntimeError("invalid Features response size")
                    payload.extend(raw[9:])
                else:
                    if raw[0] != 63:
                        raise RuntimeError("invalid Features continuation report")
                    payload.extend(raw[1:])
            if expected is not None and len(payload) >= expected:
                payload = bytes(payload[:expected])
                fields = feature_fields(payload)
                if fields.get(1, [b""])[0] != b"keepkey.com" or fields.get(12, [1])[0] != 0:
                    raise RuntimeError("Features must identify an unseeded KeepKey emulator")
                result = {"message_type": 17, "payload_bytes": expected, "report_count": len(packets),
                          "vendor": fields[1][0].decode(), "initialized": False,
                          "version": [fields[n][0] for n in [2, 3, 4]], "payload_sha256": digest(payload)}
                (out / f"{label}-features.json").write_text(json.dumps({"summary": result, "reports_hex": packets}, indent=2) + "\n")
                return result
        raise RuntimeError("Features response did not complete")

    try:
        before = features("before")
        baseline_flash_hash = digest(bytes(flash))
        started = time.monotonic()
        status = lib.kkemu_monero_feasibility()
        duration = time.monotonic() - started
        checks = ctypes.c_uint32.in_dll(lib, "monero_checks").value
        failed_line = ctypes.c_uint32.in_dll(lib, "monero_fail_line").value
        derivation_checks = ctypes.c_uint32.in_dll(lib, "monero_wallet_derivation_checks").value
        if status != 0 or failed_line or checks != 2823 or derivation_checks != 4:
            raise RuntimeError(f"native emulator Monero test failed: status={status} line={failed_line} checks={checks} derivation_checks={derivation_checks}")
        width, height = ctypes.c_int(), ctypes.c_int()
        pixels = lib.kkemu_get_display(ctypes.byref(width), ctypes.byref(height))
        if not pixels or (width.value, height.value) != (256, 64):
            raise RuntimeError("real firmware OLED snapshot unavailable")
        packed = ctypes.string_at(pixels, 2048)
        if not any(packed):
            raise RuntimeError("firmware results screen is blank")
        (out / "result-oled.bin").write_bytes(packed)
        pgm = bytes(255 if packed[x + (y // 8) * 256] & (1 << (y % 8)) else 0
                    for y in range(64) for x in range(256))
        (out / "result-oled.pgm").write_bytes(b"P5\n256 64\n255\n" + pgm)
        after = features("after")
        if before != after:
            raise RuntimeError("Features response changed across the fixture experiment")
        after_flash_hash = digest(bytes(flash))
        if baseline_flash_hash != after_flash_hash:
            raise RuntimeError("public fixture experiment changed the emulator's flash state")
        report = {
            "schema_version": 1, "status": "pass", "execution": "actual native KeepKey libkkemu firmware emulator",
            "emulator_lifecycle": "kkemu_init -> GetFeatures HID rings -> research FFI -> GetFeatures HID rings -> kkemu_shutdown",
            "cases": 96, "checks": checks, "failed_line": failed_line,
            "wallet_derivation_checks": derivation_checks,
            "wallet_derivation_method": "firmware mnemonic_to_seed(empty passphrase) -> hdnode_from_seed(ed25519) -> hardened44/128/account, compared against independent reference for two public mnemonics and accounts0/1; local seed/HDNode wiped after each",
            "wallet_derivation_vectors_sha256": digest(derivation_header.read_bytes()),
            "host_wall_seconds": duration, "before_features": before, "after_features": after,
            "anonymous_flash_bytes": len(flash), "erased_flash_sha256": erased_hash,
            "post_init_features_flash_sha256": baseline_flash_hash,
            "post_test_features_flash_sha256": after_flash_hash, "flash_unchanged_during_test": True,
            "wallet_seed_loaded": False, "physical_device_accessed": False, "production_ready": False,
            "reference_json_sha256": digest(ref_path.read_bytes()),
            "firmware_commit": subprocess.check_output(["git", "-C", str(FW), "rev-parse", "HEAD"], text=True).strip(),
            "crypto_commit": subprocess.check_output(["git", "-C", str(FW / "deps/crypto/trezor-firmware"), "rev-parse", "HEAD"], text=True).strip(),
            "shared_library_sha256": digest(library.read_bytes()), "shared_library_path": str(library),
            "oled_snapshot_sha256": digest(packed),
            "source_sha256": {name: digest((HERE / name).read_bytes()) for name in [
                "emulator.py", "emulator-overlay.cmake", "emulator-selftest.c", "interoperability.c"]},
            "scope": "96 public address/output/key-image arithmetic cases in the real emulator lifecycle; no Monero wallet protocol or transaction signing command",
        }
    finally:
        if initialized:
            lib.kkemu_shutdown()
    if lib.kkemu_is_running() != 0 or lib.kkemu_monero_feasibility() != -1:
        raise RuntimeError("research entry must reject the shutdown emulator")
    report["lifecycle_guards_passed"] = True
    report["post_shutdown_flash_sha256"] = digest(bytes(flash))
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
