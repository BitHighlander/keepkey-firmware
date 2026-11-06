#!/usr/bin/env python3
"""Build the emulator-only signer against pinned stable Monero Core sources.

No network access or private wallet input. Supply an extracted v0.18.5.4 tree
with its pinned external/supercop, randomx and rapidjson dependencies.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
from pathlib import PurePosixPath

HERE = Path(__file__).resolve().parent
COMMIT = "85f036ba7019cd36f08e8a38a27c37ea7b522618"
DEPENDENCIES = {
    "randomx": "12f2c2ffe2108d6cf54c391fee33c8bc3646cdab",
    "rapidjson": "129d19ba7f496df5e33658527a7158c79b99c21c",
    "supercop": "633500ad8c8759995049ccd022107d1fa8a1bbc9",
}
PINNED_INPUTS = {
    "src/crypto/crypto-ops.c": "6af13943a05af4c6596bd6cf655e4a2ef287d04adc9cd9d7f9686acfee4f1a4c",
    "src/ringct/rctSigs.cpp": "aa4c74e36d40413295bb9632854e9744bae4324024ec5e3b459f67ca240f7f4c",
    "src/ringct/bulletproofs_plus.cc": "02f240549b5c51a47d48494303a5bfe781ab4041e51e13bd2e5a3b35c52a7832",
    "src/cryptonote_core/cryptonote_tx_utils.cpp": "00da33a0013807851c3aba078cb2de85f84dcf47710a2951df4e9c08c5ae0676",
    "src/device/device_default.cpp": "e5a1f210fc3a10e67d95182bde38166c5029443eef0524b44e75ee127b592390",
    "src/cryptonote_basic/account.cpp": "6e79a2edad50da561b3f50fb0801ef25698169a79b86e2225f6dacae894c1d7f",
    "external/randomx/src/randomx.cpp": "beecda2d37d2963d997eb27d78210ba40265ccec3f1df3b7ee74acf982521a9d",
    "external/supercop/functions.cmake": "7d31a999f5912a3e2a7ec327f4cfb8a5170fcc367f7c0b1f76e116400e36fc41",
    "external/rapidjson/include/rapidjson/rapidjson.h": "5f98a172ef013dfbcf3adbef8bc70b0cff3146aa17ef282c8fff484739eeb764",
}
PINNED_ARCHIVES = {
    "monero-core-v0.18.5.4.tar.gz": ("", "a9514399f085a05101c84bf905bc17eae96db2215922f8023b492795259c215f"),
    "monero-randomx.tar.gz": ("external/randomx", "887513a538044c50ad0fb8a486c584704ddd7d533d9093731dd4dc3109ab16cd"),
    "monero-rapidjson.tar.gz": ("external/rapidjson", "44b007d419ac21b6affec58991e865ee572346ead19b73cf1c3e4e11c7a81273"),
    "monero-supercop.tar.gz": ("external/supercop", "b973b9d8269ec4d97c3c3443f0dad96d09f72b1b30e616e0947557adbdbb03f7"),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", "--core-source", dest="source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--build-dir", type=Path, help="Optional existing compatible Core build cache")
    parser.add_argument("--archive-dir", type=Path, help="Directory containing the four exact pinned source archives; defaults to source parent")
    parser.add_argument("--openssl-root", type=Path, default=Path("/opt/homebrew/opt/openssl@3"))
    parser.add_argument("--jobs", type=int, default=8, help="Maximum native build parallelism")
    args = parser.parse_args()
    if not 1 <= args.jobs <= 32:
        parser.error("--jobs must be between 1 and 32")
    source, out = args.source.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        parser.error("output directory must be empty")
    build = args.build_dir.resolve() if args.build_dir else out / "core-build"
    openssl = args.openssl_root.resolve()
    bridge = HERE / "commands/core-signing.cpp"
    # Pin critical transaction construction/verification sources, in addition
    # to the complete build-input manifest retained below.
    required = ["src/cryptonote_core/cryptonote_tx_utils.cpp", "src/ringct/rctSigs.cpp",
                "src/ringct/bulletproofs_plus.cc", "external/supercop/functions.cmake",
                "external/randomx/CMakeLists.txt", "external/rapidjson/include/rapidjson/rapidjson.h"]
    for name in required:
        if not (source / name).is_file():
            parser.error(f"missing pinned Core input: {name}")
    for name, expected in PINNED_INPUTS.items():
        actual = hashlib.sha256((source / name).read_bytes()).hexdigest()
        if actual != expected:
            parser.error(f"pinned Core input hash mismatch: {name}")
    # Verify the entire extracted tree against authenticated archive bytes,
    # rather than treating nine matching files as proof of a complete commit.
    archive_dir = args.archive_dir.resolve() if args.archive_dir else source.parent
    expected_tree = {}
    for name, (prefix, expected) in PINNED_ARCHIVES.items():
        archive = archive_dir / name
        if not archive.is_file() or hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
            parser.error(f"missing or mismatched pinned archive: {archive}")
        with tarfile.open(archive, "r:gz") as entries:
            for member in entries:
                if not member.isfile():
                    continue
                parts = PurePosixPath(member.name).parts[1:]
                if parts:
                    relative = str(PurePosixPath(prefix).joinpath(*parts))
                    expected_tree[relative] = hashlib.sha256(entries.extractfile(member).read()).hexdigest()
    actual_tree = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in source.rglob("*") if p.is_file() and ".git" not in p.parts}
    if actual_tree != expected_tree:
        parser.error("Core source tree differs from the pinned release/dependency archives")
    hook = out / "core-bridge.cmake"
    exports = ["monero_core_validate", "monero_core_sign", "monero_core_verify",
               "monero_core_plan_size", "monero_core_summary_size"]
    hook.write_text("\n".join([
        "function(keepkey_core_bridge)",
        f'  add_library(monero_core_signing SHARED "{bridge}")',
        f'  target_include_directories(monero_core_signing PRIVATE "{HERE / "commands"}")',
        "  target_link_libraries(monero_core_signing PRIVATE cryptonote_core)",
        f'  set_target_properties(monero_core_signing PROPERTIES CXX_STANDARD 14 POSITION_INDEPENDENT_CODE ON LIBRARY_OUTPUT_DIRECTORY "{out / "lib"}")',
        "  if(APPLE)",
        "    target_link_options(monero_core_signing PRIVATE -Wl,-dead_strip)",
        *[f"    target_link_options(monero_core_signing PRIVATE -Wl,-exported_symbol,_{name})" for name in exports],
        "  endif()",
        "endfunction()", "cmake_language(DEFER CALL keepkey_core_bridge)", ""]))

    def run(command, log):
        with (out / log).open("w") as stream:
            stream.write(json.dumps(list(map(str, command))) + "\n")
            stream.flush()
            completed = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT)
        if completed.returncode:
            print((out / log).read_text(errors="replace")[-24000:], file=sys.stderr)
            raise RuntimeError(f"Core build failed: {out / log}")

    run(["cmake", "-S", str(source), "-B", str(build), "-DMANUAL_SUBMODULES=ON",
         "-DBUILD_TESTS=OFF", "-DBUILD_DOCUMENTATION=OFF", "-DBUILD_GUI_DEPS=OFF",
         "-DUSE_DEVICE_TREZOR=OFF", "-DUSE_DEVICE_LEDGER=OFF", "-DMONERO_WALLET_CRYPTO_LIBRARY=cn",
         "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
         "-DCMAKE_POLICY_VERSION_MINIMUM=3.5", f"-DOPENSSL_ROOT_DIR={openssl}",
         f"-DOPENSSL_INCLUDE_DIR={openssl / 'include'}", f"-DOPENSSL_SSL_LIBRARY={openssl / 'lib/libssl.dylib'}",
         f"-DOPENSSL_CRYPTO_LIBRARY={openssl / 'lib/libcrypto.dylib'}",
         f"-DCMAKE_PROJECT_monero_INCLUDE={hook}"], "configure.log")
    run(["cmake", "--build", str(build), "--target", "monero_core_signing", f"-j{args.jobs}"], "build.log")
    candidates = list((out / "lib").glob("libmonero_core_signing.*"))
    libraries = [p for p in candidates if p.suffix in [".dylib", ".so"]]
    if len(libraries) != 1:
        raise RuntimeError("expected one compiled Core signing bridge")
    library = libraries[0]
    # Absolute imported target for the native firmware emulator's opt-in overlay.
    (out / "core-link.cmake").write_text("\n".join([
        "if(NOT TARGET monero_core_signing)",
        "  add_library(monero_core_signing SHARED IMPORTED GLOBAL)",
        f'  set_target_properties(monero_core_signing PROPERTIES IMPORTED_LOCATION "{library}"',
        f'    INTERFACE_INCLUDE_DIRECTORIES "{HERE / "commands"}")', "endif()", ""]))
    manifest = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(source.rglob("*")) if p.is_file() and ".git" not in p.parts}
    report = {
        "status": "pass", "core_release": "v0.18.5.4", "core_commit": COMMIT,
        "dependencies": DEPENDENCIES, "library": str(library),
        "verified_pinned_inputs": PINNED_INPUTS,
        "verified_archives_sha256": {name: digest for name, (_prefix, digest) in PINNED_ARCHIVES.items()},
        "verified_complete_tree_sha256": hashlib.sha256(json.dumps(expected_tree, sort_keys=True).encode()).hexdigest(),
        "library_sha256": hashlib.sha256(library.read_bytes()).hexdigest(),
        "source_sha256": manifest,
        "bridge_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in [Path(__file__), bridge, bridge.with_suffix('.h')]},
        "scope": "native emulator-only Monero Core CLSAG/Bulletproof+ bridge; not an STM32 signing port",
        "production_ready": False,
    }
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ["status", "core_release", "library", "library_sha256"]}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
