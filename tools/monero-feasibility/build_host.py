#!/usr/bin/env python3
"""Build the read-only native wallet-export adapter against the pinned Core tree.

This performs no downloads. Source and all four archives must match the exact
pins used by build_core.py. The optional compatible build cache can be reused;
the executable is placed in the requested empty artifact directory.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile

from build_core import COMMIT, DEPENDENCIES, PINNED_ARCHIVES, PINNED_INPUTS

HERE = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", "--core-source", dest="source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--archive-dir", type=Path)
    parser.add_argument("--openssl-root", type=Path, default=Path("/opt/homebrew/opt/openssl@3"))
    parser.add_argument("--jobs", type=int, default=8, help="Maximum native build parallelism")
    args = parser.parse_args()
    if not 1 <= args.jobs <= 32:
        parser.error("--jobs must be between 1 and 32")
    source, out = args.source.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        parser.error("output directory must be empty")
    archives = args.archive_dir.resolve() if args.archive_dir else source.parent
    expected = {}
    for name, (prefix, digest) in PINNED_ARCHIVES.items():
        archive = archives / name
        if not archive.is_file() or sha(archive) != digest:
            parser.error(f"missing or mismatched pinned archive: {archive}")
        with tarfile.open(archive, "r:gz") as entries:
            for member in entries:
                if member.isfile():
                    parts = PurePosixPath(member.name).parts[1:]
                    if parts:
                        relative = str(PurePosixPath(prefix).joinpath(*parts))
                        expected[relative] = hashlib.sha256(entries.extractfile(member).read()).hexdigest()
    actual = {str(p.relative_to(source)): sha(p) for p in sorted(source.rglob("*"))
              if p.is_file() and ".git" not in p.parts}
    if actual != expected:
        parser.error("Core source tree differs from pinned release/dependency archives")
    if any(actual[name] != digest for name, digest in PINNED_INPUTS.items()):
        parser.error("critical Core source hash mismatch")

    build = args.build_dir.resolve() if args.build_dir else out / "core-build"
    openssl = args.openssl_root.resolve()
    adapter = HERE / "host-adapter.cpp"
    hook = out / "host-adapter.cmake"
    hook.write_text("\n".join([
        "function(keepkey_host_adapter)",
        f'  add_executable(monero_host_adapter "{adapter}")',
        "  target_link_libraries(monero_host_adapter PRIVATE wallet version)",
        f'  set_target_properties(monero_host_adapter PROPERTIES CXX_STANDARD 14 OUTPUT_NAME monero-host-adapter RUNTIME_OUTPUT_DIRECTORY "{out / "bin"}")',
        "endfunction()", "cmake_language(DEFER CALL keepkey_host_adapter)", ""]))

    def run(command, logfile):
        with (out / logfile).open("w") as stream:
            stream.write(json.dumps(list(map(str, command))) + "\n")
            stream.flush()
            completed = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT)
        if completed.returncode:
            print((out / logfile).read_text(errors="replace")[-24000:], file=sys.stderr)
            raise RuntimeError(f"Host adapter build failed: {out / logfile}")

    run(["cmake", "-S", str(source), "-B", str(build), "-DMANUAL_SUBMODULES=ON",
         "-DBUILD_TESTS=OFF", "-DBUILD_DOCUMENTATION=OFF", "-DBUILD_GUI_DEPS=OFF",
         "-DUSE_DEVICE_TREZOR=OFF", "-DUSE_DEVICE_LEDGER=OFF", "-DMONERO_WALLET_CRYPTO_LIBRARY=cn",
         "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
         "-DCMAKE_POLICY_VERSION_MINIMUM=3.5", f"-DOPENSSL_ROOT_DIR={openssl}",
         f"-DOPENSSL_INCLUDE_DIR={openssl / 'include'}", f"-DOPENSSL_SSL_LIBRARY={openssl / 'lib/libssl.dylib'}",
         f"-DOPENSSL_CRYPTO_LIBRARY={openssl / 'lib/libcrypto.dylib'}",
         f"-DCMAKE_PROJECT_monero_INCLUDE={hook}"], "configure.log")
    run(["cmake", "--build", str(build), "--target", "monero_host_adapter", f"-j{args.jobs}"], "build.log")
    executable = out / "bin/monero-host-adapter"
    if not executable.is_file():
        raise RuntimeError("Expected compiled host adapter executable")
    report = {
        "status": "pass", "core_release": "v0.18.5.4", "core_commit": COMMIT,
        "dependencies": DEPENDENCIES, "executable": str(executable), "executable_sha256": sha(executable),
        "verified_archives_sha256": {name: digest for name, (_prefix, digest) in PINNED_ARCHIVES.items()},
        "verified_complete_tree_sha256": hashlib.sha256(json.dumps(expected, sort_keys=True).encode()).hexdigest(),
        "source_sha256": actual,
        "adapter_sha256": {p.name: sha(p) for p in [Path(__file__), HERE / "build_core.py", adapter]},
        "scope": "read-only watch-wallet export adapter; no spend keys, daemon connection or wallet-file writes",
        "production_ready": False,
    }
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({name: report[name] for name in ["status", "executable", "executable_sha256"]}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
