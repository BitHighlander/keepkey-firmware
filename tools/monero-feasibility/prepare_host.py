#!/usr/bin/env python3
"""Fetch and verify pinned official Monero host tools into a private run directory.

Uses the retained binaryFate-signed release manifest and public key. It does
not install globally, start a daemon, open a wallet or connect to a coin network.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile

HERE = Path(__file__).resolve().parent
VERSION = "0.18.5.4"
FINGERPRINT = "81AC591FE9C4B65C5806AFC3F0AF4D462A0BDF92"
KEY_SHA256 = "7dcb19c87d41a4399b4877054111f7dbfd30531545678bc2be218bd56903904c"
MANIFEST_SHA256 = "292f9911ebc40adffbd89b4bec2071c9545c213df25ffa15ef4e8e0367dfb0ce"
PLATFORMS = {
    ("Darwin", "arm64"): "mac-armv8",
    ("Darwin", "x86_64"): "mac-x64",
    ("Linux", "aarch64"): "linux-armv8",
    ("Linux", "arm64"): "linux-armv8",
    ("Linux", "x86_64"): "linux-x64",
}
TOOLS = ("monerod", "monero-wallet-cli", "monero-wallet-rpc")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive", type=Path, help="Reuse an already downloaded archive")
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        parser.error("output directory must be empty")
    system = (platform.system(), platform.machine())
    if system not in PLATFORMS:
        parser.error(f"unsupported host platform: {system}")
    for command in ("gpg", "gpgv") + (() if args.archive else ("curl",)):
        if not shutil.which(command):
            parser.error(f"missing required command: {command}")
    key = HERE / "host-binaryfate.asc"
    manifest = HERE / "host-release-hashes.txt"
    if sha(key) != KEY_SHA256:
        parser.error("release verification public key differs from its pinned hash")
    # Also pin the complete clearsigned container, so no unsigned appended
    # text can contribute an archive hash after signature verification.
    if sha(manifest) != MANIFEST_SHA256:
        parser.error("release manifest differs from its pinned hash")
    home = out / "gnupg"
    home.mkdir(mode=0o700)

    def run(argv, name):
        result = subprocess.run(list(map(str, argv)), capture_output=True, text=True, timeout=180)
        (out / (name + ".log")).write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(f"{name} failed: {out / (name + '.log')}")
        return result

    keyring = out / "release-key.gpg"
    run(["gpg", "--no-options", "--homedir", home, "--batch", "--yes", "--output", keyring,
         "--dearmor", key], "keyring")
    verified = run(["gpgv", "--homedir", home, "--status-fd", "1", "--keyring", keyring,
                    manifest], "signature")
    valid = [line.split() for line in verified.stdout.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
    if not any(line[2] == FINGERPRINT for line in valid):
        raise RuntimeError("release manifest did not have the pinned signing fingerprint")
    archive_name = f"monero-{PLATFORMS[system]}-v{VERSION}.tar.bz2"
    matches = re.findall(r"^([0-9a-f]{64})  " + re.escape(archive_name) + r"$", manifest.read_text(), re.M)
    if len(matches) != 1:
        raise RuntimeError("pinned archive missing from authenticated release manifest")
    url = "https://downloads.getmonero.org/cli/" + archive_name
    archive = args.archive.resolve() if args.archive else out / archive_name
    if not args.archive:
        print("download pinned official host tools", flush=True)
        run(["curl", "-fL", "--connect-timeout", "15", "--max-time", "150", url,
             "-o", archive], "download")
    if sha(archive) != matches[0]:
        raise RuntimeError("host tools archive SHA256 does not match the signed manifest")
    binary_dir = out / "bin"
    binary_dir.mkdir()
    with tarfile.open(archive, "r:bz2") as contents:
        for name in (*TOOLS, "LICENSE"):
            entries = [item for item in contents if item.isfile() and Path(item.name).name == name]
            if len(entries) != 1:
                raise RuntimeError(f"expected exactly one regular archive entry for {name}")
            target = binary_dir / name
            target.write_bytes(contents.extractfile(entries[0]).read())
            target.chmod(0o755 if name in TOOLS else 0o644)
    versions = {name: run([binary_dir / name, "--version"], name + "-version").stdout.strip()
                for name in TOOLS}
    if any(f"v{VERSION}-release" not in version for version in versions.values()):
        raise RuntimeError("unexpected extracted executable version")
    report = {
        "status": "pass", "version": VERSION, "platform": list(system),
        "bin_dir": str(binary_dir), "download_url": url,
        "archive_sha256": sha(archive), "manifest_sha256": sha(manifest),
        "release_key_sha256": sha(key), "verified_fingerprint": FINGERPRINT,
        "source_sha256": sha(Path(__file__)),
        "binary_sha256": {name: sha(binary_dir / name) for name in TOOLS},
        "versions": versions, "globally_installed": False,
        "daemon_started": False, "physical_device_accessed": False,
    }
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
