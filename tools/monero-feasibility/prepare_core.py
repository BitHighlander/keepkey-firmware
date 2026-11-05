#!/usr/bin/env python3
"""Prepare the exact public Core source tree used by the emulator signer.

Only four fixed HTTPS archives are downloaded. Every archive is checked against
build_core.py's reviewed digest before any regular file is extracted. No wallet,
key, daemon or compiler is opened here.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile

from build_core import PINNED_ARCHIVES, COMMIT, DEPENDENCIES

URLS = {
    "monero-core-v0.18.5.4.tar.gz": "https://codeload.github.com/monero-project/monero/tar.gz/refs/tags/v0.18.5.4",
    "monero-randomx.tar.gz": "https://codeload.github.com/tevador/RandomX/tar.gz/" + DEPENDENCIES["randomx"],
    "monero-rapidjson.tar.gz": "https://codeload.github.com/Tencent/rapidjson/tar.gz/" + DEPENDENCIES["rapidjson"],
    "monero-supercop.tar.gz": "https://codeload.github.com/monero-project/supercop/tar.gz/" + DEPENDENCIES["supercop"],
}
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_FILE = 64 * 1024 * 1024
MAX_TREE = 512 * 1024 * 1024


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(part)
    return value.hexdigest()


def extract_regular(archive, output, prefix):
    """Match the regular-file tree that the pinned builder later verifies."""
    seen, total = set(), 0
    with tarfile.open(archive, "r:gz") as entries:
        for member in entries:
            parts = PurePosixPath(member.name).parts
            if PurePosixPath(member.name).is_absolute() or ".." in parts:
                raise ValueError("Unsafe public source archive path")
            if not member.isfile():
                continue  # Never materialize symbolic/hard links or device nodes.
            if len(parts) < 2 or member.size < 0 or member.size > MAX_FILE:
                raise ValueError("Invalid public source archive entry")
            relative = PurePosixPath(prefix).joinpath(*parts[1:])
            if str(relative) in seen or len(seen) >= 100000:
                raise ValueError("Duplicate or excessive public source entries")
            seen.add(str(relative)); total += member.size
            if total > MAX_TREE:
                raise ValueError("Public source extraction exceeds its bound")
            target = output.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            stream = entries.extractfile(member)
            if stream is None:
                raise ValueError("Public source entry could not be read")
            with stream:
                data = stream.read(MAX_FILE + 1)
            if len(data) != member.size:
                raise ValueError("Public source entry size mismatch")
            if target.exists():
                if target.is_symlink() or not target.is_file() or target.read_bytes() != data:
                    raise ValueError("Existing public source tree differs")
            else:
                target.write_bytes(data)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)
    return len(seen)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archives", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    archives, source = args.archives.resolve(), args.source.resolve()
    archives.mkdir(parents=True, exist_ok=True)
    source.mkdir(parents=True, exist_ok=True)
    records = []
    for name, (prefix, expected) in PINNED_ARCHIVES.items():
        archive = archives / name
        if not archive.exists():
            with tempfile.NamedTemporaryFile(dir=archives, prefix=name + ".", suffix=".download", delete=False) as holder:
                temporary = Path(holder.name)
            try:
                subprocess.run(["curl", "--fail", "--location", "--silent", "--show-error",
                                "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2",
                                "--connect-timeout", "15", "--max-time", "180",
                                "--max-filesize", str(MAX_ARCHIVE), URLS[name], "--output", str(temporary)], check=True)
                if temporary.stat().st_size > MAX_ARCHIVE or digest(temporary) != expected:
                    raise ValueError("Public source archive integrity check failed")
                temporary.replace(archive)
            finally:
                temporary.unlink(missing_ok=True)
        if archive.is_symlink() or not archive.is_file() or archive.stat().st_size > MAX_ARCHIVE or digest(archive) != expected:
            raise ValueError("Pinned public source archive differs")
        count = extract_regular(archive, source, prefix)
        records.append({"archive": name, "sha256": expected, "regular_files": count})
    print(json.dumps({"status": "pass", "core_commit": COMMIT, "dependencies": DEPENDENCIES,
                      "archives": records, "source": str(source)}))


if __name__ == "__main__":
    main()
