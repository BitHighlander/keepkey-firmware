#!/usr/bin/env python3
"""Pipe-only encrypted flash I/O for the optional private Vault profile.

Public metadata is JSON; open emits exactly one flash image on stdout and save
accepts exactly one image on stdin. Plaintext is never placed in files, command
arguments, diagnostics, or mnemonic sidecars. No firmware or network runs here.
"""
import argparse
import ctypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import resource
import stat
import sys
import uuid

import private_keystore as store

FLASH_SIZE = 1024 * 1024
HERE = Path(__file__).resolve().parent


class ProfileError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise ProfileError(message)


def private_file(path):
    require(not path.is_symlink(), "Private profile files must not be symbolic links")
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077,
            "Private profile file permissions or owner are invalid")


def describe(directory):
    directory = directory.expanduser().resolve(strict=True)
    require(directory.is_dir() and not directory.is_relative_to(HERE.parents[3]) and
            not directory.is_relative_to(Path("/private/tmp")) and
            not directory.is_relative_to(Path("/tmp")), "Private profile must be outside the repository and temporary directories")
    info = directory.stat()
    require(info.st_uid == os.getuid() and not info.st_mode & 0o077, "Private profile directory permissions or owner are invalid")
    manifest, encrypted = directory / "wallet.json", directory / "wallet.enc"
    private_file(manifest)
    private_file(encrypted)
    require(manifest.stat().st_size <= 65536, "Private profile metadata exceeds its bound")
    metadata = json.loads(manifest.read_bytes())
    require(type(metadata) is dict and metadata.get("schema_version") == 1 and
            metadata.get("network") == "mainnet" and metadata.get("status") == "ready" and
            metadata.get("restore_verified") is True and metadata.get("public_test_seed") is False,
            "Private profile has not passed mainnet restoration verification")
    account, address = metadata.get("wallet_id"), metadata.get("address")
    require(type(account) is str and 1 <= len(account.encode("utf-8")) <= 256 and
            not any(ord(c) < 32 for c in account), "Invalid private profile identifier")
    require(type(address) is str and len(address) == 95 and address.startswith("4") and
            all(c in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" for c in address),
            "Invalid private profile mainnet address")
    backend = metadata.get("keystore_backend")
    require(backend in ("login", "data-protection"), "Unsupported private profile Keychain backend")
    library_name, expected = metadata.get("library"), metadata.get("library_sha256")
    require(type(library_name) is str and Path(library_name).is_absolute() and
            type(expected) is str and len(expected) == 64 and all(c in "0123456789abcdef" for c in expected),
            "Invalid private profile firmware identity")
    library = Path(library_name).resolve(strict=True)
    require(library.is_file() and library.stat().st_size <= 128 * 1024 * 1024, "Private profile firmware is unavailable")
    actual = hashlib.sha256(library.read_bytes()).hexdigest()
    require(hmac.compare_digest(actual, expected), "Private profile firmware integrity check failed")
    header_size = len(store.MAGIC) + 1 + store.NONCE_SIZE + store.TAG_SIZE
    require(encrypted.stat().st_size == FLASH_SIZE + header_size, "Private profile encrypted flash size is invalid")
    return {"walletId": account, "address": address, "directory": str(directory),
            "library": str(library), "librarySha256": expected, "backend": backend}, encrypted


class LockedBuffer:
    def __init__(self, value):
        self.value = value
        self.system = ctypes.CDLL(None, use_errno=True)
        self.system.mlock.argtypes = self.system.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        self.system.mlock.restype = self.system.munlock.restype = ctypes.c_int
        self.pointer = (ctypes.c_ubyte * len(value)).from_buffer(value)
        if self.system.mlock(self.pointer, len(value)):
            self.clear()
            raise ProfileError("Cannot lock private flash helper memory")

    def clear(self):
        if self.value:
            ctypes.memset(self.pointer, 0, len(self.value))

    def close(self):
        self.clear()
        self.system.munlock(self.pointer, len(self.value))


def atomic_write(path, encrypted):
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encrypted)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def run(operation, directory):
    profile, encrypted_path = describe(directory)
    if operation == "describe":
        print(json.dumps({"status": "pass", "profile": profile}))
        return
    store.set_backend(profile["backend"])
    if operation == "open":
        plaintext = bytearray(store.open_sealed(profile["walletId"], encrypted_path.read_bytes()))
        require(len(plaintext) == FLASH_SIZE, "Private profile flash size is invalid")
        locked = LockedBuffer(plaintext)
        try:
            sys.stdout.buffer.write(plaintext)
            sys.stdout.buffer.flush()
        finally:
            locked.close()
        return
    plaintext = bytearray(sys.stdin.buffer.read(FLASH_SIZE + 1))
    require(len(plaintext) == FLASH_SIZE, "Private flash save requires exactly one image")
    locked = LockedBuffer(plaintext)
    try:
        # Authenticate the existing image first. A missing/denied Keychain key
        # must never be treated as permission to replace a funded profile key.
        previous = bytearray(store.open_sealed(profile["walletId"], encrypted_path.read_bytes()))
        try:
            require(len(previous) == FLASH_SIZE, "Existing private flash size is invalid")
        finally:
            previous[:] = b"\0" * len(previous)
        encrypted = store.seal(profile["walletId"], plaintext)
        recovered = bytearray(store.open_sealed(profile["walletId"], encrypted))
        try:
            require(hmac.compare_digest(recovered, plaintext), "Private flash recovery verification failed")
        finally:
            recovered[:] = b"\0" * len(recovered)
        atomic_write(encrypted_path, encrypted)
        print(json.dumps({"status": "pass"}))
    finally:
        locked.close()


def main():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("describe", "open", "save"))
    parser.add_argument("--profile", type=Path, required=True)
    args = parser.parse_args()
    try:
        run(args.operation, args.profile)
    except (ProfileError, store.KeyStoreError) as error:
        print(str(error), file=sys.stderr)
        return 1
    except Exception:
        print("Private profile operation failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
