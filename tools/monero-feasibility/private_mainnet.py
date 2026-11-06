#!/usr/bin/env python3
"""Provision a fresh mainnet emulator wallet without exporting its mnemonic.

Secret-bearing flash is stored only in a private, OS-keychain-encrypted file.
Provisioning and restoration run in separate processes. No signing, transfer
or transaction broadcast is implemented here.
"""
import argparse
import ctypes
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import secrets
import ssl
import subprocess
import sys
import urllib.request
import uuid

HERE = Path(__file__).resolve().parent
PRIMARY = "https://node.sethforprivacy.com"
SECONDARY = "https://xmr.triplebit.org"
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
WIDTHS = {2: 1, 3: 2, 5: 3, 6: 4, 7: 5, 9: 6, 10: 7, 11: 8}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def wipe(value):
    if value:
        ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(value)), 0, len(value))


def fields(body):
    """Bounded views into a mutable response; no private payload copies/logs."""
    view = memoryview(body).cast("B")
    offset, result = 0, {}

    def number():
        nonlocal offset
        value = 0
        for shift in range(0, 70, 7):
            require(offset < len(view), "Malformed private firmware response")
            byte = view[offset]
            offset += 1
            value |= (byte & 127) << shift
            if byte < 128:
                require(value <= 2**64-1, "Malformed private firmware response")
                return value
        raise RuntimeError("Malformed private firmware response")

    while offset < len(view):
        key = number()
        field, encoding = key >> 3, key & 7
        require(field > 0 and encoding == 2, "Malformed private firmware response")
        size = number()
        require(size <= len(view) - offset, "Malformed private firmware response")
        result.setdefault(field, []).append(view[offset:offset + size])
        offset += size
    return result


def only(values, field, default=None):
    items = values.get(field, [default])
    require(len(items) == 1, "Repeated private firmware response field")
    return items[0]


def atomic_write(path, data):
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def save_json(path, value):
    atomic_write(path, (json.dumps(value, indent=2) + "\n").encode())


def independent_core(path):
    spec = importlib.util.spec_from_file_location("private_public_arithmetic", HERE / "reference.py")
    reference = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reference)
    core = reference.Core(path)
    reference.known_anchors(core)
    return core


def decode_address(address, core):
    require(type(address) is str and len(address) == 95, "Invalid mainnet receive address")
    decoded = bytearray()
    for position in range(0, len(address), 11):
        block = address[position:position + 11]
        require(len(block) in WIDTHS, "Invalid mainnet address block")
        value = 0
        for character in block:
            require(character in ALPHABET, "Invalid mainnet address alphabet")
            value = value * 58 + ALPHABET.index(character)
        size = WIDTHS[len(block)]
        require(value < 2 ** (size * 8), "Invalid mainnet address encoding")
        decoded.extend(value.to_bytes(size, "big"))
    require(len(decoded) == 69 and decoded[0] == 18 and
            core.hash(bytes(decoded[:-4]))[:4] == decoded[-4:],
            "Mainnet receive address checksum/network verification failed")
    return decoded[1:33], decoded[33:65]


def address_request():
    from private_transport import _number as fv
    return b"".join(fv(1, item) for item in [0x8000002c, 0x80000080, 0x80000000]) + fv(2, 1) + fv(3, 0) + fv(4, 0) + fv(5, 0)


def read_address(session, core):
    response = session.rpc(540, address_request())
    require(response[0] == 541, "Firmware refused the mainnet address request")
    address = bytes(only(fields(response[1]), 1, b"")).decode("ascii")
    decode_address(address, core)
    public_reference = json.loads((HERE / "evidence/2026-11-04-interoperability/host.json").read_text())
    public_reference = public_reference.get("reference", public_reference)
    require(address not in {case.get("address") for case in public_reference["cases"]},
            "Generated wallet unexpectedly matches a published test fixture")
    return address


def node_call(endpoint, method, params=None):
    require(endpoint in [PRIMARY, SECONDARY], "Unapproved remote node")
    context = ssl.create_default_context(cafile="/etc/ssl/cert.pem")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=context))
    payload = json.dumps({"jsonrpc": "2.0", "id": "0", "method": method, "params": params or {}}).encode()
    request = urllib.request.Request(endpoint + "/json_rpc", payload, {"Content-Type": "application/json"})
    with opener.open(request, timeout=25) as response:
        raw = response.read(1024 * 1024 + 1)
    require(len(raw) <= 1024 * 1024, "Remote node response exceeds bound")
    result = json.loads(raw)
    require("result" in result and "error" not in result, "Remote node refused a public status query")
    return result["result"]


def mainnet_checkpoint():
    nodes = [node_call(endpoint, "get_info") for endpoint in [PRIMARY, SECONDARY]]
    for node in nodes:
        require(node.get("nettype") == "mainnet" and node.get("mainnet") is True and
                node.get("synchronized") is True and node.get("height", 0) > 3_000_000,
                "Remote node is not synchronized Monero mainnet")
    height = min(node["height"] for node in nodes) - 5
    headers = [node_call(endpoint, "get_block_header_by_height", {"height": height})["block_header"]
               for endpoint in [PRIMARY, SECONDARY]]
    require(headers[0]["hash"] == headers[1]["hash"] and
            all(header["major_version"] == 16 for header in headers),
            "Independent mainnet nodes disagree or require an unsupported fork")
    return {"daemon_url": PRIMARY, "fallback_daemon_url": SECONDARY,
            "restore_height": max(0, min(node["height"] for node in nodes) - 100),
            "checked_height": height, "checked_block_hash": headers[0]["hash"],
            "tls_verified": True, "wallet_data_sent_to_remote": False}


def provision(args):
    import private_keystore as store
    from private_transport import PrivateSession
    metadata = json.loads((args.wallet_dir / "wallet.json").read_text())
    store.set_backend(metadata["keystore_backend"])
    # Fail before seed generation if native Keychain protection is unavailable.
    probe = b"private wallet keychain readiness"
    require(store.open_sealed(metadata["wallet_id"], store.seal(metadata["wallet_id"], probe)) == probe,
            "Private wallet Keychain roundtrip failed")
    core = independent_core(args.core_library)
    require(not (args.wallet_dir / "wallet.enc").exists(), "Wallet already provisioned")
    session = PrivateSession(args.library)
    plain = None
    try:
        session.reset()
        address = read_address(session, core)
        plain = session.snapshot_locked()
        encrypted = store.seal(metadata["wallet_id"], plain)
        atomic_write(args.wallet_dir / "wallet.enc", encrypted)
        atomic_write(args.wallet_dir / "wallet.backup.enc", encrypted)
        metadata.update({"status": "provisioned", "address": address,
                         "seed_creation": "firmware ResetDevice; 256-bit strength; fresh OS host entropy",
                         "generated_not_imported": True, "no_backup": False,
                         "seed_exported": False, "debug_state_requested": False,
                         "seed_screens_saved": False, "flash_memory_locked": True})
        save_json(args.wallet_dir / "wallet.json", metadata)
    finally:
        wipe(plain)
        session.close()


def restore_check(args):
    import private_keystore as store
    from private_transport import PrivateSession, _number as fv
    metadata = json.loads((args.wallet_dir / "wallet.json").read_text())
    require(metadata.get("status") == "provisioned", "Wallet is not ready for restoration proof")
    store.set_backend(metadata["keystore_backend"])
    core = independent_core(args.core_library)
    plain = bytearray(store.open_sealed(metadata["wallet_id"], (args.wallet_dir / "wallet.enc").read_bytes()))
    backup = bytearray(store.open_sealed(metadata["wallet_id"], (args.wallet_dir / "wallet.backup.enc").read_bytes()))
    try:
        require(plain == backup and len(plain) == 1024 * 1024, "Encrypted wallet backup mismatch")
        session = PrivateSession(args.library, initial_flash=plain)
    finally:
        wipe(plain)
        wipe(backup)
    credential_plain, response = None, None
    try:
        features = session.features()
        require(features["initialized"] and not features["imported"] and not features["no_backup"],
                "Restored firmware wallet is not an initialized generated wallet")
        address = read_address(session, core)
        require(address == metadata["address"], "Restored wallet derived a different address")
        response = session.rpc(542, b"".join(fv(1, item) for item in [0x8000002c, 0x80000080, 0x80000000]) + fv(2, 0))
        require(response[0] == 543, "Firmware refused authorized view-key export")
        result = fields(response[1])
        view_key = bytearray(only(result, 1, b""))
        try:
            require(len(view_key) == 32 and bytes(only(result, 2, b"")).decode("ascii") == address,
                    "View credentials belong to a different wallet")
            _, public_view = decode_address(address, core)
            require(core.op("base", bytes(view_key)) == public_view,
                    "Independent view-key/address verification failed")
            credential_plain = bytearray(json.dumps({"type": "watch_credentials", "address": address,
                "view_key": view_key.hex(), "wallet_password": secrets.token_hex(32),
                "restore_height": metadata["restore_height"]}).encode())
            atomic_write(args.wallet_dir / "watch.enc", store.seal(metadata["wallet_id"], credential_plain))
        finally:
            wipe(view_key)
        metadata.update({"status": "ready", "restore_verified": True,
                         "restored_in_separate_process": True, "load_device_used": False,
                         "independent_address_checksum_verified": True,
                         "independent_view_key_verified": True, "mainnet_transfers_sent": 0})
        save_json(args.wallet_dir / "wallet.json", metadata)
    finally:
        wipe(credential_plain)
        if response is not None:
            wipe(response[1])
        session.close()


def create(args):
    checkpoint = mainnet_checkpoint()
    wallet_id = "monero-mainnet-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:12]
    root = args.wallet_root.expanduser().resolve()
    require(not root.is_relative_to(HERE.parents[3]) and not root.is_relative_to(Path("/private/tmp")),
            "Private mainnet wallet storage must be outside Git and temporary directories")
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    wallet_dir = root / wallet_id
    wallet_dir.mkdir(mode=0o700)
    metadata = {"schema_version": 1, "wallet_id": wallet_id, "network": "mainnet",
                "status": "preparing", "keystore_backend": "login", "keystore": "macOS login Keychain",
                "library": str(args.library), "library_sha256": sha(args.library),
                "core_library": str(args.core_library), "created_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "physical_device_accessed": False, "public_test_seed": False, **checkpoint}
    save_json(wallet_dir / "wallet.json", metadata)
    for command in ["_provision", "_restore"]:
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()), command,
                                 "--wallet-dir", str(wallet_dir), "--library", str(args.library),
                                 "--core-library", str(args.core_library)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
        if result.returncode:
            metadata = json.loads((wallet_dir / "wallet.json").read_text())
            metadata.update({"status": "error", "failed_stage": command})
            save_json(wallet_dir / "wallet.json", metadata)
            raise RuntimeError(f"Private wallet {command} failed; no funding address released; exit {result.returncode}")
    metadata = json.loads((wallet_dir / "wallet.json").read_text())
    require(metadata.get("status") == "ready" and metadata.get("restore_verified"),
            "Private wallet restoration verification incomplete")
    print(json.dumps({"status": "ready", "network": "mainnet", "address": metadata["address"],
                      "wallet_dir": str(wallet_dir), "restore_verified": True,
                      "seed_exported": False, "mainnet_transfers_sent": 0}, indent=2))


def main():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["create", "_provision", "_restore"])
    parser.add_argument("--wallet-root", type=Path,
                        default=Path.home() / "Library/Application Support/KeepKey/MoneroEmulator")
    parser.add_argument("--wallet-dir", type=Path)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--core-library", type=Path, required=True)
    args = parser.parse_args()
    args.library, args.core_library = args.library.resolve(), args.core_library.resolve()
    require(args.library.is_file() and args.core_library.is_file(), "Required emulator/reference artifact is missing")
    if args.command != "create":
        require(args.wallet_dir and args.wallet_dir.is_dir(), "Private wallet directory is missing")
        args.wallet_dir = args.wallet_dir.resolve()
    {"create": create, "_provision": provision, "_restore": restore_check}[args.command](args)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Exceptions never include request bodies, flash, keys or seed text.
        message = str(error) if isinstance(error, RuntimeError) else "Private wallet operation failed"
        print(message, file=sys.stderr)
        sys.exit(1)
