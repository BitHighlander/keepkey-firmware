#!/usr/bin/env python3
"""Verify encrypted key-image synchronization over the native emulator HID rings.

Only the checked-in public fixture wallets are installed, in anonymous flash.
Expected key images and ring proofs use the separately built Monero Core adapter;
AEAD verification uses libsodium, not the candidate ChaCha implementation.
"""
import argparse
import ctypes
import ctypes.util
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import sys
import time

import test_wire as wire

HERE = Path(__file__).resolve().parent
EXPERIMENT = HERE.parent
L = 2**252 + 27742317777372353535851937790883648493


def transfer(case, *, explicit=True, additional=None, tx_public=None):
    output = bytes.fromhex(case["output_public"])
    tx = tx_public or bytes.fromhex(case["tx_public"])
    index = case["output_index"]
    extra = additional or []
    body = wire.fb(1, output) + wire.fb(2, tx)
    body += b"".join(wire.fb(3, key) for key in extra)
    body += wire.fv(4, index)
    if explicit:
        body += wire.fv(5, case["major"]) + wire.fv(6, case["minor"])
    return {"case": case, "output": output, "tx": tx, "extra": extra,
            "index": index, "body": body}


def control_hash(core, records):
    hashes = [core.hash(td["output"] + td["tx"] + b"".join(td["extra"]) + wire.vint(td["index"]))
              for td in records]
    return core.hash(b"".join(hashes))


def init_request(core, records, *, account=0, network=0, expected=None, count=None):
    body = wire.fv(1, len(records) if count is None else count)
    body += wire.fb(2, control_hash(core, records) if expected is None else expected)
    body += b"".join(wire.fv(3, index) for index in [0x8000002c, 0x80000080, 0x80000000 | account])
    body += wire.fv(4, network)
    for major, minors in [(0, [0, 1]), (1, [0]), (100, [100])]:
        sub = wire.fv(1, major) + b"".join(wire.fv(2, minor) for minor in minors)
        body += wire.fb(5, sub)
    return body


class Sodium:
    def __init__(self):
        name = ctypes.util.find_library("sodium") or "/opt/homebrew/lib/libsodium.dylib"
        self.lib = ctypes.CDLL(name)
        self.lib.sodium_init.restype = ctypes.c_int
        if self.lib.sodium_init() < 0:
            raise RuntimeError("libsodium initialization failed")
        self.fn = self.lib.crypto_aead_chacha20poly1305_ietf_decrypt
        self.fn.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_void_p,
                            ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p,
                            ctypes.c_ulonglong, ctypes.c_void_p, ctypes.c_void_p]
        self.fn.restype = ctypes.c_int

    def decrypt(self, key, nonce, blob):
        out = ctypes.create_string_buffer(max(len(blob), 1))
        length = ctypes.c_ulonglong()
        if self.fn(out, ctypes.byref(length), None, blob, len(blob), None, 0, nonce, key):
            raise ValueError("AEAD authentication failed")
        return out.raw[:length.value]


def verify_proof(core, plaintext, output):
    if len(plaintext) != 96:
        return False
    image, c, r = plaintext[:32], plaintext[32:64], plaintext[64:]
    if any(int.from_bytes(x, "little") >= L for x in [c, r]):
        return False
    left = core.op("add", core.op("base", r), core.op("mul", output, c))
    right = core.op("add", core.op("mul", core.hp(output), r), core.op("mul", image, c))
    return core.hs(image + left + right) == c


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--core-library", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reference", type=Path, default=EXPERIMENT / "evidence/2026-11-04-interoperability/host.json")
    parser.add_argument("--expect-unsupported", action="store_true")
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        parser.error("output must be empty")
    reference = json.loads(args.reference.read_text())
    reference = reference.get("reference", reference)
    if reference.get("fixture_mnemonics_public") != wire.PUBLIC_FIXTURES:
        parser.error("requires only the fixed public reference wallets")
    if args.expect_unsupported:
        checks = wire.Checks()
        session = wire.Session(args.library.resolve(), out, "ordinary-key-image")
        init = wire.fv(1, 1) + wire.fb(2, bytes(32))
        init += b"".join(wire.fv(3, n) for n in [0x8000002c, 0x80000080, 0x80000000])
        requests = [(530, init), (532, b""), (534, b"")]
        try:
            for kind, payload in requests:
                msg, events, _ = session.rpc(kind, payload)
                wire.failure(checks, f"ordinary-build-rejects-{kind}", msg, [1])
                checks.record(f"ordinary-build-{kind}-no-prompt", events == [3])
                checks.record(f"ordinary-build-{kind}-transport-recovers", session.rpc(55)[0][0] == 17)
        finally:
            session.close()
        report = {"status": "pass", "checks": checks.items, "check_count": len(checks.items),
                  "ordinary_build_key_image_rejected": [530, 532, 534],
                  "library_sha256": wire.sha(args.library.read_bytes()), "physical_device_accessed": False}
        (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report)); return
    if not args.core_library:
        parser.error("--core-library is required for key-image verification")
    spec = importlib.util.spec_from_file_location("key_image_reference", EXPERIMENT / "reference.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    core = module.Core(args.core_library.resolve())
    module.known_anchors(core)
    sodium = Sodium()
    checks = wire.Checks()
    session = wire.Session(args.library.resolve(), out, "key-image")
    sessions = [session]
    lib = session.lib
    for name in ["monero_key_image_active", "monero_key_image_state_is_zero"]:
        getattr(lib, name).restype = ctypes.c_bool
        getattr(lib, name).argtypes = []

    def state_zero(parked=False):
        if parked:
            # Init consent is pending; no session has been established yet.
            return lib.monero_key_image_state_is_zero()
        until = time.monotonic() + 2
        while not lib.kkemu_trylock():
            if time.monotonic() > until:
                raise RuntimeError("state observer could not acquire emulator lock")
            time.sleep(.001)
        try:
            return lib.monero_key_image_state_is_zero()
        finally:
            lib.kkemu_unlock()

    def chosen(fixture="abandon", account=0):
        wanted = [((0, 0), 0), ((0, 1), 1), ((1, 0), 128), ((100, 100), 65537)]
        return [transfer(next(case for case in reference["cases"]
                              if case["label"].startswith(f"{fixture}-account{account}-")
                              and (case["major"], case["minor"]) == pair
                              and case["output_index"] == index)) for pair, index in wanted]

    def passphrase_record(passphrase):
        phrase = wire.PUBLIC_FIXTURES["abandon"].encode()
        seed = hashlib.pbkdf2_hmac("sha512", phrase, ("mnemonic" + passphrase).encode(), 2048)
        digest = hmac.new(b"ed25519 seed", seed, "sha512").digest()
        key, chain = digest[:32], digest[32:]
        for index in [44, 128, 0]:
            digest = hmac.new(chain, b"\0" + key + (index | 0x80000000).to_bytes(4, "big"), "sha512").digest()
            key, chain = digest[:32], digest[32:]
        spend = core.op("reduce", key)
        view = core.hs(spend)
        tx_secret = core.hs(b"Public key-image passphrase fixture sender")
        tx_public = core.op("base", tx_secret)
        derivation = core.op("mul", core.op("mul", tx_public, view), (8).to_bytes(32, "little"))
        derived = core.hs(derivation + wire.vint(0))
        secret = ((int.from_bytes(spend, "little") + int.from_bytes(derived, "little")) % L).to_bytes(32, "little")
        output = core.op("base", secret)
        case = {"output_public": output.hex(), "tx_public": tx_public.hex(), "output_index": 0,
                "major": 0, "minor": 0, "key_image": core.op("mul", core.hp(output), secret).hex()}
        return transfer(case)

    def begin(records, label, **kw):
        msg, events, screens = session.rpc(530, init_request(core, records, **kw))
        checks.record(label + "-init-ack", msg[0] == 531 and 26 in events)
        checks.record(label + "-consent", any("key image" in x.get("title", "").lower()
                                             or "key image" in x.get("body", "").lower() for x in screens))

    def step(records, label):
        payload = b"".join(wire.fb(1, td["body"]) for td in records)
        msg, events, _ = session.rpc(532, payload)
        checks.record(label + "-step-ack", msg[0] == 533 and events == [533])
        items = wire.fields(msg[1]).get(1, [])
        checks.record(label + "-step-count", len(items) == len(records))
        results = []
        for item in items:
            item = wire.fields(item)
            iv, blob = wire.only(item, 1), wire.only(item, 3)
            checks.record(label + "-encrypted-shape", len(iv) == 12 and len(blob) == 112)
            results.append((iv, blob))
        return results

    def finish(label):
        msg, _, _ = session.rpc(534)
        checks.record(label + "-final-ack", msg[0] == 535)
        key = wire.only(wire.fields(msg[1]), 1)
        checks.record(label + "-final-key-only", len(key) == 32 and set(wire.fields(msg[1])) == {1})
        checks.record(label + "-state-zero", state_zero())
        return key

    def failure(msg, label, codes=(1, 3, 4, 11)):
        wire.failure(checks, label, msg, list(codes))
        checks.record(label + "-state-zero", state_zero())
        checks.record(label + "-no-late-key", session.receive(.025) is None)

    verified_outputs = 0
    try:
        records = chosen()
        msg, _, _ = session.rpc(530, init_request(core, records))
        failure(msg, "missing-wallet-refused", (11,))
        wire.load_wallet(session, checks, "abandon")
        for kind in [532, 534]:
            msg, _, _ = session.rpc(kind)
            failure(msg, f"inactive-{kind}-refused")

        # Explicit consent must precede any accepted session/encryption key.
        first, _, _ = session.rpc(530, init_request(core, records), approve=None)
        checks.record("init-consent-button", first[0] == 26)
        checks.record("no-confidential-session-before-consent", state_zero(parked=True))
        checks.record("no-derived-node-held-during-consent", session.derived_node_zero(parked=True))
        checks.record("no-init-ack-before-consent", session.receive(.05) is None)
        session.send(20)
        failure(session.receive(), "init-consent-cancelled", (4,))

        for account in [0, 1]:
            for network in [0, 1, 2]:
                records = chosen(account=account)
                label = f"account{account}-network{network}"
                begin(records, label, account=account, network=network)
                # Status queries must not revoke an authorized sync.
                status, _, _ = session.rpc(55)
                checks.record(label + "-status-preserves-sync", status[0] == 17)
                blobs = step(records[:2], label + "-batch0") + step(records[2:], label + "-batch1")
                checks.record(label + "-nonce-unique", len(set(iv for iv, _ in blobs)) == len(blobs))
                key = finish(label)
                for td, (iv, blob) in zip(records, blobs):
                    plaintext = sodium.decrypt(key, iv, blob)
                    checks.record(label + "-independent-key-image", plaintext[:32].hex() == td["case"]["key_image"])
                    checks.record(label + "-independent-ring-proof", verify_proof(core, plaintext, td["output"]))
                    changed = bytearray(blob); changed[0] ^= 1
                    try:
                        sodium.decrypt(key, iv, bytes(changed))
                        tamper_refused = False
                    except ValueError:
                        tamper_refused = True
                    checks.record(label + "-ciphertext-tamper-rejected", tamper_refused)
                    changed = bytearray(plaintext); changed[-1] ^= 1
                    checks.record(label + "-proof-tamper-rejected", not verify_proof(core, bytes(changed), td["output"]))
                    verified_outputs += 1
                msg, _, _ = session.rpc(534)
                failure(msg, label + "-final-replay-refused")

        records = chosen()
        # Additional tx-key compression and non-explicit subaddress discovery.
        alternative = transfer(records[1]["case"], explicit=False,
                               additional=[records[1]["tx"]], tx_public=records[0]["tx"])
        begin([alternative], "additional-key-fallback")
        blob = step([alternative], "additional-key-fallback")[0]
        key = finish("additional-key-fallback")
        plaintext = sodium.decrypt(key, *blob)
        checks.record("additional-key-owner-discovery", plaintext[:32].hex() == alternative["case"]["key_image"])
        checks.record("additional-key-proof", verify_proof(core, plaintext, alternative["output"]))
        verified_outputs += 1

        # Integrity binds output count, ordering, all tx keys and varint index.
        begin(records[:1], "wrong-final-hash", expected=bytes(32))
        step(records[:1], "wrong-final-hash")
        msg, _, _ = session.rpc(534)
        failure(msg, "wrong-final-hash-no-key")
        begin(records, "early-final")
        step(records[:1], "early-final")
        msg, _, _ = session.rpc(534)
        failure(msg, "early-final-no-key")
        begin(records[:2], "reordered-transcript")
        step(list(reversed(records[:2])), "reordered-transcript")
        msg, _, _ = session.rpc(534)
        failure(msg, "reordered-transcript-no-key")

        for label, td in [
            ("unowned-output", dict(records[0], body=wire.fb(1, records[1]["output"]) + wire.fb(2, records[0]["tx"]) + wire.fv(4, 0))),
            ("identity-tx-key", dict(records[0], body=wire.fb(1, records[0]["output"]) + wire.fb(2, bytes([1])+bytes(31)) + wire.fv(4, 0))),
            ("invalid-point", dict(records[0], body=wire.fb(1, bytes([255])*32) + wire.fb(2, records[0]["tx"]) + wire.fv(4, 0))),
            ("index-over-uint32", dict(records[0], body=wire.fb(1, records[0]["output"]) + wire.fb(2, records[0]["tx"]) + wire.fv(4, 0x100000000))),
            ("invalid-additional-point", transfer(records[0]["case"], additional=[bytes([255])*32])),
            ("short-output-key", dict(records[0], body=wire.fb(1, bytes(31)) + wire.fb(2, records[0]["tx"]) + wire.fv(4, 0))),
        ]:
            begin(records[:1], label)
            msg, _, _ = session.rpc(532, wire.fb(1, td["body"]))
            failure(msg, label + "-refused")
        begin(records[:1], "too-many-outputs")
        msg, _, _ = session.rpc(532, b"".join(wire.fb(1, td["body"]) for td in records[:2]))
        failure(msg, "too-many-outputs-refused")
        begin(records[:1], "empty-batch")
        msg, _, _ = session.rpc(532)
        failure(msg, "empty-batch-refused")
        begin(records[:1], "malformed-protobuf")
        msg, _, _ = session.rpc(532, b"\x0a\x80")
        failure(msg, "malformed-protobuf-revokes-session")
        begin(records[:1], "oversized-batch")
        msg, _, _ = session.rpc(532, wire.fb(1, records[0]["body"]) * 5)
        failure(msg, "oversized-batch-revokes-session")

        for label, kind in [("cancel", 20), ("initialize", 0), ("clear-session", 24), ("unrelated-ping", 1)]:
            begin(records[:1], label)
            session.rpc(kind)
            checks.record(label + "-revokes-confidential-state", state_zero())
            msg, _, _ = session.rpc(534)
            failure(msg, label + "-no-final-key")

        lib.session_clear.argtypes = [ctypes.c_bool]
        lib.session_clear.restype = None
        for clear_pin in [False, True]:
            label = f"direct-session-clear-{clear_pin}"
            begin(records[:1], label)
            until = time.monotonic() + 2
            while not lib.kkemu_trylock():
                if time.monotonic() > until:
                    raise RuntimeError("direct session-clear test could not acquire emulator lock")
                time.sleep(.001)
            try:
                lib.session_clear(clear_pin)
            finally:
                lib.kkemu_unlock()
            checks.record(label + "-revokes-confidential-grant", state_zero())
            msg, _, _ = session.rpc(534)
            failure(msg, label + "-no-final-key")

        # Checked RNG fails closed, then re-arm the isolated emulator test seam.
        lib.rng_health_force_verdict.argtypes = [ctypes.c_bool]
        lib.rng_health_force_verdict(False)
        msg, _, _ = session.rpc(530, init_request(core, records[:1]))
        failure(msg, "rng-failure-no-session", (9,))
        lib.rng_health_force_verdict(True)
        msg, _, _ = session.rpc(55)
        checks.record("transport-usable-after-rejections", msg[0] == 17)
        session.close()
        session = wire.Session(args.library.resolve(), out, "key-image-pin")
        sessions.append(session)
        wire.load_wallet(session, checks, "abandon", pin="1234")
        session.rpc(24)
        msg, _, _ = session.rpc(530, init_request(core, records[:1]))
        checks.record("key-image-locked-wallet-demands-pin", msg[0] == 18)
        session.send(20)
        failure(session.receive(), "key-image-pin-cancel-no-session", (6,))
        msg, events, _ = session.rpc(530, init_request(core, records[:1]), pin="1234")
        checks.record("key-image-pin-and-consent-required", msg[0] == 531 and 18 in events and 26 in events)
        blob = step(records[:1], "pin-authorized")[0]
        key = finish("pin-authorized")
        plaintext = sodium.decrypt(key, *blob)
        checks.record("pin-authorized-independent-key-image", plaintext[:32].hex() == records[0]["case"]["key_image"])
        verified_outputs += 1
        session.close()
        session = wire.Session(args.library.resolve(), out, "key-image-passphrase")
        sessions.append(session)
        wire.load_wallet(session, checks, "abandon", passphrase=True)
        msg, events, _ = session.rpc(530, init_request(core, records[:1]))
        checks.record("key-image-passphrase-challenged", msg[0] == 41 and 26 in events)
        session.send(20)
        failure(session.receive(), "key-image-passphrase-cancel-no-session", (11,))
        msg, events, _ = session.rpc(530, init_request(core, records[:1]), passphrase="")
        checks.record("key-image-passphrase-and-consent-required", msg[0] == 531 and 41 in events and 26 in events)
        blob = step(records[:1], "passphrase-authorized")[0]
        key = finish("passphrase-authorized")
        plaintext = sodium.decrypt(key, *blob)
        checks.record("passphrase-authorized-independent-key-image", plaintext[:32].hex() == records[0]["case"]["key_image"])
        verified_outputs += 1
        session.rpc(24)
        public_passphrase = "Monero key-image public fixture"
        other = passphrase_record(public_passphrase)
        msg, events, _ = session.rpc(530, init_request(core, [other]), passphrase=public_passphrase)
        checks.record("nonempty-passphrase-reauthorized-session", msg[0] == 531 and 41 in events and 26 in events)
        blob = step([other], "nonempty-passphrase")[0]
        key = finish("nonempty-passphrase")
        plaintext = sodium.decrypt(key, *blob)
        checks.record("nonempty-passphrase-independent-key-image", plaintext[:32].hex() == other["case"]["key_image"])
        checks.record("nonempty-passphrase-independent-proof", verify_proof(core, plaintext, other["output"]))
        verified_outputs += 1
    finally:
        session.close()
    report = {
        "schema_version": 1, "status": "pass", "check_count": len(checks.items),
        "checks": checks.items, "independently_verified_outputs": verified_outputs,
        "reference_core_commit": reference["core_commit"],
        "core_library_sha256": wire.sha(args.core_library.read_bytes()),
        "library_sha256": wire.sha(args.library.read_bytes()),
        "source_sha256": wire.sha(Path(__file__).read_bytes()),
        "scope": "bounded legacy/CLSAG key-image sync with ring-one proofs and final-transcript AEAD-key release",
        "limits": {"outputs": 64, "batch": 4, "additional_keys": 16, "output_index_max": 0xffffffff},
        "public_fixtures_only": True, "physical_device_accessed": False,
        "existing_flash_file_opened": False, "production_ready": False,
    }
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": "pass", "checks": len(checks.items),
                      "independently_verified_outputs": verified_outputs, "output": str(out)}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
