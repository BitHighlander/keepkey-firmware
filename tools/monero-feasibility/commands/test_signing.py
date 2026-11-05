#!/usr/bin/env python3
"""Exercise native-emulator Monero transaction construction with synthetic funding.

All wallets and ring members are public disposable fixtures. Nothing is mined,
relayed or broadcast. Returned transactions are independently decoded and scanned
for the fixture recipients, in addition to official Core RingCT verification.
"""
import argparse
import ctypes
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import unicodedata

import test_wire as wire

HERE = Path(__file__).resolve().parent
EXPERIMENT = HERE.parent
U8_32 = ctypes.c_uint8 * 32
L = 2**252 + 27742317777372353535851937790883648493
H = bytes.fromhex("8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94")


class Ring(ctypes.Structure):
    _fields_ = [("global_index", ctypes.c_uint64), ("public_key", U8_32), ("commitment", U8_32)]


class Source(ctypes.Structure):
    _fields_ = [("amount", ctypes.c_uint64), ("real_member", ctypes.c_uint32),
                ("output_index", ctypes.c_uint32), ("subaddress_major", ctypes.c_uint32),
                ("subaddress_minor", ctypes.c_uint32), ("tx_public_key", U8_32),
                ("mask", U8_32), ("additional_key_count", ctypes.c_uint32),
                ("additional_tx_public_keys", U8_32 * 16), ("ring", Ring * 16)]


class Destination(ctypes.Structure):
    _fields_ = [("amount", ctypes.c_uint64), ("address", ctypes.c_char * 96),
                ("is_change", ctypes.c_uint32), ("change_major", ctypes.c_uint32),
                ("change_minor", ctypes.c_uint32)]


class Plan(ctypes.Structure):
    _fields_ = [("network", ctypes.c_uint32), ("input_count", ctypes.c_uint32),
                ("output_count", ctypes.c_uint32), ("fee", ctypes.c_uint64),
                ("sources", Source * 4), ("destinations", Destination * 4)]


def set_bytes(array, data):
    if len(data) != len(array):
        raise RuntimeError("invalid fixture array size")
    array[:] = data


def copy_plan(plan):
    return Plan.from_buffer_copy(bytes(plan))


def source_wire(source):
    value = wire.fv(1, source.amount) + wire.fv(2, source.real_member)
    value += wire.fv(3, source.output_index) + wire.fv(4, source.subaddress_major)
    value += wire.fv(5, source.subaddress_minor) + wire.fb(6, bytes(source.tx_public_key))
    value += wire.fb(7, bytes(source.mask))
    for ring in source.ring:
        value += wire.fb(8, wire.fv(1, ring.global_index) + wire.fb(2, bytes(ring.public_key))
                         + wire.fb(3, bytes(ring.commitment)))
    for i in range(source.additional_key_count):
        value += wire.fb(9, bytes(source.additional_tx_public_keys[i]))
    return value


def encode_plan(plan, path=None, unlock=0):
    path = [0x8000002c, 0x80000080, 0x80000000] if path is None else path
    value = b"".join(wire.fv(1, part) for part in path)
    value += wire.fv(2, plan.network) + wire.fv(3, plan.fee)
    for i in range(plan.input_count):
        value += wire.fb(4, source_wire(plan.sources[i]))
    for i in range(plan.output_count):
        dest = plan.destinations[i]
        output = wire.fv(1, dest.amount) + wire.fb(2, bytes(dest.address)) + wire.fv(3, dest.is_change)
        if dest.is_change:
            output += wire.fv(4, dest.change_major) + wire.fv(5, dest.change_minor)
        value += wire.fb(5, output)
    return value + wire.fv(6, unlock)


def abi_check(out):
    source = out / "abi.c"
    source.write_text('''#include <stdio.h>
#include <stddef.h>
#include "core-signing.h"
int main(void){printf("{\\"ring\\":%zu,\\"source\\":%zu,\\"destination\\":%zu,\\"plan\\":%zu,\\"ring_offset\\":%zu,\\"sources_offset\\":%zu,\\"destinations_offset\\":%zu}\\n",sizeof(monero_core_ring_member),sizeof(monero_core_source),sizeof(monero_core_destination),sizeof(monero_core_plan),offsetof(monero_core_source,ring),offsetof(monero_core_plan,sources),offsetof(monero_core_plan,destinations));}
''')
    executable = out / "abi"
    command = ["cc", "-std=c11", "-I", str(HERE), str(source), "-o", str(executable)]
    compiled = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (out / "abi-build.log").write_text(json.dumps(command) + "\n" + compiled.stdout)
    if compiled.returncode:
        raise RuntimeError("C ABI check compilation failed")
    actual = json.loads(subprocess.check_output([str(executable)], text=True))
    expected = {"ring": ctypes.sizeof(Ring), "source": ctypes.sizeof(Source),
                "destination": ctypes.sizeof(Destination), "plan": ctypes.sizeof(Plan),
                "ring_offset": Source.ring.offset, "sources_offset": Plan.sources.offset,
                "destinations_offset": Plan.destinations.offset}
    if actual != expected:
        raise RuntimeError(f"native Core C ABI mismatch: {actual} != {expected}")
    return actual


def commitment(core, mask, amount):
    return core.op("add", core.op("base", mask), core.op("mul", H, amount.to_bytes(32, "little")))


def passphrase_case(core, passphrase):
    """Derive another public wallet and its owned funding independently."""
    phrase = unicodedata.normalize("NFKD", wire.PUBLIC_FIXTURES["abandon"]).encode()
    salt = ("mnemonic" + unicodedata.normalize("NFKD", passphrase)).encode()
    seed = hashlib.pbkdf2_hmac("sha512", phrase, salt, 2048)
    digest = hmac.new(b"ed25519 seed", seed, "sha512").digest()
    key, chain = digest[:32], digest[32:]
    for index in [44, 128, 0]:
        digest = hmac.new(chain, b"\0" + key + (index | 0x80000000).to_bytes(4, "big"), "sha512").digest()
        key, chain = digest[:32], digest[32:]
    spend = core.op("reduce", key)
    view = core.hs(spend)
    tx_secret = core.hs(b"Monero signing public passphrase funding")
    tx_public = core.op("base", tx_secret)
    derivation = core.op("mul", core.op("mul", tx_public, view), (8).to_bytes(32, "little"))
    derived = core.hs(derivation + wire.vint(0))
    secret = ((int.from_bytes(spend, "little") + int.from_bytes(derived, "little")) % L).to_bytes(32, "little")
    output = core.op("base", secret)
    return {"label": "abandon-account0-sub0-0-output0", "major": 0, "minor": 0,
            "output_index": 0, "key_seed": key.hex(), "spend_secret": spend.hex(),
            "view_secret": view.hex(), "sub_spend_public": core.op("base", spend).hex(),
            "sub_view_public": core.op("base", view).hex(), "output_secret": secret.hex(),
            "output_public": output.hex(), "tx_public": tx_public.hex(),
            "key_image": core.op("mul", core.hp(output), secret).hex()}


def displayed_atomic(text, label):
    match = re.search(r"\b" + re.escape(label) + r"\s+(\d+)(?:\.(\d{1,12}))?\s+XMR\b", text)
    if not match:
        return None
    return int(match[1]) * 10**12 + int((match[2] or "").ljust(12, "0"))


def fixture(core, ref, *, count=1, subaddress=False, network=0):
    plan = Plan()
    plan.network, plan.input_count, plan.output_count = network, count, 2
    plan.fee = 20000000
    input_cases = []
    candidates = [((0, 0), 0), ((0, 1), 1), ((1, 0), 127), ((100, 100), 128)]
    if subaddress:
        candidates = candidates[1:] + candidates[:1]
    for i in range(count):
        pair, index = candidates[i]
        case = next(c for c in ref["cases"] if c["label"].startswith("abandon-account0-")
                    and (c["major"], c["minor"]) == pair and c["output_index"] == index)
        input_cases.append(case)
        source = plan.sources[i]
        source.amount, source.real_member = 7000000000000 + i * 1000000000000, 7
        source.output_index, source.subaddress_major, source.subaddress_minor = index, *pair
        set_bytes(source.tx_public_key, bytes.fromhex(case["tx_public"]))
        mask = core.hs(f"Monero public signing fixture mask/{i}/{pair}/{index}".encode())
        set_bytes(source.mask, mask)
        for j, member in enumerate(source.ring):
            member.global_index = 1000 + i * 100 + j * 2
            public = core.op("base", core.hs(f"Monero fixture decoy/{i}/{j}".encode()))
            decoy_mask = core.hs(f"Monero fixture decoy mask/{i}/{j}".encode())
            amount = source.amount + j * 100
            if j == source.real_member:
                public, decoy_mask, amount = bytes.fromhex(case["output_public"]), mask, source.amount
            set_bytes(member.public_key, public)
            set_bytes(member.commitment, commitment(core, decoy_mask, amount))
    recipient = next(c for c in ref["cases"] if c["label"] == "trezor-account0-sub0-0-output0")
    change = next(c for c in ref["cases"] if c["label"] == "abandon-account0-sub0-0-output0")
    plan.destinations[0].amount = 2000000000000
    plan.destinations[0].address = wire.expected_address(recipient, network, core).encode()
    plan.destinations[1].amount = sum(s.amount for s in plan.sources[:count]) - plan.destinations[0].amount - plan.fee
    plan.destinations[1].address = wire.expected_address(change, network, core).encode()
    plan.destinations[1].is_change = 1
    return plan, input_cases, [recipient, change]


def parse_transaction(blob):
    offset = 0
    def number():
        nonlocal offset
        value, offset = wire.read_vint(blob, offset)
        return value
    def take(n):
        nonlocal offset
        if n < 0 or offset + n > len(blob):
            raise RuntimeError("truncated Monero transaction")
        value = blob[offset:offset+n]
        offset += n
        return value
    version, unlock, count = number(), number(), number()
    if version != 2 or unlock != 0 or not 1 <= count <= 4:
        raise RuntimeError("unexpected transaction prefix version/unlock/input count")
    inputs = []
    for _ in range(count):
        if take(1) != b"\x02":
            raise RuntimeError("unexpected input variant")
        amount, ring_count = number(), number()
        if amount or ring_count != 16:
            raise RuntimeError("input must be RingCT with a 16-member ring")
        indices, index = [], 0
        for _ in range(ring_count):
            index += number()
            indices.append(index)
        inputs.append({"indices": indices, "key_image": take(32).hex()})
    output_count = number()
    if not 2 <= output_count <= 4:
        raise RuntimeError("unexpected output count")
    outputs = []
    for _ in range(output_count):
        amount = number()
        tag = take(1)[0]
        if amount != 0 or tag != 3:
            raise RuntimeError("unexpected confidential output variant")
        outputs.append({"public_key": take(32), "view_tag": take(1) if tag == 3 else None})
    extra = take(number())
    prefix_end = offset
    rct_type = take(1)[0]
    fee = number()
    if rct_type != 6:
        raise RuntimeError(f"expected Bulletproof+ / CLSAG transaction, got RingCT type {rct_type}")
    for output in outputs:
        output["encrypted_amount"] = take(8)
    for output in outputs:
        output["commitment"] = take(32)
    base_end = offset
    proof_count = number()
    if not 1 <= proof_count <= output_count:
        raise RuntimeError("invalid Bulletproof+ proof count")
    proofs = []
    for _ in range(proof_count):
        take(6 * 32)
        rounds = number()
        if not 6 <= rounds <= 8:
            raise RuntimeError("invalid Bulletproof+ inner-product dimension")
        take(rounds * 32)
        if number() != rounds:
            raise RuntimeError("Bulletproof+ L/R dimensions differ")
        take(rounds * 32)
        proofs.append(rounds)
    take(len(inputs) * (16 + 2) * 32)  # CLSAG s[16], c1, D, with no vector-size prefixes.
    take(len(inputs) * 32)  # pseudoOuts
    if offset != len(blob):
        raise RuntimeError(f"unexpected trailing bytes: {len(blob)-offset}")
    return {"version": version, "unlock_time": unlock, "inputs": inputs, "outputs": outputs,
            "extra": extra, "prefix_end": prefix_end, "base_end": base_end,
            "rct_type": rct_type, "fee": fee, "bulletproof_plus_rounds": proofs}


def transaction_public_keys(extra):
    primary, additional, offset = None, [], 0
    while offset < len(extra):
        tag = extra[offset]; offset += 1
        if tag == 0:
            continue
        if tag == 1:
            primary = extra[offset:offset+32]; offset += 32
        elif tag == 4:
            count, offset = wire.read_vint(extra, offset)
            if count > 4 or offset + count * 32 > len(extra):
                raise RuntimeError("invalid additional transaction keys")
            additional = [extra[offset+i*32:offset+(i+1)*32] for i in range(count)]
            offset += count * 32
        elif tag == 2:
            size = extra[offset]; offset += 1 + size
        else:
            raise RuntimeError(f"unexpected transaction extra tag {tag}")
    if primary is None or len(primary) != 32 or offset != len(extra):
        raise RuntimeError("invalid transaction extra")
    return primary, additional


def scan_outputs(core, parsed, recipients):
    primary, additional = transaction_public_keys(parsed["extra"])
    scanned = []
    for index, output in enumerate(parsed["outputs"]):
        matches = []
        for recipient_index, recipient in enumerate(recipients):
            view = bytes.fromhex(recipient["view_secret"])
            spend = bytes.fromhex(recipient["sub_spend_public"])
            for tx_public in [primary] + ([additional[index]] if additional else []):
                derivation = core.op("mul", core.op("mul", tx_public, view), (8).to_bytes(32, "little"))
                shared = core.hs(derivation + wire.vint(index))
                expected = core.op("add", core.op("base", shared), spend)
                if expected != output["public_key"]:
                    continue
                if output["view_tag"] != core.hash(b"view_tag" + derivation + wire.vint(index))[:1]:
                    raise RuntimeError("output view tag does not match its recipient derivation")
                amount = int.from_bytes(bytes(a ^ b for a, b in zip(output["encrypted_amount"], core.hash(b"amount" + shared))), "little")
                mask = core.hs(b"commitment_mask" + shared)
                if commitment(core, mask, amount) != output["commitment"]:
                    raise RuntimeError("decrypted output amount does not match its Pedersen commitment")
                matches.append((recipient_index, amount))
        if len(set(matches)) != 1:
            raise RuntimeError(f"output {index} does not belong unambiguously to a fixture recipient")
        scanned.append(next(iter(set(matches))))
    return scanned


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--core-library", type=Path)
    parser.add_argument("--reference", type=Path, default=EXPERIMENT / "evidence/2026-11-04-interoperability/host.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expect-unsupported", action="store_true")
    parser.add_argument("--fixtures-only", action="store_true")
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()): parser.error("output directory must be empty")
    if args.expect_unsupported:
        # Required fee and the wallet path are present. Repeated sources and
        # destinations are empty, which is valid protobuf syntax and keeps the
        # disabled-dispatch probe within one HID packet.
        payload = b"".join(wire.fv(1, n) for n in [0x8000002c, 0x80000080, 0x80000000]) + wire.fv(3, 0)
        session = wire.Session(args.library.resolve(), out, "ordinary-signing")
        try:
            msg, events, _ = session.rpc(65000, payload, context="ordinary-signing-disabled")
            code = wire.only(wire.fields(msg[1]), 1) if msg[0] == 3 else None
            if msg[0] != 3 or code != 1 or events != [3]:
                raise RuntimeError("ordinary emulator must refuse research signing")
            if session.rpc(55)[0][0] != 17:
                raise RuntimeError("ordinary status transport did not recover")
        finally: session.close()
        report = {"status": "pass", "ordinary_build_signing_rejected": True, "rejected_ids": [65000],
                  "library_sha256": wire.sha(args.library.read_bytes()), "physical_device_accessed": False}
        (out / "result.json").write_text(json.dumps(report, indent=2)+"\n")
        print(json.dumps(report)); return
    if not args.core_library: parser.error("--core-library is required")
    abi = abi_check(out)
    spec = importlib.util.spec_from_file_location("signing_reference", EXPERIMENT / "reference.py")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    core = module.Core(args.core_library.resolve()); module.known_anchors(core)
    ref = json.loads(args.reference.read_text()); ref = ref.get("reference", ref)
    if ref.get("fixture_mnemonics_public") != wire.PUBLIC_FIXTURES:
        parser.error("only the fixed public fixture wallets are permitted")
    plan, input_cases, recipients = fixture(core, ref)
    (out / "fixture-plan.bin").write_bytes(bytes(plan))
    (out / "fixture-request.bin").write_bytes(encode_plan(plan))
    (out / "fixture-node-key-public.bin").write_bytes(bytes.fromhex(input_cases[0]["key_seed"]))
    if args.fixtures_only:
        print(json.dumps({"status": "pass", "abi": abi, "fixture_request_bytes": len(encode_plan(plan)), "output": str(out)}, indent=2)); return
    checks = wire.Checks()
    session = wire.Session(args.library.resolve(), out, "signing")
    sessions = [session]
    transactions = []

    def verify(plan, blob):
        lib = session.lib
        lib.monero_core_verify.argtypes = [ctypes.POINTER(Plan), ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        lib.monero_core_verify.restype = ctypes.c_int
        error = ctypes.create_string_buffer(192)
        ok = lib.monero_core_verify(ctypes.byref(plan), blob, len(blob), error)
        return ok == 1, error.value.decode(errors="replace")

    def state_zero(parked=False):
        lib = session.lib
        lib.monero_signing_state_is_zero.argtypes = []
        lib.monero_signing_state_is_zero.restype = ctypes.c_bool
        if parked:
            return lib.monero_signing_state_is_zero()
        end = time.monotonic() + 2
        while not lib.kkemu_trylock():
            if time.monotonic() > end:
                raise RuntimeError("signing observer could not acquire firmware lock")
            time.sleep(.001)
        try:
            return lib.monero_signing_state_is_zero()
        finally:
            lib.kkemu_unlock()

    def sign(plan, label, hold_first=False, pin=None, passphrase=None):
        payload = encode_plan(plan)
        session.capture("stale")
        session.send(65000, payload)
        screens, events = [], []
        for _ in range(96):
            msg = session.receive(60)
            if not msg: raise RuntimeError(f"signing {label} response timed out (deadline 60s)")
            events.append(msg[0])
            if msg[0] == 26:
                meta = session.observe_screen(label + f"-review{len(screens)}")
                screens.append(meta)
                session.log.append({"direction": "screen", **meta})
                if hold_first and len(screens) == 1:
                    checks.record(label + "-no-signed-tx-before-ack", session.receive(.05) is None)
                    checks.record(label + "-derived-node-cleared-before-review", session.derived_node_zero(parked=True))
                    session.send(27)
                    checks.record(label + "-ack-alone-cannot-sign", session.receive(.05) is None)
                    session.send(100, wire.fv(1, 1), iface=1)
                else:
                    session.send(27)
                    session.send(100, wire.fv(1, 1), iface=1)
            elif msg[0] == 18 and pin is not None:
                matrix = wire.only(session.debug_state(), 3).decode()
                if sorted(matrix) != list("123456789"):
                    raise RuntimeError("PIN matrix is invalid")
                session.send(19, wire.fb(1, "".join(str(matrix.index(digit) + 1) for digit in pin)))
            elif msg[0] == 41 and passphrase is not None:
                session.send(42, wire.fb(1, passphrase))
            else:
                return msg, screens, events
        raise RuntimeError("too many signing confirmation rounds")

    def check_signed(plan, source_cases, recipients, label, hold=False, **authentication):
        msg, screens, events = sign(plan, label, hold, **authentication)
        if msg[0] != 65001:
            raise RuntimeError(f"signing {label} failed: {msg[0]}, {wire.fields(msg[1])}")
        data = wire.fields(msg[1]); blob, tx_hash = wire.only(data, 1), wire.only(data, 2)
        checks.record(label + "-bounded-signed-response", len(blob) <= 16384 and len(tx_hash) == 32 and msg[2] >= 2)
        parsed = parse_transaction(blob)
        checks.record(label + "-prefix-input-count", len(parsed["inputs"]) == plan.input_count)
        checks.record(label + "-prefix-output-count", len(parsed["outputs"]) == plan.output_count)
        checks.record(label + "-fee", parsed["fee"] == plan.fee)
        checks.record(label + "-bulletproof-plus-clsag", parsed["rct_type"] == 6 and bool(parsed["bulletproof_plus_rounds"]))
        expected_hash = core.hash(core.hash(blob[:parsed["prefix_end"]]) + core.hash(blob[parsed["prefix_end"]:parsed["base_end"]]) + core.hash(blob[parsed["base_end"]:]))
        checks.record(label + "-independent-three-part-tx-hash", tx_hash == expected_hash)
        by_image = {case["key_image"]: i for i, case in enumerate(source_cases)}
        checks.record(label + "-all-input-key-images", set(x["key_image"] for x in parsed["inputs"]) == set(by_image))
        for i, source in enumerate(parsed["inputs"]):
            original = plan.sources[by_image[source["key_image"]]]
            checks.record(label + f"-input{i}-ring-indices", source["indices"] == [m.global_index for m in original.ring])
        scanned = scan_outputs(core, parsed, recipients)
        checks.record(label + "-independent-recipient-change-amounts", sorted(scanned) == sorted((i, plan.destinations[i].amount) for i in range(plan.output_count)))
        ok, error = verify(plan, blob)
        checks.record(label + "-official-core-verification", ok, error=error)
        corrupt = bytearray(blob); corrupt[-1] ^= 1
        checks.record(label + "-tampered-signature-rejected", not verify(plan, bytes(corrupt))[0])
        corrupt = bytearray(blob); corrupt[parsed["base_end"] + 20] ^= 1
        checks.record(label + "-tampered-range-proof-rejected", not verify(plan, bytes(corrupt))[0])
        checks.record(label + "-truncated-transaction-rejected", not verify(plan, blob[:-1])[0])
        bodies = "\n".join(s["body"] for s in screens)
        for i in range(plan.output_count):
            dest = plan.destinations[i]
            checks.record(label + f"-output{i}-full-address-reviewed", bytes(dest.address).decode() in bodies)
            details = [s["body"] for s in screens if f"Output {i+1}/{plan.output_count}:" in s["body"]]
            checks.record(label + f"-output{i}-exact-amount-reviewed", len(details) == 1 and displayed_atomic(details[0], "Amount") == dest.amount)
            checks.record(label + f"-output{i}-role-reviewed", ("Change" if dest.is_change else "Recipient") in details[0])
        first_output = next(i for i, s in enumerate(screens) if "Output 1/" in s["body"])
        checks.record(label + "-exact-fee-reviewed-before-outputs", any(displayed_atomic(s["body"], "Fee") == plan.fee for s in screens[:first_output]))
        checks.record(label + "-exact-fee-reviewed-before-signing", displayed_atomic(screens[-1]["body"], "Fee") == plan.fee)
        checks.record(label + "-derived-node-zero-after-signing", session.derived_node_zero())
        checks.record(label + "-signing-state-zero-after-response", state_zero())
        if authentication.get("pin") is not None:
            checks.record(label + "-pin-challenged", 18 in events)
        if authentication.get("passphrase") is not None:
            checks.record(label + "-passphrase-challenged", 41 in events)
        (out / f"{label}.tx.bin").write_bytes(blob)
        (out / f"{label}.tx.hex").write_text(blob.hex()+"\n")
        transactions.append({"name": label, "bytes": len(blob), "tx_hash": tx_hash.hex(),
                             "inputs": plan.input_count, "outputs": plan.output_count, "fee": plan.fee,
                             "rct_type": parsed["rct_type"], "bulletproof_plus_rounds": parsed["bulletproof_plus_rounds"],
                             "independent_scanned_outputs": scanned, "review_stages": [s["title"] for s in screens]})
        return screens

    try:
        msg, _, _ = session.rpc(65000, encode_plan(plan), context="missing-wallet")
        wire.failure(checks, "missing-wallet-cannot-sign", msg, [11])
        wire.load_wallet(session, checks, "abandon")
        screens = check_signed(plan, input_cases, recipients, "base-input", hold=True)
        for count, sub, label in [(1, True, "subaddress-input"), (2, False, "two-inputs"), (3, False, "three-inputs"), (4, False, "four-inputs")]:
            p, cases, dests = fixture(core, ref, count=count, subaddress=sub)
            check_signed(p, cases, dests, label)
        p, cases, dests = fixture(core, ref)
        p.sources[0].additional_key_count = 1
        set_bytes(p.sources[0].additional_tx_public_keys[0], bytes(p.sources[0].tx_public_key))
        set_bytes(p.sources[0].tx_public_key, core.op("base", core.hs(b"Public additional-key fixture primary")))
        check_signed(p, cases, dests, "additional-key-input")
        recipient_sub = next(c for c in ref["cases"] if c["label"] == "trezor-account0-sub0-1-output0")
        p, cases, dests = fixture(core, ref)
        p.destinations[0].address = wire.expected_address(recipient_sub, 0, core).encode()
        check_signed(p, cases, [recipient_sub, dests[1]], "subaddress-recipient")
        change_sub = next(c for c in ref["cases"] if c["label"] == "abandon-account0-sub0-1-output0")
        p, cases, dests = fixture(core, ref)
        p.destinations[1].address = wire.expected_address(change_sub, 0, core).encode()
        p.destinations[1].change_minor = 1
        check_signed(p, cases, [dests[0], change_sub], "subaddress-change")
        for network in [1, 2]:
            p, cases, dests = fixture(core, ref, network=network)
            check_signed(p, cases, dests, "testnet" if network == 1 else "stagenet")
        for output_count in [3, 4]:
            p, cases, dests = fixture(core, ref)
            change = Destination.from_buffer_copy(bytes(p.destinations[1]))
            p.output_count = output_count
            extra_recipients = [recipient_sub, next(c for c in ref["cases"] if c["label"] == "trezor-account0-sub1-0-output0")][:output_count-2]
            for i, recipient in enumerate(extra_recipients, 1):
                p.destinations[i] = Destination()
                p.destinations[i].amount = 1000000000000
                p.destinations[i].address = wire.expected_address(recipient, 0, core).encode()
                change.amount -= p.destinations[i].amount
            p.destinations[output_count-1] = change
            check_signed(p, cases, [dests[0]] + extra_recipients + [dests[1]], f"{output_count}-outputs")

        invalid = []
        p = copy_plan(plan); set_bytes(p.sources[0].ring[7].public_key, bytes(p.sources[0].ring[0].public_key)); invalid.append(("unowned-real-output", p, {}))
        p = copy_plan(plan); set_bytes(p.sources[0].ring[7].commitment, bytes(p.sources[0].ring[0].commitment)); invalid.append(("bad-real-commitment", p, {}))
        p = copy_plan(plan); p.destinations[0].amount += 1; invalid.append(("unbalanced-amounts", p, {}))
        p = copy_plan(plan); p.fee += 1; invalid.append(("wrong-fee", p, {}))
        p = copy_plan(plan); p.sources[0].ring[1].global_index = p.sources[0].ring[0].global_index; invalid.append(("duplicate-ring-index", p, {}))
        p = copy_plan(plan); set_bytes(p.sources[0].ring[0].public_key, bytes([255])*32); invalid.append(("invalid-decoy-point", p, {}))
        p = copy_plan(plan); set_bytes(p.sources[0].ring[0].commitment, bytes([255])*32); invalid.append(("invalid-decoy-commitment", p, {}))
        p = copy_plan(plan); set_bytes(p.sources[0].mask, bytes([255])*32); invalid.append(("noncanonical-mask", p, {}))
        p = copy_plan(plan); p.sources[0].additional_key_count = 1; set_bytes(p.sources[0].additional_tx_public_keys[0], bytes([255])*32); invalid.append(("invalid-additional-tx-key", p, {}))
        p = copy_plan(plan); p.destinations[1].address = plan.destinations[0].address; invalid.append(("false-change-address", p, {}))
        p = copy_plan(plan); p.destinations[1].change_minor = 1; invalid.append(("false-change-subaddress", p, {}))
        p = copy_plan(plan); p.sources[0].subaddress_minor = 1; invalid.append(("false-source-subaddress", p, {}))
        p, _, _ = fixture(core, ref, count=2); p.sources[0].subaddress_minor = 1; invalid.append(("false-source-subaddress-with-other-owned-input", p, {}))
        p = copy_plan(plan); p.destinations[0].address = wire.expected_address(recipients[0], 1, core).encode(); invalid.append(("wrong-address-network", p, {}))
        p = copy_plan(plan); p.network = 3; invalid.append(("invalid-network", p, {}))
        p, _, _ = fixture(core, ref, count=2)
        p.sources[0].amount = 0xffffffffffffffff
        set_bytes(p.sources[0].ring[7].commitment, commitment(core, bytes(p.sources[0].mask), p.sources[0].amount))
        invalid.append(("overflowing-input-total", p, {}))
        p = copy_plan(plan); p.destinations[0].amount = 0xffffffffffffffff; p.destinations[1].amount = 1; invalid.append(("overflowing-output-total", p, {}))
        p = copy_plan(plan); p.fee = 0xffffffffffffffff; invalid.append(("overflowing-fee-balance", p, {}))
        invalid += [("nonzero-unlock-time", plan, {"unlock": 1}),
                    ("wrong-wallet-path", plan, {"path": [0x8000002c, 0x80000081, 0x80000000]})]
        for label, p, options in invalid:
            msg, events, _ = session.rpc(65000, encode_plan(p, **options), context=label)
            wire.failure(checks, label, msg, [1, 3, 9])
            checks.record(label + "-no-user-prompt", 26 not in events and 65001 not in events)
            checks.record(label + "-no-late-signed-tx", session.receive(.025) is None)
            checks.record(label + "-signing-state-wiped", state_zero())
        msg, _, _ = session.rpc(65000, b"\x22\x80", context="malformed-signing-protobuf")
        wire.failure(checks, "malformed-signing-protobuf", msg, [1, 3])

        source_body = source_wire(plan.sources[0])
        request = encode_plan(plan)
        def replace_source(body):
            return request.replace(wire.fb(4, source_body), wire.fb(4, body), 1)
        last = plan.sources[0].ring[-1]
        last_member = wire.fb(8, wire.fv(1, last.global_index) + wire.fb(2, bytes(last.public_key)) + wire.fb(3, bytes(last.commitment)))
        first_destination = wire.fields(request)[5][0]
        four, _, _ = fixture(core, ref, count=4)
        malformed = [
            ("fifteen-ring-members", replace_source(source_body[:-len(last_member)])),
            ("seventeen-ring-members", replace_source(source_body + last_member)),
            ("short-source-tx-key", replace_source(source_body.replace(wire.fb(6, bytes(plan.sources[0].tx_public_key)), wire.fb(6, bytes(31)), 1))),
            ("short-source-mask", replace_source(source_body.replace(wire.fb(7, bytes(plan.sources[0].mask)), wire.fb(7, bytes(31)), 1))),
            ("short-additional-tx-key", replace_source(source_body + wire.fb(9, bytes(31)))),
            ("seventeen-additional-tx-keys", replace_source(source_body + wire.fb(9, bytes(plan.sources[0].tx_public_key)) * 17)),
            ("five-inputs", encode_plan(four) + wire.fb(4, source_body)),
            ("five-outputs", request + wire.fb(5, first_destination) * 3),
            ("recipient-with-change-indices", request.replace(wire.fb(5, first_destination), wire.fb(5, first_destination + wire.fv(4, 0)), 1)),
            ("overlong-output-address", request.replace(wire.fb(5, first_destination), wire.fb(5, wire.fv(1, plan.destinations[0].amount) + wire.fb(2, b"1" * 96)), 1)),
            ("overlong-wallet-path", encode_plan(plan, path=[0x8000002c, 0x80000080, 0x80000000, 0x80000000])),
            ("overflowing-output-index", replace_source(source_body.replace(wire.fv(3, 0), wire.fv(3, 2**32), 1))),
        ]
        for label, payload in malformed:
            msg, events, _ = session.rpc(65000, payload, context=label)
            wire.failure(checks, label, msg, [1, 3, 9])
            checks.record(label + "-no-user-prompt", 26 not in events and 65001 not in events)
            checks.record(label + "-signing-state-wiped", state_zero())

        # Fee overview, destination review and final authorization are distinct.
        destination_title = next(s["title"] for s in screens if "Output 1/" in s["body"])
        fee_title = next(s["title"] for s in screens if displayed_atomic(s["body"], "Fee") == plan.fee)
        for label, target in [("fee", fee_title), ("destination", destination_title), ("final", screens[-1]["title"])]:
            session.send(65000, encode_plan(plan))
            cancelled = False
            for _ in range(64):
                msg = session.receive(60)
                if not msg or msg[0] != 26:
                    raise RuntimeError(f"cancel target {target} was not reached")
                meta = session.observe_screen("cancel-"+label)
                if meta["title"] == target:
                    session.send(20); cancelled = True; break
                session.send(27); session.send(100, wire.fv(1, 1), iface=1)
            checks.record(label + "-cancel-stage-reached", cancelled)
            wire.failure(checks, label + "-cancel-no-signature", session.receive(), [4])
            checks.record(label + "-cancel-no-late-transaction", session.receive(.03) is None)
            checks.record(label + "-cancel-node-zero", session.derived_node_zero())
            checks.record(label + "-cancel-signing-state-wiped", state_zero())
        for label, kind in [("initialize", 0), ("unexpected-ping", 1)]:
            # A valid plan reaches the same Core validation as sign(), which
            # already permits 60s on slower CI hosts. Fast invalid controls
            # above retain the generic five-second transport deadline.
            first, _, _ = session.rpc(65000, encode_plan(plan), approve=None,
                                      timeout=60, context=label + "-review-open")
            checks.record(label + "-review-open", first[0] == 26)
            session.send(kind)
            msg = session.receive()
            checks.record(label + "-does-not-return-signed-tx", msg and msg[0] in [3, 17])
            checks.record(label + "-single-terminal-response", session.receive(.03) is None)
            checks.record(label + "-signing-state-wiped", state_zero())
        msg, _, _ = session.rpc(55)
        checks.record("transport-usable-after-signing-rejections", msg[0] == 17)

        session.close()
        session = wire.Session(args.library.resolve(), out, "signing-pin")
        sessions.append(session)
        wire.load_wallet(session, checks, "abandon", pin="1234")
        session.rpc(24)
        first, _, _ = session.rpc(65000, encode_plan(plan), timeout=60,
                                  context="locked-wallet-pin-challenge")
        checks.record("signing-locked-wallet-demands-pin", first[0] == 18)
        session.send(20)
        wire.failure(checks, "signing-pin-cancel-no-transaction", session.receive(), [6])
        checks.record("signing-pin-cancel-state-wiped", state_zero())
        msg, events, _ = session.rpc(65000, encode_plan(plan), pin="9999", timeout=60,
                                     context="wrong-pin-refused")
        wire.failure(checks, "signing-wrong-pin-refused", msg, [7])
        checks.record("signing-wrong-pin-was-challenged", 18 in events)
        checks.record("signing-wrong-pin-state-wiped", state_zero())
        check_signed(plan, input_cases, recipients, "pin-authorized", pin="1234")

        session.close()
        session = wire.Session(args.library.resolve(), out, "signing-passphrase")
        sessions.append(session)
        wire.load_wallet(session, checks, "abandon", passphrase=True)
        first, _, _ = session.rpc(65000, encode_plan(plan), timeout=60,
                                  context="wallet-passphrase-challenge")
        checks.record("signing-wallet-demands-passphrase", first[0] == 41)
        session.send(20)
        wire.failure(checks, "signing-passphrase-cancel-no-transaction", session.receive(), [11])
        checks.record("signing-passphrase-cancel-state-wiped", state_zero())
        check_signed(plan, input_cases, recipients, "empty-passphrase-authorized", passphrase="")
        session.rpc(24)
        public_passphrase = "Monero signing public fixture"
        hidden_case = passphrase_case(core, public_passphrase)
        hidden_ref = {**ref, "cases": [hidden_case if c["label"] == hidden_case["label"] else c for c in ref["cases"]]}
        p, cases, dests = fixture(core, hidden_ref)
        checks.record("nonempty-passphrase-fixture-is-distinct-wallet", hidden_case["sub_spend_public"] != input_cases[0]["sub_spend_public"])
        check_signed(p, cases, dests, "nonempty-passphrase-authorized", passphrase=public_passphrase)
    finally:
        session.close()
    report = {"schema_version": 1, "status": "pass", "checks": checks.items,
              "check_count": len(checks.items), "transactions": transactions,
              "abi": abi, "library_sha256": wire.sha(args.library.read_bytes()),
              "reference_core_commit": ref["core_commit"], "core_library_sha256": wire.sha(args.core_library.read_bytes()),
              "source_sha256": wire.sha(Path(__file__).read_bytes()),
              "funding": "synthetic public owned outputs and decoy rings; not mined, relayed, or broadcast",
              "verification": "official Core RingCT/Bulletproof+ verification plus independent prefix/RCT parsing, three-part tx hashing, recipient scanning, ECDH amount and commitment checks",
              "physical_device_accessed": False, "production_ready": False,
              "frames": [frame for item in sessions for frame in item.frames]}
    (out / "result.json").write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps({"status": "pass", "checks": len(checks.items),
                      "transactions": transactions, "output": str(out)}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
