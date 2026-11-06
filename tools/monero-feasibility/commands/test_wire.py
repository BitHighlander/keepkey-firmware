#!/usr/bin/env python3
"""Exercise research Monero commands over the real emulator's HID packet rings.

Only fixed public test mnemonics are installed, in a fresh anonymous flash
buffer. This runner has no USB transport or emulator.img input.
"""
import argparse
import ctypes
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import sys
import time
import unicodedata

HERE = Path(__file__).resolve().parent
EXPERIMENT = HERE.parent
PUBLIC_FIXTURES = {
    "abandon": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "trezor": "alcohol woman abuse must during monitor noble actual mixed trade anger aisle",
}
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
WIDTH = [0, 2, 3, 5, 6, 7, 9, 10, 11]
TAGS = {0: (18, 42), 1: (53, 63), 2: (24, 36)}
RETAINED_SESSIONS = []  # Preserve flash/library ownership if bounded shutdown fails.
MAX_UNIQUE_CAPTURED_FRAMES = 1024  # Bound disk use; exceeding it fails evidence collection.


def sha(data):
    return hashlib.sha256(data).hexdigest()


def vint(value):
    if not 0 <= value <= 0xffffffffffffffff:
        raise ValueError("protobuf integer outside uint64 range")
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def fv(field, value):
    return vint(field << 3) + vint(value)


def fb(field, value):
    value = value.encode() if isinstance(value, str) else value
    return vint((field << 3) | 2) + vint(len(value)) + value


def read_vint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        if offset == len(data):
            raise RuntimeError("truncated protobuf varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if byte < 128:
            if value > 0xffffffffffffffff:
                raise RuntimeError("overflowing protobuf varint")
            return value, offset
    raise RuntimeError("oversized protobuf varint")


def fields(data):
    result = {}
    offset = 0
    while offset < len(data):
        key, offset = read_vint(data, offset)
        field, wire = key >> 3, key & 7
        if not field:
            raise RuntimeError("zero protobuf field number")
        if wire == 0:
            value, offset = read_vint(data, offset)
        elif wire == 2:
            length, offset = read_vint(data, offset)
            value = data[offset:offset + length]
            offset += length
        elif wire in (1, 5):
            length = 8 if wire == 1 else 4
            value = data[offset:offset + length]
            offset += length
        else:
            raise RuntimeError(f"unsupported wire type {wire}")
        if offset > len(data):
            raise RuntimeError("truncated protobuf field")
        result.setdefault(field, []).append(value)
    return result


def only(mapping, key, default=None):
    values = mapping.get(key, [default])
    if len(values) != 1:
        raise RuntimeError(f"expected one protobuf field {key}")
    return values[0]


def request(account=0, major=0, minor=0, network=0, display=False, path=None, payment=None):
    path = [0x8000002c, 0x80000080, 0x80000000 | account] if path is None else path
    payload = b"".join(fv(1, component) for component in path)
    payload += fv(2, int(display)) + fv(3, network) + fv(4, major) + fv(5, minor)
    if payment is not None:
        payload += fb(6, payment)
    return payload


class Session:
    def __init__(self, library, output, label):
        self.library = library
        self.out = output
        self.label = label
        self.log = []
        self.frames = []
        self.frame_hashes = set()
        self.closed = False
        self.partial = {0: None, 1: None}
        self.ready = {0: [], 1: []}
        self.flash = (ctypes.c_uint8 * (1024 * 1024))()
        ctypes.memset(self.flash, 0xff, len(self.flash))
        self.lib = ctypes.CDLL(str(library))
        lib = self.lib
        lib.kkemu_init.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        lib.kkemu_init.restype = ctypes.c_int
        for name in ["kkemu_start", "kkemu_is_running", "kkemu_trylock"]:
            getattr(lib, name).restype = ctypes.c_int
        lib.kkemu_write.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        lib.kkemu_read.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        lib.kkemu_write.restype = lib.kkemu_read.restype = ctypes.c_int
        lib.kkemu_pop_frame.argtypes = [ctypes.c_void_p]
        lib.kkemu_pop_frame.restype = ctypes.c_int
        lib.kkemu_shutdown_timeout.argtypes = [ctypes.c_uint32]
        lib.kkemu_shutdown_timeout.restype = ctypes.c_int
        if hasattr(lib, "fsm_test_derivedNodeIsZero"):
            lib.fsm_test_derivedNodeIsZero.argtypes = []
            lib.fsm_test_derivedNodeIsZero.restype = ctypes.c_bool
        if lib.kkemu_init(self.flash, len(self.flash)):
            self.closed = True
            raise RuntimeError("could not initialize/start the real firmware emulator")
        if lib.kkemu_start():
            if lib.kkemu_shutdown_timeout(5000):
                RETAINED_SESSIONS.append(self)
                raise RuntimeError("start failed and shutdown timed out; resources retained")
            self.closed = True
            raise RuntimeError("could not start the firmware emulator poll thread")

    def close(self):
        if self.closed:
            return
        if self.lib.kkemu_shutdown_timeout(5000):
            if self not in RETAINED_SESSIONS:
                RETAINED_SESSIONS.append(self)
            raise RuntimeError("bounded emulator shutdown failed; retain flash/library")
        self.closed = True
        (self.out / f"{self.label}-wire.json").write_text(json.dumps(self.log, indent=2) + "\n")

    def flash_hash(self):
        end = time.monotonic() + 2
        while not self.lib.kkemu_trylock():
            if time.monotonic() > end:
                raise RuntimeError("firmware flash lock unavailable")
            time.sleep(.001)
        try:
            return sha(bytes(self.flash))
        finally:
            self.lib.kkemu_unlock()

    def send(self, kind, payload=b"", iface=0):
        data = b"##" + kind.to_bytes(2, "big") + len(payload).to_bytes(4, "big") + payload
        packets = [b"?" + data[i:i + 63].ljust(63, b"\0") for i in range(0, len(data), 63)]
        for packet in packets:
            storage = ctypes.create_string_buffer(packet, 64)
            if self.lib.kkemu_write(storage, 64, iface):
                raise RuntimeError("emulator input ring full")
        self.log.append({"direction": "send", "iface": iface, "type": kind,
                         "bytes": len(payload), "reports": len(packets), "payload_sha256": sha(payload)})

    def drain(self, iface):
        packet = ctypes.create_string_buffer(64)
        while self.lib.kkemu_read(packet, 64, iface) == 64:
            raw = packet.raw
            partial = self.partial[iface]
            if partial is None:
                if raw[:3] != b"?##":
                    raise RuntimeError("response header does not contain HID framing")
                kind, length = int.from_bytes(raw[3:5], "big"), int.from_bytes(raw[5:9], "big")
                if length > 65536:
                    raise RuntimeError("response exceeds test bounds")
                partial = [kind, length, bytearray(raw[9:]), 1]
                self.partial[iface] = partial
            else:
                if raw[0] != 63:
                    raise RuntimeError("response continuation missing report marker")
                partial[2].extend(raw[1:])
                partial[3] += 1
            if len(partial[2]) >= partial[1]:
                kind, length, body, count = partial
                body = bytes(body[:length])
                self.ready[iface].append((kind, body, count))
                self.log.append({"direction": "receive", "iface": iface, "type": kind,
                                 "bytes": length, "reports": count, "payload_sha256": sha(body)})
                self.partial[iface] = None

    def receive(self, timeout=5, iface=0):
        end = time.monotonic() + timeout
        while True:
            self.drain(iface)
            if self.ready[iface]:
                return self.ready[iface].pop(0)
            if time.monotonic() >= end:
                return None
            time.sleep(.001)

    def capture(self, name, wait=False):
        end = time.monotonic() + (.3 if wait else 0)
        found = []
        while True:
            frame = ctypes.create_string_buffer(2048)
            for _ in range(128):
                if self.lib.kkemu_pop_frame(frame) != 1:
                    break
                pixels = frame.raw
                h = sha(pixels)
                if h in self.frame_hashes:
                    continue
                if len(self.frames) >= MAX_UNIQUE_CAPTURED_FRAMES:
                    raise RuntimeError("OLED evidence frame limit exceeded; capture cannot be reported as complete")
                stem = f"{self.label}-{len(self.frames):03d}-{name}"
                raw_path, pgm_path = f"{stem}.bin", f"{stem}.pgm"
                (self.out / raw_path).write_bytes(pixels)
                pgm = bytes(255 if pixels[x + (y // 8) * 256] & (1 << (y % 8)) else 0
                            for y in range(64) for x in range(256))
                (self.out / pgm_path).write_bytes(b"P5\n256 64\n255\n" + pgm)
                self.frames.append({"name": name, "sha256": h, "path": pgm_path, "raw_path": raw_path})
                self.frame_hashes.add(h)
                found.append(h)
            if found or time.monotonic() >= end:
                return found
            time.sleep(.002)

    def debug_state(self):
        self.send(101, iface=1)
        msg = self.receive(iface=1)
        if not msg or msg[0] != 102:
            raise RuntimeError("DebugLinkGetState did not return its state")
        return fields(msg[1])

    def derived_node_zero(self, parked=False):
        if not hasattr(self.lib, "fsm_test_derivedNodeIsZero"):
            raise RuntimeError("DEBUG_LINK derived-node boundary observer is unavailable")
        if parked:
            # confirm_helper owns the lock, but the handler has scrubbed the
            # node and cannot derive another while this approval is pending.
            return self.lib.fsm_test_derivedNodeIsZero()
        end = time.monotonic() + 2
        while not self.lib.kkemu_trylock():
            if time.monotonic() > end:
                raise RuntimeError("derived-node observer could not acquire firmware lock")
            time.sleep(.001)
        try:
            return self.lib.fsm_test_derivedNodeIsZero()
        finally:
            self.lib.kkemu_unlock()

    def observe_screen(self, label):
        end = time.monotonic() + 2
        while True:
            state = self.debug_state()
            layout = only(state, 1, b"")
            self.capture(label, wait=True)
            if len(layout) == 2048 and any(layout) and sha(layout) in self.frame_hashes:
                return {"label": label, "title": only(state, 16, b"").decode(),
                        "body": only(state, 17, b"").decode(), "frame_sha256": sha(layout)}
            if time.monotonic() > end:
                raise RuntimeError("current DebugLink screen was not observed in the real frame ring")

    def approve_button(self, label, yes=True):
        # Persist only public screen metadata, not DebugLink's seed/node fields.
        meta = self.observe_screen(label)
        self.log.append({"direction": "screen", **meta})
        self.send(27)
        self.send(100, fv(1, int(yes)), iface=1)
        return meta

    def rpc(self, kind, payload=b"", approve=True, pin=None, passphrase=None,
            timeout=5, context=None):
        self.capture("stale")
        self.send(kind, payload)
        events = []
        screens = []
        for _ in range(64):
            msg = self.receive(timeout)
            if msg is None:
                detail = f"; scenario {context}" if context else ""
                raise RuntimeError(f"timeout awaiting response to message {kind} "
                                   f"(deadline {timeout:g}s{detail})")
            msg_type, body, count = msg
            events.append(msg_type)
            if msg_type == 26:
                if approve is None:
                    return msg, events, screens
                screens.append(self.approve_button(f"message{kind}-confirm{len(screens)}", approve))
            elif msg_type == 18 and pin is not None:
                matrix = only(self.debug_state(), 3).decode()
                if sorted(matrix) != list("123456789"):
                    raise RuntimeError("PIN matrix is invalid")
                encoded = "".join(str(matrix.index(digit) + 1) for digit in pin)
                self.send(19, fb(1, encoded))
            elif msg_type == 41 and passphrase is not None:
                self.send(42, fb(1, passphrase))
            else:
                return msg, events, screens
        raise RuntimeError("too many firmware interaction rounds")


class Checks:
    def __init__(self):
        self.items = []

    def record(self, label, condition, **detail):
        if not condition:
            raise RuntimeError(f"check failed: {label}; {detail}")
        self.items.append({"name": label, "status": "pass", **detail})


def failure(checks, label, msg, codes):
    parsed = fields(msg[1]) if msg and msg[0] == 3 else {}
    code = only(parsed, 1)
    checks.record(label, msg is not None and msg[0] == 3 and code in codes,
                  failure_code=code, message=only(parsed, 2, b"").decode(errors="replace"))


def expected_address(case, network, core):
    tag = TAGS[network][int((case["major"], case["minor"]) != (0, 0))]
    raw = bytes([tag]) + bytes.fromhex(case["sub_spend_public"] + case["sub_view_public"])
    raw += core.hash(raw)[:4]
    result = ""
    for offset in range(0, len(raw), 8):
        block = raw[offset:offset + 8]
        value = int.from_bytes(block, "big")
        encoded = ""
        while value:
            value, digit = divmod(value, 58)
            encoded = ALPHABET[digit] + encoded
        result += encoded.rjust(WIDTH[len(block)], "1")
    return result


def independent_passphrase_address(core, fixture, passphrase):
    phrase = unicodedata.normalize("NFKD", PUBLIC_FIXTURES[fixture]).encode()
    salt = ("mnemonic" + unicodedata.normalize("NFKD", passphrase)).encode()
    seed = hashlib.pbkdf2_hmac("sha512", phrase, salt, 2048)
    digest = hmac.new(b"ed25519 seed", seed, "sha512").digest()
    key, chain = digest[:32], digest[32:]
    for index in [44, 128, 0]:
        digest = hmac.new(chain, b"\0" + key + (index | 0x80000000).to_bytes(4, "big"), "sha512").digest()
        key, chain = digest[:32], digest[32:]
    spend = core.op("reduce", key)
    view = core.hs(spend)
    case = {"major": 0, "minor": 0, "sub_spend_public": core.op("base", spend).hex(),
            "sub_view_public": core.op("base", view).hex()}
    return expected_address(case, 0, core)


def load_wallet(session, checks, fixture, pin="", passphrase=False):
    payload = (fb(1, PUBLIC_FIXTURES[fixture]) + fb(3, pin) + fv(4, int(passphrase))
               + fb(5, "english") + fb(6, "Monero public fixture"))
    msg, events, _ = session.rpc(13, payload)
    checks.record(f"{session.label}-normal-load-device", msg[0] == 2 and 26 in events)
    msg, _, _ = session.rpc(55)
    info = fields(msg[1])
    checks.record(f"{session.label}-seed-installed-in-anonymous-emulator",
                  msg[0] == 17 and only(info, 12) == 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--reference", type=Path)
    parser.add_argument("--core-library", type=Path)
    parser.add_argument("--expect-unsupported", action="store_true",
                        help="Negative control: ordinary emulator must reject research message 540")
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        parser.error("output directory must be empty")
    if args.expect_unsupported:
        control = Session(args.library.resolve(), out, "ordinary-build")
        try:
            before, _, _ = control.rpc(55)
            msg, events, _ = control.rpc(540, request())
            code = only(fields(msg[1]), 1) if msg and msg[0] == 3 else None
            if not (before[0] == 17 and msg and msg[0] == 3 and code == 1 and events == [3]):
                raise RuntimeError("ordinary emulator unexpectedly accepts Monero research command")
            after, _, _ = control.rpc(55)
            if after[0] != 17:
                raise RuntimeError("ordinary emulator transport did not recover after refusal")
        finally:
            control.close()
        report = {"status": "pass", "ordinary_build_monero_command_rejected": True,
                  "failure_code": code, "physical_device_accessed": False,
                  "library_sha256": sha(args.library.read_bytes()), "source_sha256": sha(Path(__file__).read_bytes())}
        (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
        return
    ref_path = args.reference or EXPERIMENT / "evidence/2026-11-04-interoperability/host.json"
    ref = json.loads(ref_path.read_text())
    if "reference" in ref:
        ref = ref["reference"]
    if ref.get("fixture_mnemonics_public") != PUBLIC_FIXTURES or ref.get("case_count") != 96:
        parser.error("requires the fixed, independently generated public reference")
    candidates = [args.core_library] if args.core_library else []
    candidates += [ref_path.parent / name for name in ["core-reference.dylib", "core-reference.so"]]
    core_path = next((p for p in candidates if p and p.exists()), None)
    if core_path is None:
        parser.error("provide --core-library from the pinned reference.py build for network checksums")
    spec = importlib.util.spec_from_file_location("monero_independent_reference", EXPERIMENT / "reference.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    core = module.Core(core_path.resolve())
    module.known_anchors(core)
    cases = [case for case in ref["cases"] if case["output_index"] == 0]
    checks = Checks()
    sessions = []

    def new(label):
        s = Session(args.library.resolve(), out, label)
        sessions.append(s)
        return s

    s = new("abandon")
    try:
        msg, _, _ = s.rpc(540, request())
        failure(checks, "missing-seed-refused", msg, [11])
        load_wallet(s, checks, "abandon")
        invalid = [
            ("empty-path", request(path=[])),
            ("wrong-purpose", request(path=[0x8000002d, 0x80000080, 0x80000000])),
            ("wrong-coin", request(path=[0x8000002c, 0x80000081, 0x80000000])),
            ("unhardened-account", request(path=[0x8000002c, 0x80000080, 0])),
            ("too-many-path-components", request(path=[0x8000002c, 0x80000080, 0x80000000, 0x80000000])),
            ("unsupported-network", request(network=3)),
            ("empty-payment-id-present", request(payment=b"")),
            ("integrated-payment-id", request(payment=bytes(8))),
            ("oversized-payment-id", request(payment=bytes(9))),
            ("truncated-protobuf", b"\x08\x80"),
        ]
        for label, payload in invalid:
            msg, events, _ = s.rpc(540, payload)
            codes = [1, 3] if label in ["too-many-path-components", "oversized-payment-id", "truncated-protobuf"] else [3]
            failure(checks, label, msg, codes)
            checks.record(label + "-no-user-prompt", 26 not in events and 18 not in events)
        for fixture in ["abandon", "trezor"]:
            if fixture != "abandon":
                s.close()
                s = new(fixture)
                load_wallet(s, checks, fixture)
            # The existing storage layer persists its encrypted root-seed cache
            # on the first derivation. Establish the read-only matrix baseline
            # after exercising that normal initialization path.
            before_warmup = s.flash_hash()
            warmup, _, _ = s.rpc(540, request())
            warmup_case = next(case for case in cases if case["label"] == fixture + "-account0-sub0-0-output0")
            checks.record(fixture + "-normal-seed-cache-warmup", warmup[0] == 541
                          and only(fields(warmup[1]), 1).decode() == warmup_case["address"],
                          flash_changed_by_existing_storage_cache=s.flash_hash() != before_warmup)
            fixture_flash = s.flash_hash()
            fixture_cases = [case for case in cases if case["label"].startswith(fixture + "-")]
            for case in fixture_cases:
                account = int(case["label"].split("-account")[1].split("-")[0])
                for network in [0, 1, 2]:
                    payload = request(account, case["major"], case["minor"], network)
                    msg, events, _ = s.rpc(540, payload)
                    address = only(fields(msg[1]), 1, b"").decode() if msg[0] == 541 else ""
                    expected = expected_address(case, network, core)
                    label = f"{case['label']}-network{network}"
                    checks.record(label, msg[0] == 541 and address == expected and events == [541],
                                  address=address, reports=msg[2])
                    checks.record(label + "-response-spans-reports", msg[2] >= 2)
            checks.record(fixture + "-address-matrix-flash-unchanged", s.flash_hash() == fixture_flash)
        case = next(case for case in cases if case["label"] == "trezor-account0-sub0-0-output0")
        msg, _, _ = s.rpc(540, request() + fb(99, b"padding for inbound packet fragmentation" * 3))
        checks.record("multi-report-request", msg[0] == 541 and only(fields(msg[1]), 1).decode() == case["address"])
        default_payload = b"".join(fv(1, part) for part in [0x8000002c, 0x80000080, 0x80000000])
        msg, _, _ = s.rpc(540, default_payload)
        checks.record("omitted-optional-fields-use-base-mainnet", msg[0] == 541
                      and only(fields(msg[1]), 1).decode() == case["address"])
        packed_path = fb(1, b"".join(vint(part) for part in [0x8000002c, 0x80000080, 0x80000000]))
        msg, _, _ = s.rpc(540, packed_path)
        checks.record("packed-path-protobuf-compatible", msg[0] == 541
                      and only(fields(msg[1]), 1).decode() == case["address"])
        view = bytes.fromhex(case["view_secret"])
        sub_secret = core.hs(b"SubAddr\0" + view + bytes([255]) * 8)
        sub_spend = core.op("add", bytes.fromhex(case["spend_public"]), core.op("base", sub_secret))
        sub_view = core.op("mul", sub_spend, view)
        max_case = {"major": 0xffffffff, "minor": 0xffffffff,
                    "sub_spend_public": sub_spend.hex(), "sub_view_public": sub_view.hex()}
        msg, _, _ = s.rpc(540, request(major=0xffffffff, minor=0xffffffff))
        checks.record("uint32-max-subaddress-indices", msg[0] == 541
                      and only(fields(msg[1]), 1).decode() == expected_address(max_case, 0, core))

        # Hold each approval stage open until a frame and metadata are observed.
        s.capture("before-display")
        s.send(540, request(display=True))
        first = s.receive()
        checks.record("display-starts-with-button-request", first and first[0] == 26)
        held = s.observe_screen("held-address-first-stage")
        title, body = held["title"], held["body"]
        checks.record("display-frame-before-approval", title == "Derivation" and "Monero Mainnet" in body
                      and "m/44'/128'/0'" in body and "Subaddress 0/0" in body,
                      title=title, body=body, frame_sha256=held["frame_sha256"])
        checks.record("derived-node-zero-before-first-approval", s.derived_node_zero(parked=True))
        checks.record("no-address-before-button-ack", s.receive(.05) is None)
        s.send(27)
        checks.record("button-ack-alone-does-not-release-address", s.receive(.05) is None)
        s.send(100, fv(1, 1), iface=1)
        screens = [{"title": title, "body": body}]
        for _ in range(32):
            msg = s.receive()
            if not msg:
                raise RuntimeError("display approval timed out")
            if msg[0] == 26:
                screens.append(s.approve_button("monero-address-page"))
            else:
                break
        checks.record("display-approved-address-matches-oracle", msg[0] == 541 and only(fields(msg[1]), 1).decode() == case["address"])
        checks.record("derived-node-zero-after-address-response", s.derived_node_zero())
        checks.record("display-reviewed-full-address", any(case["address"] in screen["body"] for screen in screens),
                      stages=[screen["title"] for screen in screens])
        checks.record("display-reviewed-address-and-qr-stages",
                      {"Address", "Address QR"}.issubset({screen["title"] for screen in screens}))

        first, _, _ = s.rpc(540, request(display=True), approve=None)
        checks.record("cancel-setup-button-request", first[0] == 26)
        s.capture("cancel-address", wait=True)
        s.send(20)
        failure(checks, "display-cancel-does-not-return-address", s.receive(), [4])
        checks.record("derived-node-zero-after-display-cancel", s.derived_node_zero())
        checks.record("no-second-terminal-message-after-cancel", s.receive(.03) is None)
        msg, _, _ = s.rpc(55)
        checks.record("transport-recovers-after-display-cancel", msg[0] == 17)

        for cancel_stage in ["Address", "Address QR"]:
            s.capture("before-stage-cancel")
            s.send(540, request(display=True))
            reached = False
            for _ in range(32):
                message = s.receive()
                if not message or message[0] != 26:
                    raise RuntimeError(f"address returned before cancellation at {cancel_stage}")
                observed = s.observe_screen("cancel-at-" + cancel_stage.replace(" ", "-"))
                title = observed["title"]
                if title == cancel_stage:
                    checks.record("node-zero-at-cancel-" + cancel_stage, s.derived_node_zero(parked=True))
                    s.send(20)
                    failure(checks, "cancel-at-" + cancel_stage, s.receive(), [4])
                    checks.record("no-late-address-after-cancel-" + cancel_stage, s.receive(.03) is None)
                    reached = True
                    break
                s.send(27)
                s.send(100, fv(1, 1), iface=1)
            checks.record("reached-cancel-stage-" + cancel_stage, reached)

        first, _, _ = s.rpc(540, request(display=True), approve=None)
        checks.record("unexpected-request-test-confirm-open", first[0] == 26)
        s.capture("unexpected-request", wait=True)
        s.send(540, request())
        failure(checks, "unexpected-address-request-during-confirm-refused", s.receive(), [1])
        checks.record("unexpected-request-single-terminal-response", s.receive(.03) is None)
        msg, _, _ = s.rpc(55)
        checks.record("transport-recovers-after-unexpected-request", msg[0] == 17)

        first, _, _ = s.rpc(540, request(display=True), approve=None)
        checks.record("initialize-cancel-setup", first[0] == 26)
        s.capture("initialize-cancel", wait=True)
        s.send(0)
        msg = s.receive()
        checks.record("initialize-cancels-address-with-features", msg and msg[0] == 17)
        checks.record("initialize-cancel-no-late-address", s.receive(.03) is None)
        s.close()
        s = new("pin")
        load_wallet(s, checks, "abandon", pin="1234")
        msg, _, _ = s.rpc(24)
        checks.record("clear-session-before-pin-check", msg[0] == 2)
        first, _, _ = s.rpc(540, request())
        checks.record("locked-wallet-demands-pin", first[0] == 18)
        s.send(20)
        failure(checks, "pin-cancel-does-not-return-address", s.receive(), [6])
        msg, events, _ = s.rpc(540, request(), pin="9999")
        failure(checks, "wrong-pin-refused", msg, [7])
        checks.record("wrong-pin-was-challenged", 18 in events)
        msg, events, _ = s.rpc(540, request(), pin="1234")
        expected = next(case["address"] for case in cases if case["label"] == "abandon-account0-sub0-0-output0")
        checks.record("valid-pin-address", msg[0] == 541 and only(fields(msg[1]), 1).decode() == expected and 18 in events)
        msg, events, _ = s.rpc(540, request())
        checks.record("authenticated-pin-session-reused", msg[0] == 541 and 18 not in events)
        s.close()
        s = new("passphrase")
        load_wallet(s, checks, "abandon", passphrase=True)
        msg, events, _ = s.rpc(540, request(), passphrase="")
        checks.record("empty-passphrase-authenticated-address", msg[0] == 541 and 41 in events
                      and only(fields(msg[1]), 1).decode() == expected)
        msg, _, _ = s.rpc(24)
        checks.record("passphrase-session-cleared", msg[0] == 2)
        challenge, _, _ = s.rpc(540, request())
        checks.record("passphrase-challenged-after-session-clear", challenge[0] == 41)
        s.send(20)
        failure(checks, "passphrase-cancel-does-not-return-address", s.receive(), [11])
        checks.record("passphrase-cancel-node-zero", s.derived_node_zero())
        checks.record("passphrase-cancel-no-late-address", s.receive(.03) is None)
        public_passphrase = "Monero public experiment"
        msg, events, _ = s.rpc(540, request(), passphrase=public_passphrase)
        hidden = independent_passphrase_address(core, "abandon", public_passphrase)
        checks.record("nonempty-public-passphrase-selects-independent-wallet", msg[0] == 541 and 41 in events
                      and only(fields(msg[1]), 1).decode() == hidden and hidden != expected,
                      address=hidden)
        s.rpc(24)
        msg, events, _ = s.rpc(540, request(), passphrase="")
        checks.record("clearing-session-does-not-reuse-hidden-wallet-seed", msg[0] == 541 and 41 in events
                      and only(fields(msg[1]), 1).decode() == expected)
        s.close()
        s = None
    finally:
        if s is not None:
            s.close()
    report = {
        "schema_version": 1, "status": "pass", "checks": checks.items,
        "check_count": len(checks.items), "scope": "research emulator MoneroGetAddress HID path; no transaction signing",
        "library_sha256": sha(args.library.read_bytes()), "reference_sha256": sha(ref_path.read_bytes()),
        "core_library_sha256": sha(core_path.read_bytes()), "reference_core_commit": ref["core_commit"],
        "source_sha256": sha(Path(__file__).read_bytes()), "physical_device_accessed": False,
        "existing_flash_file_opened": False, "public_fixtures_only": True,
        "session_frames": {session.label: session.frames for session in sessions},
    }
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": "pass", "checks": len(checks.items), "output": str(out)}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
