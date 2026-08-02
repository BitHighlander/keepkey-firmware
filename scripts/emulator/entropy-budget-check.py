#!/usr/bin/env python3
"""Functional check for the GetEntropy per-boot budget (fsm_msg_common.h).

Drives a standalone kkemu over UDP with raw wire frames -- no regenerated
protos needed. Asserts:
  1. GetEntropy(8192) returns 8192 bytes (the raised Entropy.entropy cap).
  2. The first ENTROPY_FREE_BUDGET (64 KiB) needs no button press.
  3. The very next call falls back to a ButtonRequest.
  4. Bytes actually differ between calls (emulator RNG is not stuck).
"""
import os, socket, struct, subprocess, sys, tempfile, time

PORT = int(os.environ.get("KEEPKEY_UDP_PORT", "31044"))
KKEMU = sys.argv[1] if len(sys.argv) > 1 else "build/bin/kkemu"

GET_ENTROPY, ENTROPY, BUTTON_REQUEST, FAILURE, INITIALIZE = 9, 10, 26, 3, 0


def frames(msg_type, body):
    """Split a message into 64-byte HID-style frames."""
    head = b"\x3f##" + struct.pack(">HL", msg_type, len(body))
    payload = head + body
    out = []
    first, rest = payload[:64], payload[64:]
    out.append(first.ljust(64, b"\x00"))
    while rest:
        chunk, rest = rest[:63], rest[63:]
        out.append((b"\x3f" + chunk).ljust(64, b"\x00"))
    return out


def call(sock, msg_type, body=b"", timeout=5.0):
    for f in frames(msg_type, body):
        sock.send(f)
    sock.settimeout(timeout)
    pkt = sock.recv(64)
    assert pkt[:3] == b"\x3f##", f"bad response header {pkt[:3]!r}"
    rtype, rlen = struct.unpack(">HL", pkt[3:9])
    data = pkt[9:]
    while len(data) < rlen:
        data += sock.recv(64)[1:]
    return rtype, data[:rlen]


def varint(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def get_entropy(sock, size):
    return call(sock, GET_ENTROPY, b"\x08" + varint(size))


def parse_entropy(body):
    assert body[0] == 0x0A, f"expected field 1 bytes, got {body[0]:#x}"
    i, shift, ln = 1, 0, 0
    while True:
        b = body[i]; i += 1
        ln |= (b & 0x7F) << shift; shift += 7
        if not (b & 0x80):
            break
    return body[i:i + ln]


def main():
    workdir = tempfile.mkdtemp(prefix="kkemu-entropy-")
    emu = subprocess.Popen([os.path.abspath(KKEMU)], cwd=workdir,
                           env={**os.environ, "KEEPKEY_UDP_PORT": str(PORT)},
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("127.0.0.1", PORT))
        call(sock, INITIALIZE)

        CHUNK, BUDGET = 8192, 64 * 1024
        n_free = BUDGET // CHUNK
        seen = []
        for i in range(n_free):
            rtype, body = get_entropy(sock, CHUNK)
            assert rtype == ENTROPY, (
                f"call {i+1}/{n_free} within budget returned type {rtype}, "
                f"expected Entropy({ENTROPY}) with no press")
            ent = parse_entropy(body)
            assert len(ent) == CHUNK, f"got {len(ent)} bytes, expected {CHUNK}"
            seen.append(ent)
        print(f"  [ok] {n_free} x {CHUNK}B = {n_free*CHUNK} bytes, no button press")
        print(f"  [ok] Entropy.entropy cap raised: {CHUNK} bytes in one call")

        assert len(set(seen)) == n_free, "repeated entropy block across calls!"
        print(f"  [ok] all {n_free} blocks distinct (RNG not stuck)")

        rtype, _ = get_entropy(sock, CHUNK)
        assert rtype == BUTTON_REQUEST, (
            f"budget exhausted but got type {rtype}, expected "
            f"ButtonRequest({BUTTON_REQUEST}) -- budget is not enforced!")
        print(f"  [ok] budget exhausted -> ButtonRequest (confirm restored)")
        print("\nPASS")
        return 0
    finally:
        emu.terminate()


if __name__ == "__main__":
    sys.exit(main())
