#!/usr/bin/env python3
"""Generate public address/output/key-image fixtures using pinned Monero Core.

This generator has no production seed/mnemonic input and performs no network IO.
Supply the nine pinned source files in --core-source, preserving their upstream
directory layout and license headers. Source hashes are verified before build.
"""
import argparse
import ctypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import unicodedata

HERE = Path(__file__).resolve().parent
CORE_COMMIT = "b14fae7bca4099cea56205e44c1005602834b7bd"
CORE_SHA256 = {
    "contrib/epee/include/int-util.h": "70f4ac6a783585a51062ecde2ced9851708ea5507e1f7221b4bb9677da01149e",
    "contrib/epee/include/warnings.h": "b70e9d851e3ad1835ad47cd90d3365a51982f5503421288daa2e54ce11e4b825",
    "src/crypto/crypto-ops-data.c": "94bee88043845662892a6f489347ad2b4f37744ff6b21c47a1aa0f3e52aed985",
    "src/crypto/crypto-ops.c": "7da995bedd791475d85c9f7f1fde32c2b287a64d7184a294abacad53c0ca64ed",
    "src/crypto/crypto-ops.h": "9b2d2e0bbfd9c8061607ca596f21e4d2ddb0b25d0225fd88590feb07eaeab5e9",
    "src/crypto/hash-def.h": "f09795fb08fa68acd88957b551bbbcd81c896b4ab319c9aad45a2f3b08b5f994",
    "src/crypto/hash-ops.h": "6340b58874b4645cc90d6cf97f87c157b8c8605421aafebcb8fd0bfc7424920a",
    "src/crypto/keccak.c": "56aec12b01d0b85dfff97f8d32e9dbe1bdf4f5cc76a4a97a93af73aa05c98b39",
    "src/crypto/keccak.h": "dde2bdb591a893b8ca5890b7e3d5be906812d4b3977e9006b5434e1cf35d3be7",
}
L = 2**252 + 27742317777372353535851937790883648493
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BLOCK_WIDTH = [0, 2, 3, 5, 6, 7, 9, 10, 11]
FIELDS = ["key_seed", "tx_secret", "spend_secret", "view_secret", "spend_public",
          "view_public", "sub_spend_public", "sub_view_public", "tx_public",
          "derivation", "output_secret", "output_public", "key_image"]
FIXTURES = {
    "abandon": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "trezor": "alcohol woman abuse must during monitor noble actual mixed trade anger aisle",
}


def slip10(mnemonic, account):
    """BIP39 empty passphrase, then SLIP-0010 Ed25519 hardened path."""
    sentence = unicodedata.normalize("NFKD", mnemonic).encode()
    seed = hashlib.pbkdf2_hmac("sha512", sentence, b"mnemonic", 2048)
    digest = hmac.new(b"ed25519 seed", seed, "sha512").digest()
    key, chain = digest[:32], digest[32:]
    for index in [44, 128, account]:
        digest = hmac.new(chain, b"\0" + key + (index | 0x80000000).to_bytes(4, "big"), "sha512").digest()
        key, chain = digest[:32], digest[32:]
    return key


def varint(value):
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


class Core:
    def __init__(self, library):
        self.lib = ctypes.CDLL(str(library))
        for name, arity in [("reduce", 1), ("base", 1), ("mul", 2), ("add", 2)]:
            fn = getattr(self.lib, "ref_" + name)
            fn.argtypes = [ctypes.c_void_p] * (arity + 1)
            fn.restype = ctypes.c_int if name in ["mul", "add"] else None
        for name in ["hash", "hp"]:
            fn = getattr(self.lib, "ref_" + name)
            fn.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
            fn.restype = None

    def op(self, name, *data):
        out = ctypes.create_string_buffer(32)
        result = getattr(self.lib, "ref_" + name)(out, *data)
        if name in ["mul", "add"] and result != 0:
            raise RuntimeError(f"invalid point supplied to Core {name}")
        return out.raw

    def hash(self, data):
        return self.op("hash", data, len(data))

    def hs(self, data):
        return self.op("reduce", self.hash(data))

    def hp(self, data):
        return self.op("hp", data, len(data))

    def address(self, spend, view, subaddress):
        data = bytes([42 if subaddress else 18]) + spend + view
        data += self.hash(data)[:4]
        out = ""
        for offset in range(0, len(data), 8):
            block = data[offset:offset + 8]
            number = int.from_bytes(block, "big")
            chars = ""
            while number:
                number, digit = divmod(number, 58)
                chars = ALPHABET[digit] + chars
            out += chars.rjust(BLOCK_WIDTH[len(block)], "1")
        return out


def add_scalar(a, b):
    return ((int.from_bytes(a, "little") + int.from_bytes(b, "little")) % L).to_bytes(32, "little")


def known_anchors(core):
    if core.hash(b"").hex() != "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470":
        raise RuntimeError("Keccak-256 known answer mismatch")
    x = bytes.fromhex("09321db315661e54fe0d606faffc2437506d6594db804cddd5b5ce27970f2e09")
    public = core.op("base", x)
    if public.hex() != "cd48cd05ee40c3d42dfd9d39e812cbe7021141d1357eb4316f25ced372a9d695":
        raise RuntimeError("independent base-multiplication anchor mismatch")
    hp = core.hp(public)
    if hp.hex() != "c530057dc18b4a216cc15ab76e53720865058b76791ff8c9cef3303d73ae5628":
        raise RuntimeError("independent hash-to-point anchor mismatch")
    if core.op("mul", hp, x).hex() != "d9a248bf031a2157a5a63991c00848a5879e42b7388458b4716c836bb96d96c0":
        raise RuntimeError("independent key-image anchor mismatch")
    # Existing Trezor device-vector anchors validate the wallet convention,
    # separately from the independent Core implementation of curve/hash ops.
    anchors = [
        (0, "4Ahp23WfMrMFK3wYL2hLWQFGt87ZTeRkufS6JoQZu6MEFDokAQeGWmu9MA3GFq1yVLSJQbKJqVAn9F9DLYGpRzRAEXqAXKM", "8722520a581e2a50cc1adab4a1692401effd37b0d63b9d9b60fd7f34ea2b950e"),
        (1, "44iAazhoAkv5a5RqLNVyh82a1n3ceNggmN4Ho7bUBJ14WkEVR8uFTe9f7v5rNnJ2kEbVXxfXiRzsD5Jtc6NvBi4D6WNHPie", "1f70b7d9e86c11b7a5bee883b75c43d6be189c8f812726ea1ecd94b06bb7db04"),
    ]
    for account, address, watch in anchors:
        spend = core.op("reduce", slip10(FIXTURES["trezor"], account))
        view = core.hs(spend)
        actual = core.address(core.op("base", spend), core.op("base", view), False)
        if actual != address or view.hex() != watch:
            raise RuntimeError(f"Trezor wallet derivation anchor mismatch for account {account}")
    return {"keccak": True, "base": True, "hash_to_point": True,
            "key_image": True, "trezor_device_address_and_view_key_accounts": [0, 1]}


def make_cases(core):
    cases = []
    for fixture, mnemonic in FIXTURES.items():
        for account in [0, 1]:
            key_seed = slip10(mnemonic, account)
            spend = core.op("reduce", key_seed)
            view = core.hs(spend)
            spend_pub, view_pub = core.op("base", spend), core.op("base", view)
            tx_secret = core.hs(f"KeepKey Monero public fixture sender/{fixture}/{account}".encode())
            for major, minor in [(0, 0), (0, 1), (1, 0), (100, 100)]:
                is_sub = (major, minor) != (0, 0)
                m = core.hs(b"SubAddr\0" + view + major.to_bytes(4, "little") + minor.to_bytes(4, "little")) if is_sub else bytes(32)
                sub_spend = core.op("add", spend_pub, core.op("base", m)) if is_sub else spend_pub
                sub_view = core.op("mul", sub_spend, view) if is_sub else view_pub
                tx_pub = core.op("mul", sub_spend, tx_secret) if is_sub else core.op("base", tx_secret)
                derivation = core.op("mul", core.op("mul", tx_pub, view), (8).to_bytes(32, "little"))
                sender = core.op("mul", core.op("mul", sub_view, tx_secret), (8).to_bytes(32, "little"))
                if derivation != sender:
                    raise RuntimeError("sender and receiver derivations disagree")
                for index in [0, 1, 127, 128, 65537, 0xFFFFFFFF]:
                    h = core.hs(derivation + varint(index))
                    secret = add_scalar(add_scalar(h, spend), m)
                    output = core.op("base", secret)
                    if output != core.op("add", sub_spend, core.op("base", h)):
                        raise RuntimeError("output public and secret derivation disagree")
                    case = {"label": f"{fixture}-account{account}-sub{major}-{minor}-output{index}",
                            "major": major, "minor": minor, "output_index": index}
                    case.update(dict(zip(FIELDS, [key_seed, tx_secret, spend, view, spend_pub, view_pub,
                                                  sub_spend, sub_view, tx_pub, derivation, secret, output,
                                                  core.op("mul", core.hp(output), secret)])))
                    case["address"] = core.address(sub_spend, sub_view, is_sub)
                    cases.append(case)
    return cases


def write_header(cases, path):
    lines = ["/* Generated by reference.py from public disposable fixtures; no wallet secrets. */",
             "#ifndef KEEPKEY_MONERO_INTEROP_VECTORS_H", "#define KEEPKEY_MONERO_INTEROP_VECTORS_H",
             "#include <stdint.h>", "typedef struct {", "  const char *label;",
             "  uint32_t major, minor, output_index;"]
    lines += [f"  uint8_t {field}[32];" for field in FIELDS]
    lines += ["  char address[96];", "} monero_reference_case;",
              "static const monero_reference_case monero_reference_cases[] = {"]
    for case in cases:
        lines += ["  {", f"    .label = {json.dumps(case['label'])},",
                  f"    .major = {case['major']}u, .minor = {case['minor']}u, .output_index = {case['output_index']}u,"]
        for field in FIELDS:
            array = ", ".join(f"0x{x:02x}" for x in case[field])
            lines.append(f"    .{field} = {{{array}}},")
        lines += [f"    .address = {json.dumps(case['address'])}", "  },"]
    lines += ["};", f"#define MONERO_REFERENCE_CASE_COUNT {len(cases)}u", "#endif", ""]
    path.write_text("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    parser.add_argument("--boost-include", type=Path, default=Path("/opt/homebrew/include"))
    args = parser.parse_args()
    root, out = args.core_source.resolve(), args.output.resolve()
    for relative, expected in CORE_SHA256.items():
        actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        if actual != expected:
            raise RuntimeError(f"pinned Monero Core source hash mismatch: {relative}")
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        parser.error("output directory must be empty")
    sodium = subprocess.check_output(["pkg-config", "--cflags", "--libs", "libsodium"], text=True)
    library = out / ("core-reference.dylib" if sys.platform == "darwin" else "core-reference.so")
    command = [args.cc, "-std=c11", "-O2", "-fPIC", "-shared", "-I", str(root / "src/crypto"),
               "-I", str(root / "contrib/epee/include"), "-I", str(args.boost_include),
               str(HERE / "core-reference.c"), *[str(root / "src/crypto" / s) for s in ["crypto-ops.c", "crypto-ops-data.c", "keccak.c"]],
               *shlex.split(sodium), "-o", str(library)]
    compiled = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (out / "build.log").write_text(json.dumps(command) + "\n" + compiled.stdout)
    if compiled.returncode:
        raise RuntimeError(f"reference build failed: {out / 'build.log'}")
    core = Core(library)
    anchors = known_anchors(core)
    cases = make_cases(core)
    write_header(cases, out / "interop_vectors.h")
    report = {
        "schema_version": 1, "scope": "public disposable fixtures only; no network and no hardware",
        "core_commit": CORE_COMMIT, "core_source_sha256": CORE_SHA256,
        "fixture_mnemonics_public": FIXTURES, "bip39_passphrase": "",
        "derivation": "SLIP-0010 Ed25519 m/44'/128'/account'; spend=reduce(node.private_key); view=reduce(Keccak256(spend))",
        "key_image_variant": "pre-FCMP++/Carrot biased Keccak+fromfe+mul8 (legacy/CLSAG path)",
        "key_image_variant_source": f"https://github.com/monero-project/monero/blob/{CORE_COMMIT}/src/crypto/crypto.cpp",
        "compiler": subprocess.check_output([args.cc, "--version"], text=True).splitlines()[0],
        "sodium_version": subprocess.check_output(["pkg-config", "--modversion", "libsodium"], text=True).strip(),
        "anchors": anchors, "case_count": len(cases),
        "header_sha256": hashlib.sha256((out / "interop_vectors.h").read_bytes()).hexdigest(),
        "adapter_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__), HERE / "core-reference.c"]},
        "anchor_sources": [
            "https://github.com/KeystoneHQ/keystone3-firmware/blob/2a48ba022ac24d3b343fa4b9e59251a5de3e1160/rust/apps/monero/src/key.rs#L259",
            "https://github.com/keepkey/trezor-firmware/blob/f3fbfc7f14f79bbfc672f5df3121e7d5c1823990/tests/device_tests/test_msg_monero_getaddress.py",
            "https://github.com/keepkey/trezor-firmware/blob/f3fbfc7f14f79bbfc672f5df3121e7d5c1823990/tests/device_tests/test_msg_monero_getwatchkey.py"],
        "cases": [{k: v.hex() if isinstance(v, bytes) else v for k, v in case.items()} for case in cases],
    }
    (out / "reference.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(out), "case_count": len(cases), "anchors": anchors}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
