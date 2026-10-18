#!/usr/bin/env python3
"""Vectors for certified UTXO contacts (unittests/firmware/contact_book_utxo_vectors.h).

Written from the formats alone: the KKABREQ1/KKABPRF1 layout in
docs/design/certified-contacts-utxo.md, BIP-32/39, Base58Check, BIP-173/350
and CashAddr. No firmware code is used. The attestor key is m/'KK'/'CS'/0' of
the "all" x12 test mnemonic (OTHER: m/'KK'/'CS'/1'). Signatures are RFC 6979,
so a rerun reproduces the file byte for byte.

    python3 scripts/clearsign/gen_contact_book_utxo_vectors.py > \\
        unittests/firmware/contact_book_utxo_vectors.h
"""

import hashlib
import hmac

from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_string_canonize

MNEMONIC = " ".join(["all"] * 12)
ATTESTOR_PUBKEY_ALL = (
    "03f2ffb8489096035d8bc25201ea7439379fa3dd55a6ed781bf7a94213408ed015")

NETWORK = {
    "Bitcoin": "bip122:000000000019d6689c085ae165831e93",
    "Testnet": "bip122:000000000933ea01ad0ee984209779ba",
    "Litecoin": "bip122:12a765e31ffd4059bada1e25190f6e98",
    "Dogecoin": "bip122:00000000001a91e3dace36e2be3bf030",
    "BitcoinCash": "bip122:000000000000000000651ef99cb9fcbe",
    "Dash": "bip122:000007d91d1254d60e2dd1ae58038307",
    "Zcash": "bip122:00040fe8ec8471911baa1db1266ea15d",
    "DigiByte": "bip122:4da631f2ac1bed857bd968c67c913978",
}
# (p2pkh version, p2sh version, bech32 hrp, cashaddr prefix), from coins.def.
COIN = {
    "Bitcoin": (0, 5, "bc", None),
    "Testnet": (111, 196, "tb", None),
    "Litecoin": (48, 50, "ltc", None),
    "Dogecoin": (30, 22, None, None),
    "BitcoinCash": (0, 5, None, "bitcoincash"),
    "Dash": (76, 16, None, None),
    "Zcash": (0x1CB8, 0x1CBD, None, None),
    "DigiByte": (30, 63, "dgb", None),
}

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def sha(data):
    return hashlib.sha256(data).digest()


def b58check(payload):
    data = payload + sha(sha(payload))[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def version_bytes(v):
    return v.to_bytes(1 if v < 0x100 else 2 if v < 0x10000 else 3, "big")


BECH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def _bits(data, frm, to):
    acc = bits = 0
    out = []
    for b in data:
        acc = (acc << frm) | b
        bits += frm
        while bits >= to:
            bits -= to
            out.append((acc >> bits) & ((1 << to) - 1))
    if bits:
        out.append((acc << (to - bits)) & ((1 << to) - 1))
    return out


def segwit(hrp, ver, prog):
    const = 1 if ver == 0 else 0x2bc830a3
    data = [ver] + _bits(prog, 8, 5)
    hrpx = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    pm = _polymod(hrpx + data + [0] * 6) ^ const
    data += [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(BECH[d] for d in data)


def cashaddr(prefix, kind, h):
    def pm(values):
        gen = [0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8,
               0x1e4f43e470]
        c = 1
        for d in values:
            c0 = c >> 35
            c = ((c & 0x07ffffffff) << 5) ^ d
            for i in range(5):
                if (c0 >> i) & 1:
                    c ^= gen[i]
        return c ^ 1
    payload = _bits(bytes([kind]) + h, 8, 5)
    mod = pm([ord(c) & 31 for c in prefix] + [0] + payload + [0] * 8)
    payload += [(mod >> 5 * (7 - i)) & 31 for i in range(8)]
    return prefix + ":" + "".join(BECH[d] for d in payload)


def address(coin, script):
    p2pkh, p2sh, hrp, cash = COIN[coin]
    s = script
    if len(s) == 25 and s[:3] == b"\x76\xa9\x14" and s[23:] == b"\x88\xac":
        return (cashaddr(cash, 0, s[3:23]) if cash
                else b58check(version_bytes(p2pkh) + s[3:23]))
    if len(s) == 23 and s[:2] == b"\xa9\x14" and s[22:] == b"\x87":
        return (cashaddr(cash, 8, s[2:22]) if cash
                else b58check(version_bytes(p2sh) + s[2:22]))
    if hrp and ((s[0] == 0 and len(s) in (22, 34) and s[1] == len(s) - 2) or
                (s[0] == 0x51 and len(s) == 34 and s[1] == 32)):
        return segwit(hrp, 0 if s[0] == 0 else 1, s[2:])
    raise ValueError("not a standard script for %s" % coin)


def p2pkh(h): return b"\x76\xa9\x14" + h + b"\x88\xac"
def p2sh(h): return b"\xa9\x14" + h + b"\x87"
def p2wpkh(h): return b"\x00\x14" + h
def p2wsh(h): return b"\x00\x20" + h
def p2tr(h): return b"\x51\x20" + h


H20 = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
H32 = bytes.fromhex(
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
WSH = bytes.fromhex(
    "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262")
CASH = bytes.fromhex("76a04053bda0a88bda5177b86a15c3b29f559873")
J98 = bytes.fromhex("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb")
# Published vectors: these encoders must reproduce them.
assert address("Bitcoin", p2wpkh(H20)) == \
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
assert address("Bitcoin", p2wsh(WSH)) == \
    "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
assert address("Bitcoin", p2tr(H32)) == \
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
assert address("BitcoinCash", p2pkh(CASH)) == \
    "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
assert address("Bitcoin", p2sh(J98)) == "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"

# Every form each coin can show, for the round trip through compile_output.
ADDRESSES = [
    ("Bitcoin", p2pkh(H20)), ("Bitcoin", p2sh(J98)), ("Bitcoin", p2wpkh(H20)),
    ("Bitcoin", p2wsh(WSH)), ("Bitcoin", p2tr(H32)),
    ("Testnet", p2pkh(H20)), ("Testnet", p2sh(J98)), ("Testnet", p2wpkh(H20)),
    ("Testnet", p2tr(H32)),
    ("Litecoin", p2pkh(H20)), ("Litecoin", p2sh(J98)),
    ("Litecoin", p2wpkh(H20)),
    ("Dogecoin", p2pkh(H20)), ("Dogecoin", p2sh(J98)),
    ("BitcoinCash", p2pkh(CASH)), ("BitcoinCash", p2sh(J98)),
    ("Dash", p2pkh(H20)), ("Dash", p2sh(J98)),
    ("Zcash", p2pkh(H20)), ("Zcash", p2sh(J98)),
    ("DigiByte", p2pkh(H20)), ("DigiByte", p2wpkh(H20)),
]

# Bitcoin and Testnet only: certifiable in both builds.
BOOK_BTC = [
    ("Bitcoin", p2wpkh(H20), "Alice"),
    ("Bitcoin", p2tr(H32), "Bob"),
    ("Bitcoin", p2pkh(CASH), "Carol"),
    ("Bitcoin", p2sh(J98), "Dave"),
    ("Bitcoin", p2wsh(WSH), "Erin"),
    ("Testnet", p2wpkh(H20), "Tess"),
]
# Every bound coin, the same name on two networks, the same script on two
# networks (Carol on BTC and BCH), and one EVM entry: a full-build book.
BOOK_MIXED = BOOK_BTC + [
    ("Litecoin", p2wpkh(H20), "Alice"),
    ("BitcoinCash", p2pkh(CASH), "Carol cash"),
    ("Dogecoin", p2pkh(H20), "Doge"),
    ("Dash", p2pkh(H20), "Dash"),
    ("Zcash", p2pkh(H20), "Zed"),
    ("DigiByte", p2wpkh(H20), "Digi"),
]
EVM = ("eip155:1", bytes.fromhex("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045"),
       "Eve")
REVISION = 9


def entry_bytes(network, dtype, dest, label):
    net, name = network.encode(), label.encode()
    return (bytes([len(net)]) + net + bytes([dtype, len(dest)]) + dest +
            bytes([len(name)]) + name)


def entries(book):
    return [entry_bytes(NETWORK[c], 2, s, l) for c, s, l in book]


def leaf_tag(entry, legacy=False):
    """UTXO_SCRIPT leaves are tagged KKABUTXO, others KKABLEAF. `legacy`
    tags every leaf KKABLEAF, as alpha builds before 7.17 did."""
    dtype = entry[1 + entry[0]]
    return b"KKABUTXO" if dtype == 2 and not legacy else b"KKABLEAF"


def levels(leaves, legacy=False):
    level = [sha(leaf_tag(e, legacy) + e) for e in leaves]
    width = 1
    while width < len(level):
        width *= 2
    level += [level[-1]] * (width - len(level))
    out = [level]
    while len(level) > 1:
        level = [sha(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        out.append(level)
    return out


def header(n, revision=REVISION):
    return b"\x01" + revision.to_bytes(4, "big") + bytes([n])


def request(leaves):
    return b"KKABREQ1" + header(len(leaves)) + b"".join(leaves)


def proof(leaves, index, key, tamper_label=False, revision=REVISION,
          legacy=False):
    lv = levels(leaves, legacy)
    root = lv[-1][0]
    manifest = b"KKABRT01" + header(len(leaves), revision) + root
    sig = key.sign_digest_deterministic(sha(manifest), hashfunc=hashlib.sha256,
                                        sigencode=sigencode_string_canonize)
    pub = key.get_verifying_key().to_string("compressed")
    siblings, cursor = [], index
    for level in lv[:-1]:
        siblings.append(level[cursor ^ 1])
        cursor >>= 1
    leaf = leaves[index]
    if tamper_label:
        leaf = leaf[:-1] + bytes([leaf[-1] ^ 1])
    return (b"KKABPRF1" + header(len(leaves), revision) + root + pub + sig +
            leaf + bytes([index, len(siblings)]) + b"".join(siblings))


def ckd_priv(k, c, i):
    data = b"\0" + k.to_bytes(32, "big") + i.to_bytes(4, "big")
    I = hmac.new(c, data, hashlib.sha512).digest()
    return (int.from_bytes(I[:32], "big") + k) % SECP256k1.order, I[32:]


def attestor(last):
    seed = hashlib.pbkdf2_hmac("sha512", MNEMONIC.encode(), b"mnemonic", 2048)
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k, c = int.from_bytes(I[:32], "big"), I[32:]
    for i in (0x4B4B, 0x4353, last):
        k, c = ckd_priv(k, c, 0x80000000 | i)
    return SigningKey.from_secret_exponent(k, curve=SECP256k1)


def c_str(name, data):
    return "static const char %s[] =\n    \"%s\";" % (name, data.hex())


def main():
    key, other = attestor(0), attestor(1)
    assert key.get_verifying_key().to_string("compressed").hex() == \
        ATTESTOR_PUBKEY_ALL
    btc = entries(BOOK_BTC)
    mixed = entries(BOOK_MIXED) + [entry_bytes(EVM[0], 1, EVM[1], EVM[2])]
    print("/* Certified UTXO contact vectors. Generated by")
    print(" * scripts/clearsign/gen_contact_book_utxo_vectors.py from the formats")
    print(" * alone (no firmware code); RFC 6979 signatures, so a rerun is")
    print(" * identical. Do not edit by hand. */")
    print("#ifndef UNITTESTS_FIRMWARE_CONTACT_BOOK_UTXO_VECTORS_H")
    print("#define UNITTESTS_FIRMWARE_CONTACT_BOOK_UTXO_VECTORS_H\n")
    print("struct UtxoAddressVector {\n  const char* coin;\n  const char* script;"
          "\n  const char* address;\n};")
    print("static const UtxoAddressVector UTXO_ADDRESSES[] = {")
    for coin, script in ADDRESSES:
        print('    {"%s", "%s",\n     "%s"},' % (coin, script.hex(),
                                                address(coin, script)))
    print("};\n")
    print("/* BOOK_BTC: %s */" % ", ".join(
        "%d %s %s" % (i, c, l) for i, (c, _, l) in enumerate(BOOK_BTC)))
    print(c_str("UREQ_BTC", request(btc)))
    for i in range(len(BOOK_BTC)):
        print(c_str("UPROOF_BTC_%d" % i, proof(btc, i, key)))
    print(c_str("UPROOF_BTC_0_OTHER_KEY", proof(btc, 0, other)))
    print(c_str("UPROOF_BTC_0_TAMPERED", proof(btc, 0, key, True)))
    # No revocation: revision 8 of the book still names Alice after revision
    # 9 is certified. Pinned so no host counts on the device refusing it.
    print(c_str("UPROOF_BTC_0_REVISION_8", proof(btc, 0, key, revision=8)))
    # The same book with KKABLEAF leaves, as alpha builds before 7.17 signed
    # it after showing each script only as hex: never a contact.
    print(c_str("UPROOF_BTC_0_LEGACY_LEAF", proof(btc, 0, key, legacy=True)))
    print("/* BOOK_MIXED: BOOK_BTC, then %s, then EVM %s */" % (
        ", ".join("%d %s %s" % (len(BOOK_BTC) + i, c, l)
                  for i, (c, _, l) in enumerate(BOOK_MIXED[len(BOOK_BTC):])),
        EVM[2]))
    print(c_str("UREQ_MIXED", request(mixed)))
    for i in range(len(mixed)):
        print(c_str("UPROOF_MIXED_%d" % i, proof(mixed, i, key)))
    print("\n#endif")


if __name__ == "__main__":
    main()
