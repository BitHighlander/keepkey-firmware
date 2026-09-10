#!/usr/bin/env python3
"""Recompute a KeepKey dice-only wallet from the roll string alone.

Dice-only mode derives the seed as

    entropy  = SHA256(rolls)          # rolls as ASCII '1'-'6', no separators
    mnemonic = BIP39(entropy[:strength/8])

and nothing else participates: the device RNG draw is discarded rather than
folded in, and the host's EntropyAck bytes are consumed and dropped. So every
input is one you hold, and this script needs no secret from the device and no
network.

Run it on an offline machine, compare the mnemonic it prints with the words the
device showed, and you have checked the derivation yourself rather than taking
the firmware's word for it.

    ./verify_dice_seed.py --rolls 5312...  --words 24
    echo 5312... | ./verify_dice_seed.py --words 12

WARNING: the roll string IS the wallet in this mode. Anyone who obtains it
recreates your keys. Verify on a machine you would trust with the seed, and
prefer a throwaway run -- roll, verify the math, then start again with fresh
rolls for the wallet you actually fund.

This mode has no device randomness by design. That is what makes it verifiable
and also what makes it unforgiving: a biased die, too few rolls, or a
photographed roll sheet is the whole wallet. The mixed mode is safer for almost
everyone and cannot be checked this way.
"""

import argparse
import hashlib
import os
import sys

# 50 rolls for 128-bit, 75 for 192-bit, 99 for 256-bit -- matches
# dice_rolls_for_strength() in lib/firmware/dice_input.c.
ROLLS_FOR_STRENGTH = {128: 50, 192: 75, 256: 99}
STRENGTH_FOR_WORDS = {12: 128, 18: 192, 24: 256}

WORDLIST_CANDIDATES = (
    "deps/crypto/trezor-firmware/crypto/bip39_english.txt",
    "deps/crypto/bip39_english.txt",
)


def find_wordlist(explicit):
    if explicit:
        return explicit
    here = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    for rel in WORDLIST_CANDIDATES:
        path = os.path.join(here, rel)
        if os.path.isfile(path):
            return path
    return None


def load_wordlist(path):
    with open(path) as handle:
        words = [line.strip() for line in handle if line.strip()]
    if len(words) != 2048:
        raise SystemExit("wordlist %s has %d entries, expected 2048"
                         % (path, len(words)))
    return words


def mnemonic_from_entropy(entropy, words):
    """BIP39: entropy + SHA256 checksum, split into 11-bit indices."""
    checksum_bits = len(entropy) * 8 // 32
    digest = hashlib.sha256(entropy).digest()
    bits = "".join("{:08b}".format(b) for b in entropy)
    bits += "".join("{:08b}".format(b) for b in digest)[:checksum_bits]
    return " ".join(words[int(bits[i:i + 11], 2)]
                    for i in range(0, len(bits), 11))


def main():
    ap = argparse.ArgumentParser(
        description="Recompute a KeepKey dice-only wallet from its rolls.")
    ap.add_argument("--rolls", help="roll string, digits 1-6 (default: stdin)")
    ap.add_argument("--words", type=int, choices=sorted(STRENGTH_FOR_WORDS),
                    required=True, help="word count the device produced")
    ap.add_argument("--wordlist", help="path to bip39_english.txt")
    args = ap.parse_args()

    rolls = args.rolls if args.rolls is not None else sys.stdin.read()
    rolls = "".join(rolls.split())

    bad = sorted(set(rolls) - set("123456"))
    if bad:
        raise SystemExit("rolls contain non-d6 characters: %s" % ", ".join(bad))

    strength = STRENGTH_FOR_WORDS[args.words]
    expected = ROLLS_FOR_STRENGTH[strength]
    if len(rolls) != expected:
        raise SystemExit(
            "got %d rolls, but a %d-word dice-only seed uses exactly %d.\n"
            "A different count derives a different wallet, so this is a "
            "transcription error, not a warning." % (len(rolls), args.words,
                                                     expected))

    digest = hashlib.sha256(rolls.encode("ascii")).digest()

    path = find_wordlist(args.wordlist)
    if path is None:
        print("roll digest : %s" % digest.hex())
        print("entropy     : %s" % digest[:strength // 8].hex())
        raise SystemExit(
            "\nno BIP39 wordlist found; pass --wordlist <bip39_english.txt> to "
            "print the mnemonic.\nThe digest above is still the value the "
            "device showed while rolling.")

    mnemonic = mnemonic_from_entropy(digest[:strength // 8],
                                     load_wordlist(path))

    print("rolls       : %d" % len(rolls))
    print("roll digest : %s" % digest.hex())
    print("            : the device showed the leading bytes of this while "
          "rolling")
    print("entropy     : %s" % digest[:strength // 8].hex())
    print()
    print("mnemonic    :")
    words = mnemonic.split()
    for i in range(0, len(words), 4):
        print("  %2d. %s" % (i + 1, "  ".join(words[i:i + 4])))
    print()
    print("If these are not the words the device showed, the device did not "
          "derive")
    print("the wallet from your rolls. Do not fund it.")


if __name__ == "__main__":
    main()
