#!/usr/bin/env python3
"""Recompute a KeepKey dice wallet offline, from what you hold.

Both dice modes are designed so that every input to the seed is one you can
write down, so this script needs no secret from the device and no network.

DICE ONLY  -- seed = SHA256(rolls)
    The rolls are the entire derivation. Identical to Coldcard's
    Dice-Rolls-Only, so their published verifier gives the same answer.

        ./verify_dice_seed.py --rolls 5312...  --words 24

MIXED      -- seed = SHA256(SHA256(b"KK\\x01SM" + device + SHA256(b"KK\\x01D" + rolls)))
    The device showed its own 32-byte draw as 24 BIP-39 words BEFORE you
    rolled. Pass those words back in; with them and your rolls the seed is
    fully determined. The host's EntropyAck bytes are consumed by the device
    and discarded, so they do not appear here.

        ./verify_dice_seed.py --rolls 5312... --words 12 \\
            --device-words "abandon ability able ..."

Compare the printed mnemonic with the backup words the device showed. If
they differ, the device did not derive the wallet from your rolls (and, in
MIXED, from the entropy it committed to). Do not fund it.

WARNING: in DICE ONLY the roll string IS the wallet; in MIXED the roll string
plus the device words are. Anyone who obtains them recreates your keys. Run
this on a machine you would trust with the seed, and prefer a throwaway run:
roll, verify the math, then start again with fresh rolls for the wallet you
actually fund.

Neither mode is a default, and DICE ONLY in particular has no device
randomness by design: a biased die, too few rolls, or a photographed roll
sheet is the whole wallet. The device refuses rolls where any face exceeds
30% of the total, as Coldcard does, but that is a floor, not a guarantee.
"""

import argparse
import hashlib
import os
import sys

# 50 rolls for 128-bit, 75 for 192-bit, 99 for 256-bit -- matches
# dice_rolls_for_strength() in lib/firmware/dice_input.c.
ROLLS_FOR_STRENGTH = {128: 50, 192: 75, 256: 99}
STRENGTH_FOR_WORDS = {12: 128, 18: 192, 24: 256}

# Byte tags, matching lib/firmware/dice_input.c. Python's \x takes exactly
# two hex digits, so b"KK\x01D" is the four bytes K, K, 0x01, D.
TAG_USER = b"KK\x01D"
TAG_MIX = b"KK\x01SM"

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


def entropy_from_mnemonic(sentence, words):
    """Inverse of the above for the 24-word device sentence, checksum
    verified: a typo in a copied word is caught here, not blamed on the
    device."""
    parts = sentence.split()
    if len(parts) != 24:
        raise SystemExit("--device-words must be the 24 words the device "
                         "showed; got %d" % len(parts))
    try:
        bits = "".join("{:011b}".format(words.index(w)) for w in parts)
    except ValueError as exc:
        raise SystemExit("not a BIP-39 word: %s" % exc)
    entropy = bytes(int(bits[i:i + 8], 2) for i in range(0, 256, 8))
    if bits[256:] != "{:08b}".format(hashlib.sha256(entropy).digest()[0]):
        raise SystemExit("device words fail their BIP-39 checksum; re-check "
                         "the transcription before suspecting the device")
    return entropy


def seed_dice_only(rolls):
    return hashlib.sha256(rolls.encode("ascii")).digest()


def seed_mixed(device_entropy, rolls):
    user = hashlib.sha256(TAG_USER + rolls.encode("ascii")).digest()
    inner = hashlib.sha256(TAG_MIX + device_entropy + user).digest()
    return hashlib.sha256(inner).digest()


def main():
    ap = argparse.ArgumentParser(
        description="Recompute a KeepKey dice wallet from what you hold.")
    ap.add_argument("--rolls", help="roll string, digits 1-6 (default: stdin)")
    ap.add_argument("--words", type=int, choices=sorted(STRENGTH_FOR_WORDS),
                    required=True, help="word count the device produced")
    ap.add_argument("--device-words",
                    help="the 24 device-entropy words shown before rolling "
                         "(MIXED mode); omit for DICE ONLY")
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
            "got %d rolls, but a %d-word dice seed uses exactly %d.\n"
            "A different count derives a different wallet, so this is a "
            "transcription error, not a warning." % (len(rolls), args.words,
                                                     expected))

    path = find_wordlist(args.wordlist)
    words = load_wordlist(path) if path else None

    digest = hashlib.sha256(rolls.encode("ascii")).digest()
    if args.device_words:
        if words is None:
            raise SystemExit("MIXED mode needs the BIP-39 wordlist to decode "
                             "--device-words; pass --wordlist")
        device_entropy = entropy_from_mnemonic(args.device_words, words)
        seed = seed_mixed(device_entropy, rolls)
        mode = "MIXED   seed = SHA256d(tag || device || SHA256(tag || rolls))"
    else:
        seed = seed_dice_only(rolls)
        mode = "DICE ONLY   seed = SHA256(rolls)"

    print("mode        : %s" % mode)
    print("rolls       : %d" % len(rolls))
    print("roll digest : %s" % digest.hex())
    print("            : the device showed this in full on the Dice Rolls "
          "screen")
    if args.device_words:
        print("device draw : %s" % device_entropy.hex())
    print("entropy     : %s" % seed[:strength // 8].hex())

    if words is None:
        raise SystemExit(
            "\nno BIP39 wordlist found; pass --wordlist <bip39_english.txt> to "
            "print the mnemonic. The entropy above is the value the backup "
            "words encode.")

    mnemonic = mnemonic_from_entropy(seed[:strength // 8], words)
    print()
    print("mnemonic    :")
    parts = mnemonic.split()
    for i in range(0, len(parts), 4):
        print("  %2d. %s" % (i + 1, "  ".join(parts[i:i + 4])))
    print()
    print("If these are not the words the device showed, the device did not "
          "derive")
    print("the wallet from your rolls. Do not fund it.")


if __name__ == "__main__":
    main()
