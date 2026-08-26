#!/usr/bin/env python3
"""Ensure ARM artifacts advertise the feature set Vault will enforce.

Vault cannot query Features while a device is in bootloader mode, so it scans
the candidate payload for the same marker the running firmware later returns in
Features.firmware_variant. A bitcoin-only image without this marker looks like
full firmware both before and after flash, leaving unsupported chains visible.
"""

import argparse
from pathlib import Path


BTC_ONLY_MARKER = b"KeepKeyBTC\x00"
REQUIRED_BITCOIN_SYMBOLS = (
    b"fsm_msgGetAddress",
    b"fsm_msgGetPublicKey",
    b"fsm_msgSignTx",
)
FORBIDDEN_HANDLER_PREFIXES = (
    b"fsm_msgBinance",
    b"fsm_msgClearsignAttestor",
    b"fsm_msgCosmos",
    b"fsm_msgEos",
    b"fsm_msgEthereum",
    b"fsm_msgHive",
    b"fsm_msgLoadClearsignSigner",
    b"fsm_msgMayachain",
    b"fsm_msgNano",
    b"fsm_msgOsmosis",
    b"fsm_msgRipple",
    b"fsm_msgSolana",
    b"fsm_msgTendermint",
    b"fsm_msgThorchain",
    b"fsm_msgTon",
    b"fsm_msgTron",
    b"fsm_msgZcash",
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--elf", required=True, type=Path)
    parser.add_argument("--variant", required=True, choices=("full", "bitcoin-only"))
    args = parser.parse_args()

    data = args.artifact.read_bytes()
    count = data.count(BTC_ONLY_MARKER)

    if args.variant == "bitcoin-only" and count == 0:
        raise SystemExit(
            "bitcoin-only artifact does not embed KeepKeyBTC; Vault cannot "
            "identify or restrict this firmware"
        )
    if args.variant == "full" and count != 0:
        raise SystemExit(
            "full artifact embeds KeepKeyBTC; Vault would misclassify it as "
            "bitcoin-only"
        )

    if args.variant == "bitcoin-only":
        elf = args.elf.read_bytes()
        missing = [symbol.decode() for symbol in REQUIRED_BITCOIN_SYMBOLS if symbol not in elf]
        if missing:
            raise SystemExit(
                "bitcoin-only ELF is missing core Bitcoin handlers: "
                + ", ".join(missing)
            )
        present = [prefix.decode() for prefix in FORBIDDEN_HANDLER_PREFIXES if prefix in elf]
        if present:
            raise SystemExit(
                "bitcoin-only ELF contains non-Bitcoin message handlers: "
                + ", ".join(present)
            )

    print(
        f"Firmware identity verified: variant={args.variant}, "
        f"KeepKeyBTC markers={count}"
        + (", Bitcoin handlers present and altcoin handlers absent"
           if args.variant == "bitcoin-only" else "")
    )


if __name__ == "__main__":
    main()
