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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", required=True, type=Path)
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

    print(
        f"Firmware identity verified: variant={args.variant}, "
        f"KeepKeyBTC markers={count}"
    )


if __name__ == "__main__":
    main()
