#!/usr/bin/env python3
"""Enforce the RC18 split between public and secret Pallas operations."""

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def source(path):
    return (ROOT / path).read_text(encoding="utf-8")


def function_body(text, name):
    match = re.search(r"\b" + re.escape(name) + r"\s*\([^;]*?\)\s*\{", text, re.S)
    if not match:
        raise AssertionError("function not found: " + name)
    start = match.end() - 1
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1:index]
    raise AssertionError("unterminated function: " + name)


def code_only(text):
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)


def require(body, token, where):
    if token not in body:
        raise AssertionError("{} must call {}".format(where, token))


def forbid(body, token, where):
    if token in body:
        raise AssertionError("{} must not call {}".format(where, token))


def main():
    pallas = source("deps/crypto/trezor-crypto/pallas.c")
    sinsemilla = source("deps/crypto/trezor-crypto/pallas_sinsemilla.c")
    redpallas = source("deps/crypto/trezor-crypto/redpallas.c")
    zcash = source("lib/firmware/zcash.c")

    # Public transaction data needs the fast compatibility implementation.
    forbid(pallas, '"pallas_ct.h"', "pallas.c public compatibility path")
    hash_to_point = code_only(function_body(sinsemilla,
                                            "pallas_sinsemilla_hash_to_point"))
    require(hash_to_point, "sinsemilla_incomplete_add",
            "Sinsemilla public hash path")
    forbid(hash_to_point, "pallas_ct_", "Sinsemilla public hash path")
    incomplete_add = code_only(function_body(sinsemilla,
                                             "sinsemilla_incomplete_add"))
    require(incomplete_add, "pallas_point_add", "Sinsemilla public hash add")
    forbid(incomplete_add, "pallas_ct_", "Sinsemilla public hash add")

    # The commitment blind is rivk on IVK derivation paths, so its one scalar
    # multiplication and the final add remain fixed-schedule.  This does not
    # put the repeated transaction commitment hash additions on the slow path.
    commit = code_only(function_body(sinsemilla, "pallas_sinsemilla_commit"))
    require(commit, "pallas_ct_point_mult", "Sinsemilla blinding")
    require(commit, "pallas_ct_point_add", "Sinsemilla blinding")
    forbid(commit, "pallas_point_mult(", "Sinsemilla blinding")
    forbid(commit, "pallas_point_add(", "Sinsemilla blinding")

    # Authorization scalars, nonces, and randomized keys must never fall back
    # to the variable-time public-data API.
    spendauth = code_only(function_body(redpallas, "pallas_scalar_mult_spendauth"))
    require(spendauth, "pallas_ct_point_mult", "RedPallas scalar multiplication")
    forbid(spendauth, "pallas_point_mult(", "RedPallas scalar multiplication")

    sign = code_only(function_body(redpallas, "redpallas_sign_digest"))
    for token in ("pallas_ct_add_mod_q", "pallas_ct_mod_q",
                  "pallas_ct_mul_mod_q", "pallas_ct_scalar_replace_zero_with_one"):
        require(sign, token, "redpallas_sign_digest")
    for token in ("pallas_add_mod_q(", "pallas_mod_q(", "pallas_mul_mod_q("):
        forbid(sign, token, "redpallas_sign_digest")

    derive_rk = code_only(function_body(redpallas, "redpallas_derive_rk"))
    require(derive_rk, "pallas_ct_add_mod_q", "redpallas_derive_rk")

    # ZIP-32 key reduction and transmission-key derivation also process
    # device-secret viewing/spending material.
    for name in ("to_scalar", "to_base"):
        body = code_only(function_body(zcash, name))
        require(body, "pallas_ct_", name)
    transmission = code_only(function_body(zcash, "zcash_orchard_derive_transmission_key"))
    require(transmission, "pallas_ct_point_mult", "Orchard transmission-key derivation")
    forbid(transmission, "pallas_point_mult(", "Orchard transmission-key derivation")

    print("Pallas API boundary: public Sinsemilla fast path and secret CT path verified")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as error:
        print("Pallas API boundary violation: {}".format(error), file=sys.stderr)
        sys.exit(1)
