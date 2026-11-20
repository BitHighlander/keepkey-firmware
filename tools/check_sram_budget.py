#!/usr/bin/env python3
"""SRAM budget gate for ARM firmware builds.

Fails CI when the runtime stack/heap reserve — the gap between the end of
static allocation (_ebss) and the top-of-RAM stack (_stack) — drops below the
per-variant budget, or when the largest single stack frame (-fstack-usage)
leaves less than the configured margin inside that reserve.

Why this exists: RC7's zcash-privacy build shipped with an 11,232-byte gap
while msg_write() carried a 12,416-byte automatic TrezorFrameBuffer — every
USB response overwrote static memory, hard-faulting on boot. The linker also
ASSERTs a 16 KiB floor (tools/firmware/keepkey.ld); this script is the
observability + frame-margin half of that gate.

Usage:
  check_sram_budget.py --elf bin/...firmware.keepkey.elf \
      --su-tar bin/stack-usage.tgz --lto-map bin/firmware.keepkey.map \
      --budgets tools/sram-budgets.json \
      --variant zcash-privacy
"""

import argparse
from collections import Counter
import json
from pathlib import PurePosixPath
import sys
import tarfile

from elftools.elf.elffile import ELFFile  # pip install pyelftools


def read_symbols(elf_path):
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            sys.exit(f"ERROR: {elf_path} has no .symtab")
        wanted = {}
        for sym in symtab.iter_symbols():
            if sym.name in ("_ebss", "_stack"):
                wanted[sym.name] = sym["st_value"]
        missing = {"_ebss", "_stack"} - set(wanted)
        if missing:
            sys.exit(f"ERROR: {elf_path} missing symbols: {sorted(missing)}")
        return wanted


def lto_reports(link_map):
    """Get the stack reports for the LTO objects that ld actually linked."""
    reports = set()
    with open(link_map) as stream:
        for line in stream:
            if line.startswith("LOAD "):
                obj = PurePosixPath(line[5:].strip())
                if obj.match("lto-su/*.ltrans.o"):
                    reports.add(PurePosixPath("lto-su", obj.with_suffix(".su").name))
    if not reports:
        sys.exit(f"ERROR: no firmware LTO partitions in {link_map}")
    return reports


def largest_frames(su_tar_path, top_n=15, lto_map=None):
    """Parse GCC -fstack-usage records from a tar of .su files.

    Record format: "<file>:<line>:<col>:<function>\t<bytes>\t<qualifier>"
    """
    frames = []
    missing = lto_reports(lto_map) if lto_map else set()
    with tarfile.open(su_tar_path, "r:*") as tar:
        for member in tar:
            if not member.name.endswith(".su") or not member.isfile():
                continue
            data = tar.extractfile(member).read().decode("utf-8", "replace")
            count_before = len(frames)
            for line in data.splitlines():
                parts = line.rsplit("\t", 2)
                if len(parts) != 3:
                    continue
                loc, size, qual = parts
                qualifiers = {part.strip().lower()
                              for part in qual.split(",")}
                # GCC reports a reliable maximum for dynamic,bounded, but
                # only the fixed portion for an unbounded dynamic frame.
                if "dynamic" in qualifiers and "bounded" not in qualifiers:
                    sys.exit(f"ERROR: unbounded dynamic stack frame in "
                             f"{member.name}: {loc} ({qual})")
                try:
                    frames.append((int(size), loc.split("/")[-1], qual))
                except ValueError:
                    continue
            if len(frames) > count_before:
                missing.discard(PurePosixPath(member.name))
    if missing:
        sys.exit("ERROR: missing stack-usage records for linked LTO partitions: "
                 + ", ".join(str(path) for path in sorted(missing)))
    frames.sort(reverse=True)
    return frames[:top_n]


def passkey_dispatch_frames(frames):
    """Charge the largest mutually exclusive command plus its enclosing scopes.

    Every other emitted CTAP helper is charged once, including split LTO
    functions. USB may reenter u2fhid_read on a tiny poll, so charge all U2F
    helpers twice. This deliberately overcounts unrelated helper branches.
    The separate margin covers code outside these two files (CBOR recursion,
    USB drivers, display, crypto, storage, interrupts). It is a budget for
    those paths, not a proven bound on them.
    """
    commands = {"make_credential", "get_assertion", "get_next_assertion",
                "get_info", "client_pin", "reset_authenticator",
                "u2f_register", "u2f_authenticate"}
    by_command = Counter()
    helpers = 0
    seen = set()
    for size, location, _ in frames:
        source, _, name = location.partition(":")
        if source not in {"ctap2.c", "u2f.c"}:
            continue
        name = name.rsplit(":", 1)[-1].split(".", 1)[0]
        seen.add(name)
        if name in commands:
            by_command[name] += size
        else:
            helpers += size * (2 if source == "u2f.c" else 1)
    # Review the model again if compiler or source changes remove these
    # identifiable entry points from the reports.
    missing = {"u2fhid_read", "u2f_register", "make_credential"} - seen
    if missing:
        sys.exit("ERROR: missing passkey stack frames: " + ", ".join(sorted(missing)))
    return helpers + max(by_command.values())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", required=True)
    ap.add_argument("--su-tar", required=True)
    ap.add_argument("--lto-map", help="require stack records for all LTO objects in the linker map")
    ap.add_argument("--budgets", required=True)
    ap.add_argument("--variant", required=True)
    args = ap.parse_args()

    budgets = json.load(open(args.budgets))
    reserve_min = budgets.get("variants", {}).get(args.variant, {}).get(
        "reserve_min", budgets["reserve_min"])
    frame_margin = budgets.get("variants", {}).get(args.variant, {}).get(
        "frame_margin", budgets["frame_margin"])

    syms = read_symbols(args.elf)
    gap = syms["_stack"] - syms["_ebss"]

    frames = largest_frames(args.su_tar, top_n=None, lto_map=args.lto_map)
    if not frames:
        # An empty .su archive means -fstack-usage generation broke (or the
        # tar glob went stale). Treating it as "largest frame = 0" would let
        # the margin check false-pass — fail loudly instead.
        sys.exit("ERROR: no -fstack-usage records found in "
                 f"{args.su_tar} — stack-usage generation is broken; "
                 "refusing to pass the frame-margin gate without data")
    largest = frames[0][0]
    passkey_frames = passkey_dispatch_frames(frames)
    passkey_margin = budgets["passkey_external_margin"]

    print(f"SRAM budget report — variant: {args.variant}")
    print(f"  _ebss  = 0x{syms['_ebss']:08x}")
    print(f"  _stack = 0x{syms['_stack']:08x}")
    print(f"  stack/heap reserve (gap) = {gap:,} B "
          f"(budget: >= {reserve_min:,} B)")
    print(f"  largest stack frame      = {largest:,} B "
          f"(gap - largest must be >= {frame_margin:,} B)")
    print("  top stack frames (-fstack-usage):")
    for size, loc, qual in frames[:15]:
        print(f"    {size:7,} B  {qual:14s} {loc}")

    print(f"  U2F/CTAP dispatcher and command frame budget = {passkey_frames:,} B")
    print(f"  reserve for external callees and interrupts = {gap - passkey_frames:,} B "
          f"(minimum {passkey_margin:,} B)")
    failed = False
    if gap - passkey_frames < passkey_margin:
        print("::error::SRAM gate: insufficient reserve for passkey callees")
        failed = True
    if gap < reserve_min:
        print(f"::error::SRAM gate: reserve {gap:,} B < budget "
              f"{reserve_min:,} B for {args.variant}")
        failed = True
    if gap - largest < frame_margin:
        print(f"::error::SRAM gate: reserve minus largest frame "
              f"({gap:,} - {largest:,} = {gap - largest:,} B) < margin "
              f"{frame_margin:,} B for {args.variant}")
        failed = True

    if failed:
        sys.exit(1)
    print("SRAM budget gate: PASS")


if __name__ == "__main__":
    main()
