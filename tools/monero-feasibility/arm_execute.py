#!/usr/bin/env python3
"""Execute deterministic Monero interoperability checks as Cortex-M3 Thumb code.

Requires Unicorn and pyelftools in the invoking Python environment. This does
not access USB or a physical device. Instruction counts and emulator wall time
are not MCU cycle counts; painted-stack use excludes interrupts and drivers.
"""
import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import subprocess
import sys
import time

from elftools.elf.elffile import ELFFile
import unicorn
from unicorn import Uc, UcError
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_SP

import run as primitive_run

HERE = Path(__file__).resolve().parent
FLASH_START, FLASH_SIZE = 0x08060000, 0xA0000
RAM_START, RAM_SIZE = 0x20000000, 0x20000
STACK_SENTINEL = 0xA7


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vectors", type=Path, required=True,
                        help="Generated interop_vectors.h, containing public test data only")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--arm-prefix", required=True)
    parser.add_argument("--max-instructions", type=int, default=2000000000)
    parser.add_argument("--timeout-seconds", type=float, default=300)
    parser.add_argument("--trace-blocks", action="store_true",
                        help="Optional basic-block counts/SP sampling; correctness defaults to no block tracing")
    args = parser.parse_args()
    if args.vectors.name != "interop_vectors.h":
        parser.error("--vectors must be named interop_vectors.h")
    if args.max_instructions <= 0 or args.timeout_seconds <= 0:
        parser.error("instruction and time limits must be positive")
    vectors = args.vectors.resolve()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        parser.error("output directory must be empty")
    cc = args.arm_prefix + "gcc"
    commands = []

    def run(command):
        commands.append([str(x) for x in command])
        proc = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
        with (out / "commands.log").open("a") as log:
            log.write(json.dumps(commands[-1]) + "\n" + proc.stdout + "\n")
        if proc.returncode:
            raise RuntimeError(f"command failed: {command[0]}\n{proc.stdout}")
        return proc.stdout

    flags = ["-std=gnu99", "-Os", "-DNDEBUG", "-mthumb", "-mcpu=cortex-m3",
             "-msoft-float", "-fno-common", "-ffunction-sections",
             "-fdata-sections", "-fstack-usage", "-fstack-protector-strong",
             *[f"-D{value}" for value in primitive_run.DEFINES], "-DUSE_MONERO=1",
             "-DMONERO_ARM=1",
             "-I", str(primitive_run.CRYPTO), "-I", str(vectors.parent)]
    sources = [primitive_run.CRYPTO / source
               for source in primitive_run.COMMON + primitive_run.MONERO]
    sources += [HERE / "interoperability.c", HERE / "arm-startup.S"]
    objects = []
    for index, source in enumerate(sources):
        obj = out / f"{index}-{source.stem}.o"
        run([cc, *flags, "-c", str(source), "-o", str(obj)])
        objects.append(obj)
    elf_path = out / "interoperability.elf"
    run([cc, "-mthumb", "-mcpu=cortex-m3", "-msoft-float", "-nostartfiles",
         "--specs=nosys.specs", "-Wl,--gc-sections", "-T", str(HERE / "arm.ld"),
         f"-Wl,-Map={out / 'interoperability.map'}", *map(str, objects),
         "-o", str(elf_path)])
    symbols = run([args.arm_prefix + "nm", "-S", str(elf_path)])
    (out / "symbols.txt").write_text(symbols)
    symbols_by_name = {}
    with elf_path.open("rb") as stream:
        elf = ELFFile(stream)
        for entry in elf.get_section_by_name(".symtab").iter_symbols():
            symbols_by_name[entry.name] = int(entry["st_value"])
        uc = Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_THUMB | unicorn.UC_MODE_MCLASS)
        uc.mem_map(FLASH_START, FLASH_SIZE, unicorn.UC_PROT_ALL)
        uc.mem_map(RAM_START, RAM_SIZE, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
        for segment in elf.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue
            address = int(segment["p_vaddr"])
            length = int(segment["p_memsz"])
            if not ((FLASH_START <= address and address + length <= FLASH_START + FLASH_SIZE)
                    or (RAM_START <= address and address + length <= RAM_START + RAM_SIZE)):
                raise RuntimeError("ELF segment falls outside the research flash/SRAM map")
            uc.mem_write(address, segment.data())
        uc.mem_protect(FLASH_START, FLASH_SIZE, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)

    def required(name):
        if name not in symbols_by_name:
            raise RuntimeError(f"missing harness symbol {name}")
        return symbols_by_name[name]

    start = required("monero_arm_start")
    done = required("monero_arm_done") & ~1
    stack_top, static_end = required("_stack"), required("_ebss")
    if not RAM_START <= static_end < stack_top <= RAM_START + RAM_SIZE:
        raise RuntimeError("invalid stack paint range")
    uc.mem_write(static_end, bytes([STACK_SENTINEL]) * (stack_top - static_end))
    # The usual reset handler is absent. Initialize newlib's test canary here.
    if "__stack_chk_guard" in symbols_by_name:
        uc.mem_write(symbols_by_name["__stack_chk_guard"], (0xA5B6C7D8).to_bytes(4, "little"))
    uc.reg_write(UC_ARM_REG_SP, stack_top)
    state = {"reached_done": False, "instructions": 0, "blocks": 0,
             "min_sp_at_block_entry": stack_top, "lowest_stack_write": stack_top,
             "traps": []}
    block_counts = {}
    # Thumb instruction width is encoded by the first halfword. A top-five-bit
    # value of 11101, 11110 or 11111 denotes a 32-bit Thumb-2 instruction.
    def block_hook(machine, address, size, _user):
        if address == done:
            state["reached_done"] = True
            machine.emu_stop()
            return
        sp = machine.reg_read(UC_ARM_REG_SP)
        if not static_end <= sp <= stack_top:
            state["traps"].append({"kind": "stack_pointer_outside_painted_reserve",
                                   "sp": hex(sp), "pc": hex(address)})
            machine.emu_stop()
            return
        state["min_sp_at_block_entry"] = min(state["min_sp_at_block_entry"], sp)
        key = (address, size)
        if key not in block_counts:
            code = bytes(machine.mem_read(address, size))
            offset, count = 0, 0
            while offset < len(code):
                halfword = int.from_bytes(code[offset:offset + 2], "little")
                offset += 4 if halfword >> 11 in [0b11101, 0b11110, 0b11111] else 2
                count += 1
            if offset != len(code):
                raise RuntimeError("translation block splits a Thumb instruction")
            block_counts[key] = count
        state["instructions"] += block_counts[key]
        state["blocks"] += 1

    def invalid_memory_hook(machine, access, address, size, _value, _user):
        state["traps"].append({"kind": "unmapped_or_protected_memory", "access": access,
                               "address": hex(address), "size": size,
                               "pc": hex(machine.reg_read(UC_ARM_REG_PC))})
        return False

    traps = {symbols_by_name[name] & ~1: name for name in
             ["__stack_chk_fail", "abort", "random_buffer", "xmr_random_scalar", "exit", "_exit"]
             if name in symbols_by_name}

    def forbidden_call_hook(machine, address, _size, _user):
        state["traps"].append({"kind": "forbidden_call", "function": traps[address]})
        machine.emu_stop()

    if args.trace_blocks:
        uc.hook_add(unicorn.UC_HOOK_BLOCK, block_hook)
    uc.hook_add(unicorn.UC_HOOK_MEM_INVALID, invalid_memory_hook)
    for address in traps:
        uc.hook_add(unicorn.UC_HOOK_CODE, forbidden_call_hook, begin=address, end=address)
    # Unicorn 2.1.4's ARM backend changed a uint64 varint result when a memory
    # write hook was registered, even with an empty callback. Never use write
    # hooks here. Read the painted stack only after execution has stopped.
    began = time.monotonic()
    emulator_error = None
    try:
        uc.emu_start(start | 1, done, timeout=int(args.timeout_seconds * 1000000),
                     count=args.max_instructions)
    except UcError as error:
        emulator_error = str(error)
    elapsed = time.monotonic() - began
    state["reached_done"] = (uc.reg_read(UC_ARM_REG_PC) & ~1) == done

    def read_word(name):
        return int.from_bytes(uc.mem_read(required(name), 4), "little")

    paint = bytes(uc.mem_read(static_end, stack_top - static_end))
    touched = next((offset for offset, value in enumerate(paint)
                    if value != STACK_SENTINEL), len(paint))
    high_water = len(paint) - touched
    checks, fail_line = read_word("monero_checks"), read_word("monero_fail_line")
    result_code = read_word("monero_arm_result")
    passed = (state["reached_done"] and result_code == 0 and checks > 0
              and fail_line == 0 and not state["traps"] and emulator_error is None)
    frames = []
    for su in out.glob("*.su"):
        for line in su.read_text().splitlines():
            loc, count, kind = line.rsplit("\t", 2)
            name = loc.rsplit(":", 1)[-1]
            if name in symbols_by_name:
                frames.append({"function": name, "bytes": int(count), "kind": kind})
    frames.sort(key=lambda frame: frame["bytes"], reverse=True)
    report = {
        "schema_version": 1, "status": "pass" if passed else "fail",
        "execution": "Unicorn Cortex-M3/Thumb instruction emulation; no physical device",
        "emulator_version": importlib.metadata.version("unicorn"),
        "pyelftools_version": importlib.metadata.version("pyelftools"),
        "compiler": run([cc, "--version"]).splitlines()[0],
        "checks": checks, "fail_line": fail_line, "result_code": result_code,
        "last_phase": read_word("monero_phase") if "monero_phase" in symbols_by_name else None,
        "boundary_diagnostics": {name: read_word(name) for name in
                                 ["monero_boundary_index", "monero_boundary_need", "monero_boundary_written"]
                                 if name in symbols_by_name},
        "reached_done": state["reached_done"],
        "instruction_count": state["instructions"] if args.trace_blocks else None,
        "instruction_count_method": "sum decoded Thumb instructions at translation-block entries on completed runs; includes predicated instructions in entered blocks",
        "basic_blocks": state["blocks"] if args.trace_blocks else None,
        "trace_blocks": args.trace_blocks, "memory_write_hooks_enabled": False,
        "emulator_wall_seconds": elapsed,
        "instruction_limit": args.max_instructions, "timeout_seconds": args.timeout_seconds,
        "stack": {
            "initial_sp": hex(stack_top), "static_end": hex(static_end),
            "painted_bytes": len(paint), "sentinel_byte": STACK_SENTINEL,
            "paint_high_water_bytes": high_water,
            "min_sp_at_block_entry": hex(state["min_sp_at_block_entry"]) if args.trace_blocks else None,
            "sp_depth_at_block_entry_bytes": (stack_top - state["min_sp_at_block_entry"])
                                             if args.trace_blocks else None,
            "largest_retained_compiled_frames": frames[:10],
            "limits": "test harness only; excludes interrupts, USB, firmware callers and hardware timing",
        },
        "traps": state["traps"], "emulator_error": emulator_error,
        "hardware_cycles": None, "physical_device_accessed": False,
        "production_ready": False,
        "input_sha256": {str(source): hashlib.sha256(source.read_bytes()).hexdigest()
                         for source in sorted(set([*sources, vectors, HERE / "arm.ld",
                             Path(__file__), HERE / "run.py", *primitive_run.CRYPTO.rglob("*.h")]))},
        "elf_sha256": hashlib.sha256(elf_path.read_bytes()).hexdigest(),
    }
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ["status", "checks", "fail_line",
                     "instruction_count", "emulator_wall_seconds", "stack", "traps"]}, indent=2))
    if not passed:
        raise RuntimeError(f"ARM interoperability execution failed; see {out / 'result.json'}")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
