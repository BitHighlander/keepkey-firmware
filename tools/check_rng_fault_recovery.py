#!/usr/bin/env python3
"""Run the actual device RNG provider against simulated STM32 registers.

Only register access and ARM nop/wfi are substituted. No emulator RNG path or
copy of the recovery algorithm is used. RM0033 section 20.3.1 requires restarting
RNGEN after seed errors and discarding the first word after RNGEN is set.
"""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define RNG_CR_RNGEN 4u
#define RNG_CR_IE 8u
#define RNG_SR_DRDY 1u
#define RNG_SR_CECS 2u
#define RNG_SR_SECS 4u
#define RNG_SR_CEIS 32u
#define RNG_SR_SEIS 64u
static uint32_t sr, cr = RNG_CR_RNGEN | RNG_CR_IE;
static unsigned polls, reads, stops, starts;
static bool was_enabled = true;
static void observe_control(void) {
  bool enabled = (cr & RNG_CR_RNGEN) != 0;
  if (was_enabled && !enabled) ++stops;
  if (!was_enabled && enabled) ++starts;
  was_enabled = enabled;
}
static uint32_t* control_register(void) {
  observe_control();
  return &cr;
}
static bool delayed, recurring, persistent;
static uint32_t* status_register(void) {
  observe_control();
  ++polls;
  if (recurring) sr |= RNG_SR_SEIS;
  if (persistent) sr |= RNG_SR_SECS;
  // More than reset_rng's 2000 status polls: exercise deferred discard too.
  if (delayed && polls > 2100) sr |= RNG_SR_DRDY;
  return &sr;
}
static uint32_t data_register(void) {
  observe_control();
  ++reads;
  if (reads > 2) { fputs("unexpected extra RNG read\n", stderr); exit(2); }
  return reads == 1 ? 0xdeadbeefu : 0x12345678u;
}
static void arm_instruction(const char* instruction) {
  if (strcmp(instruction, "wfi") == 0) {
    if (!(recurring || persistent) || reads > 3 || stops != 3 || starts != 3) exit(3);
    // Expected fail-closed halt after the bounded reset budget.
    exit(77);
  }
}
#define RNG_SR (*status_register())
#define RNG_CR (*control_register())
#define RNG_DR data_register()
#define __asm__(instruction) arm_instruction(instruction)
#include "rng-under-test.c"
uint32_t random_uniform(uint32_t n) { (void)n; return 0; }
int main(int argc, char** argv) {
  if (argc != 2) return 4;
  delayed = strcmp(argv[1], "delayed") == 0;
  recurring = strcmp(argv[1], "recurring") == 0;
  persistent = strcmp(argv[1], "persistent") == 0;
  sr = strcmp(argv[1], "clock") == 0 ? RNG_SR_CEIS : RNG_SR_SEIS;
  if (!delayed && !recurring && !persistent) sr |= RNG_SR_DRDY;
  uint32_t result = random32();
  if (recurring || persistent) return 5;
  if (result != 0x12345678u || reads != 2 || stops != 1 || starts != 1 ||
      !rng_seed_error_latched()) {
    fprintf(stderr, "fault word escaped: %08x reads=%u latch=%d\n",
            result, reads, rng_seed_error_latched());
    return 6;
  }
  return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / "lib/rand/rng.c")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="keepkey-rng-registers-") as directory:
        temporary = Path(directory)
        for name in ("libopencm3/cm3/common.h", "libopencm3/stm32/memorymap.h",
                     "libopencm3/stm32/f2/rng.h"):
            header = temporary / name
            header.parent.mkdir(parents=True, exist_ok=True)
            header.write_text("/* Registers supplied by harness. */\n")
        (temporary / "trezor/crypto").mkdir(parents=True)
        (temporary / "trezor/crypto/rand.h").write_text(
            (ROOT / "deps/crypto/trezor-firmware/crypto/rand.h").read_text())
        (temporary / "rng-under-test.c").write_text(args.source.read_text())
        (temporary / "harness.c").write_text(HARNESS)
        executable = temporary / "rng-register-test"
        subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
            "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-O2",
            "-DRAND_PLATFORM_INDEPENDENT", "-I", str(temporary),
            "-I", str(ROOT / "include"), str(temporary / "harness.c"),
            "-o", str(executable)], check=True)
        failures = []
        for scenario in ("seed", "clock", "delayed", "recurring", "persistent"):
            expected = 77 if scenario in ("recurring", "persistent") else 0
            try:
                result = subprocess.run([str(executable), scenario], timeout=5)
                passed = result.returncode == expected
            except subprocess.TimeoutExpired:
                passed = False
            if not passed:
                failures.append(scenario)
            print("{}: {}".format(scenario, "PASS" if passed else "FAIL"), flush=True)
        if failures:
            raise SystemExit("RNG recovery failures: " + ", ".join(failures))


if __name__ == "__main__":
    main()
