#!/usr/bin/env python3
"""Replay fixed-wallet flash snapshots through released bootloader 2.1.4 ARM code.

Requires unicorn==2.1.4. Input is the 262144-byte payload extracted at offset
0x3204 from upstream v7.3.2 blupdater.bin, verified by the firmware's recognized
double-SHA256. No hardware is accessed and no input files are modified.

The binary's storage_protect_status (0x0802363c), its real selector/marker compare,
and storage_protect_wipe (0x080236ac) execute in Unicorn. Only the lowest-level
flash_erase_word call is intercepted to record which sectors would be erased.
This tests the released decision logic, not reset/startup, MMIO or erase physics.
"""
import argparse
import hashlib
import json
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_R0, UC_ARM_REG_PC

RECOGNIZED_HASH = 'fe98454e7ebd4aef4a6db5bd4c60f52cf3f58b974283a7c1e1fcc5fea02cf3eb'
FLASH_BASE = 0x08000000
FLASH_SIZE = 0x100000
STORAGE_OFFSETS = (0x4000, 0x8000, 0xc000)
OFF_MARKER = bytes.fromhex('31884eb8482a2809e37461d96ad7f0ed8cdd7ca6073e686a15c089c6118995a0') + b'\0'
DISABLED = 0x5ac35ac3
RETURN_PC = 0x080f0000


class Bootloader:
    def __init__(self, payload):
        digest = hashlib.sha256(hashlib.sha256(payload).digest()).hexdigest()
        if len(payload) != 262144 or digest != RECOGNIZED_HASH:
            raise ValueError('input is not the recognized released 2.1.4 bootloader')
        self.mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.mu.mem_map(FLASH_BASE, FLASH_SIZE)
        self.mu.mem_map(0x20000000, 0x20000)
        self.mu.mem_write(FLASH_BASE, b'\xff' * FLASH_SIZE)
        self.mu.mem_write(0x08020000, payload)
        self.erases = []
        self.mu.hook_add(UC_HOOK_CODE, self._erase, begin=0x08022790, end=0x08022790)

    def _erase(self, mu, address, size, data):
        self.erases.append(mu.reg_read(UC_ARM_REG_R0))
        mu.reg_write(UC_ARM_REG_PC, mu.reg_read(UC_ARM_REG_LR))

    def _call(self, address, argument=0):
        self.mu.reg_write(UC_ARM_REG_SP, 0x2001f000)
        self.mu.reg_write(UC_ARM_REG_LR, RETURN_PC | 1)
        self.mu.reg_write(UC_ARM_REG_R0, argument)
        self.mu.emu_start(address | 1, RETURN_PC, timeout=1000000, count=100000)
        if self.mu.reg_read(UC_ARM_REG_PC) != RETURN_PC:
            raise RuntimeError('bootloader routine did not return within its execution budget')
        return self.mu.reg_read(UC_ARM_REG_R0)

    def check(self, image):
        if len(image) != FLASH_SIZE:
            raise ValueError('snapshot must contain the complete 1 MiB emulated flash')
        storage = bytes(image[0x4000:0x10000])
        self.mu.mem_write(FLASH_BASE + 0x4000, storage)
        self.erases.clear()
        status = self._call(0x0802363c)
        self._call(0x080236ac, status)
        if bytes(self.mu.mem_read(FLASH_BASE + 0x4000, len(storage))) != storage:
            raise AssertionError('decision routines unexpectedly mutated storage')
        return status, list(self.erases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bootloader', type=Path)
    parser.add_argument('snapshots', type=Path)
    args = parser.parse_args()
    boot = Bootloader(args.bootloader.read_bytes())
    controls = 0
    erased = bytearray(b'\xff' * FLASH_SIZE)
    if boot.check(erased) != (DISABLED, []):
        raise AssertionError('factory-empty control failed')
    controls += 1
    for i, offset in enumerate(STORAGE_OFFSETS):
        image = erased.copy()
        image[offset:offset + 4] = b'stor'
        marker = STORAGE_OFFSETS[(i + 1) % 3]
        if boot.check(image) != (0, [2, 3, 4]):
            raise AssertionError('missing-marker rejection control failed')
        controls += 1
        image[marker:marker + len(OFF_MARKER)] = OFF_MARKER
        if boot.check(image) != (DISABLED, []):
            raise AssertionError('valid-marker control failed')
        controls += 1
        # Every marker bit matters, including the C string terminator.
        for byte in range(len(OFF_MARKER)):
            for bit in range(8):
                image[marker + byte] ^= 1 << bit
                if boot.check(image) != (0, [2, 3, 4]):
                    raise AssertionError(f'corrupt-marker control failed: {i}/{byte}/{bit}')
                image[marker + byte] ^= 1 << bit
                controls += 1
    expected = {f'commit-{i}.bin' for i in range(17)}
    paths = list(args.snapshots.glob('commit-*.bin'))
    if {p.name for p in paths} != expected:
        raise ValueError('expected exactly the 17 actual-commit replay images')
    receipts = []
    for path in sorted(paths, key=lambda p: int(p.stem.split('-')[1])):
        image = path.read_bytes()
        if boot.check(image) != (DISABLED, []):
            raise AssertionError(f'released bootloader would erase {path.name}')
        receipts.append({'file': path.name, 'sha256': hashlib.sha256(image).hexdigest()})
    print(json.dumps({'bootloader_double_sha256': RECOGNIZED_HASH,
                      'controls_passed': controls, 'snapshots_passed': len(receipts),
                      'snapshots': receipts,
                      'scope': 'released 2.1.4 decision routines; no physical erase or complete boot'}, indent=2))


if __name__ == '__main__':
    main()
