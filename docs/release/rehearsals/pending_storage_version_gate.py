#!/usr/bin/env python3
"""Check active/pending Bitcoin-only version refusal and supported recovery.

Usage: pending_storage_version_gate.py FIRMWARE_CHECKOUT BUILD_DIRECTORY
Uses only an owned emulator with a fixed test wallet and isolated flash images.
"""
import os
import signal
import sys
import unittest
from pathlib import Path

if len(sys.argv) != 3:
    raise SystemExit(__doc__)
root = Path(sys.argv[1]).resolve()
os.environ.update(KK_FORCE_UDP='1', KK_FIRMWARE_ROOT=str(root),
                  KK_EMULATOR_BIN=str(root / sys.argv[2] / 'bin/kkemu'))
sys.path[:0] = [str(root / 'deps/python-keepkey/tests'), str(root / 'deps/python-keepkey')]
from test_storage_version_gate import (TestStorageUpgradePreservation, OFF_VERSION,
                                      SECTOR_OFFSETS, BIP44_ADDRESS_N, PIN,
                                      _define, _read_source)
import keepkeylib
assert Path(keepkeylib.__file__).resolve().is_relative_to(root / 'deps/python-keepkey')
VERSION = _define(_read_source('include/keepkey/firmware/storage.h'), 'STORAGE_VERSION')
BAND = _define(_read_source('include/keepkey/firmware/storage.h'), 'STORAGE_VERSION_BTC_ONLY_BASE')


def check_record(self, version, pending, legacy=False, expect_locked=True):
    address, off = self._create_wallet()
    original = self.emu.image()[off:off + 2580]
    self.emu.write_u32(off, OFF_VERSION, version)
    if pending:
        # Leave the CRC for eventual 'stor' intact, matching the real handoff.
        with open(self.emu.img, 'r+b') as image:
            image.seek(off)
            image.write(b'\xff' * 4)
            if legacy:
                legacy_off = SECTOR_OFFSETS[(SECTOR_OFFSETS.index(off) + 1) % 3]
                record = bytearray(original)
                record[2572:2580] = b'\xff' * 8
                image.seek(legacy_off)
                image.write(record)
    before = self.emu.image()
    device_id = before[off + 16:off + 40].decode('ascii')
    self.emu.boot()
    client = self.emu.client(self.method, pin=PIN)
    try:
        client.init_device()
        self.assertEqual(not expect_locked, client.features.initialized)
        self.assertEqual(device_id, client.features.device_id)
        if not expect_locked:
            self.assertEqual(address, client.get_address('Bitcoin', BIP44_ADDRESS_N))
    finally:
        client.close()
        self.emu.halt()
    if expect_locked:
        after = self.emu.image()
        changed = [i for i, (a, b) in enumerate(zip(before, after)) if a != b]
        self.assertEqual([], changed, 'refused version mutated flash')
    elif pending:
        # PIN authentication can legitimately commit and rotate the active
        # sector after recovery; the wallet/address checks above must survive.
        self.assertIsNotNone(self.emu.active_sector())


def make_refusal(version, pending, legacy=False):
    def case(self):
        check_record(self, version, pending, legacy)
    return case


def supported_recovery(self):
    check_record(self, VERSION, True, expect_locked=False)


def current_band(self):
    # Determine the actual variant, then exercise its current-band contract.
    self._create_wallet()
    check_record(self, BAND + VERSION, True, expect_locked=not self.bitcoin_only)


cases = {}
for version in (BAND + VERSION + 1, 0x7fffffff, 0x80000000, 0xffffffff):
    for pending in (False, True):
        cases[f'test_{version:08x}_' + ('pending' if pending else 'active')] = make_refusal(version, pending)
cases['test_future_pending_over_legacy'] = make_refusal(BAND + VERSION + 1, True, True)
cases['test_supported_pending_recovers'] = supported_recovery
cases['test_current_band_pending'] = current_band
# Inherit only the fixture helpers; explicitly select this bounded matrix.
for name, case in cases.items():
    setattr(TestStorageUpgradePreservation, name, case)


def timeout(*_):
    raise TimeoutError('pending-version rehearsal exceeded two minutes')


signal.signal(signal.SIGALRM, timeout)
signal.alarm(120)
suite = unittest.TestSuite(TestStorageUpgradePreservation(name) for name in cases)
result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() and not result.skipped else 1)
