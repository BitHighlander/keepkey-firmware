"""Rehearse migration of CRC-framed storage; update framing after fixture edits."""
import os, sys, signal, struct, unittest
from pathlib import Path
if len(sys.argv) != 3:
    raise SystemExit("usage: framed_storage_migration.py CHECKOUT BUILD_DIRECTORY")
root = Path(sys.argv[1]).resolve()
os.environ["KK_FORCE_UDP"] = "1"
os.environ["KK_FIRMWARE_ROOT"] = str(root)
os.environ["KK_EMULATOR_BIN"] = str(root / sys.argv[2] / "bin/kkemu")
sys.path[:0] = [str(root / "deps/python-keepkey/tests"), str(root / "deps/python-keepkey")]
def timeout(signum, frame):
    raise TimeoutError("framed storage rehearsal exceeded 60 seconds")
signal.signal(signal.SIGALRM, timeout)
signal.alarm(60)
from test_storage_version_gate import Emulator, TestStorageUpgradePreservation, OFF_VERSION
original_patch = Emulator.patch
def framed_patch(self, off, rel, data):
    original_patch(self, off, rel, data)
    image = self.image()
    if image[off + 2572:off + 2576] != b"crc1":
        raise AssertionError("fixture must originate from a CRC-framed record")
    crc = 0xffffffff
    for (word,) in struct.iter_unpack("<I", image[off:off + 2572]):
        crc ^= word
        for _ in range(32):
            crc = ((crc << 1) ^ (0x04c11db7 if crc & 0x80000000 else 0)) & 0xffffffff
    original_patch(self, off, 2576, struct.pack("<I", crc))
Emulator.patch = framed_patch
original_v16 = TestStorageUpgradePreservation._make_v16_blob
def legacy_v16(self, off):
    original_v16(self, off)
    # Legacy writers leave metadata padding zero and the trailer erased.
    original_patch(self.emu, off, 41, b"\x00" * 3)
    original_patch(self.emu, off, 2572, b"\xff" * 8)
def test_legacy_v16(self):
    self._make_v16_blob = lambda off: legacy_v16(self, off)
    self.test_v16_blob_upgrades_without_wiping()
TestStorageUpgradePreservation.test_unframed_v16_migration = test_legacy_v16
def test_future_record(self):
    _, off = self._create_wallet()
    self.emu.write_u32(off, OFF_VERSION, self.emu.read_u32(off, OFF_VERSION) + 1)
    before = self.emu.image()
    self.emu.boot()
    client = self.emu.client(self.method)
    try:
        client.init_device()
        self.assertFalse(client.features.initialized)
    finally:
        client.close()
        self.emu.halt()
    if self.bitcoin_only:
        self.assertEqual(before, self.emu.image())
    else:
        self.assertNotEqual(before, self.emu.image())
TestStorageUpgradePreservation.test_valid_framed_future_version = test_future_record
names = [
    "test_valid_framed_future_version",
    "test_reboot_preserves_the_wallet",
    "test_v16_blob_upgrades_without_wiping",
    "test_unframed_v16_migration",
    "test_bitcoin_only_band_refuses_without_wiping",
]
if os.environ.get("KK_TEST_BAND", "1") == "0":
    names.remove("test_bitcoin_only_band_refuses_without_wiping")
suite = unittest.TestSuite(TestStorageUpgradePreservation(name) for name in names)
result = unittest.TextTestRunner(verbosity=2).run(suite)
if not result.wasSuccessful() or result.skipped:
    raise SystemExit(1)
