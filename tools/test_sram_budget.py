"""Regression checks for the extracted SRAM acceptance gate."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "sram_gate", Path(__file__).with_name("check_sram_budget.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class BudgetGate(unittest.TestCase):
    def test_missing_and_corrupt_archive_report_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "frames.tar"
            with self.assertRaisesRegex(SystemExit, "ERROR: cannot read stack archive"):
                gate.largest_frames(path)
            path.write_bytes(b"not a tar archive")
            with self.assertRaisesRegex(SystemExit, "ERROR: cannot read stack archive"):
                gate.largest_frames(path)

    def test_missing_and_invalid_budgets_report_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "budgets.json"
            args = ["gate", "--elf", "unused", "--su-tar", "unused",
                    "--budgets", str(path), "--variant", "full"]
            with patch("sys.argv", args):
                with self.assertRaisesRegex(SystemExit, "ERROR: cannot read budgets"):
                    gate.main()
                path.write_text("{")
                with self.assertRaisesRegex(SystemExit, "ERROR: cannot read budgets"):
                    gate.main()
                path.write_text("[]")
                with self.assertRaisesRegex(SystemExit, "ERROR: budgets must"):
                    gate.main()

    def test_missing_and_invalid_elf_report_errors(self):
        try:
            import elftools
        except ImportError:
            self.skipTest("ELF parser dependency unavailable")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "firmware.elf"
            with self.assertRaisesRegex(SystemExit, "ERROR: cannot read ELF"):
                gate.read_symbols(path)
            path.write_bytes(b"not an ELF")
            with self.assertRaisesRegex(SystemExit, "ERROR: cannot read ELF"):
                gate.read_symbols(path)

    def run_gate(self, reserve, frames, variant="full"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            budgets = root / "budgets.json"
            budgets.write_text(json.dumps({"reserve_min": 16384,
                                           "frame_margin": 4096,
                                           "variants": {"full": {}}}))
            archive = root / "frames.tgz"
            with tarfile.open(archive, "w:gz") as output:
                data = frames if isinstance(frames, bytes) else frames.encode()
                entry = tarfile.TarInfo("build/firmware.c.su")
                entry.size = len(data)
                output.addfile(entry, io.BytesIO(data))
            args = ["gate", "--elf", "firmware.elf", "--su-tar", str(archive),
                    "--budgets", str(budgets), "--variant", variant]
            with patch.object(gate.sys, "argv", args), patch.object(
                    gate, "read_symbols", return_value={
                        "_ebss": 0x20000000, "_stack": 0x20000000 + reserve
                    }), contextlib.redirect_stdout(io.StringIO()):
                gate.main()

    def test_unknown_variant_fails(self):
        with self.assertRaises(SystemExit):
            self.run_gate(32768, "f.c:1:1:f\t16\tstatic\n", "typo")

    def test_invalid_utf8_fails(self):
        with self.assertRaises(SystemExit):
            self.run_gate(32768, b"\xff\t16\tstatic\n")

    def test_exact_limits_pass(self):
        self.run_gate(16384, "firmware.c:1:1:send\t12288\tstatic\n")

    def test_insufficient_reserve_fails(self):
        with self.assertRaises(SystemExit):
            self.run_gate(16383, "firmware.c:1:1:send\t64\tstatic\n")

    def test_largest_frame_exhausts_margin(self):
        with self.assertRaises(SystemExit):
            self.run_gate(16384, "f.c:1:1:small\t32\tstatic\n"
                          "f.c:2:1:large\t12289\tstatic\n")

    def test_missing_records_fail_closed(self):
        with self.assertRaises(SystemExit):
            self.run_gate(32768, "")

    def test_mixed_valid_and_malformed_records_fail(self):
        with self.assertRaises(SystemExit):
            self.run_gate(32768, "f.c:1:1:small\t16\tstatic\n"
                          "f.c:2:1:large\tunknown\tdynamic\n")

    def test_unbounded_dynamic_frame_fails(self):
        with self.assertRaises(SystemExit):
            self.run_gate(32768, "f.c:1:1:alloca\t16\tdynamic\n")

    def test_bounded_dynamic_frame_passes(self):
        self.run_gate(32768, "f.c:1:1:vla\t128\tdynamic,bounded\n")

    def test_malformed_records_do_not_false_pass(self):
        with self.assertRaises(SystemExit):
            self.run_gate(32768, "f.c:1:1:send\tunknown\tstatic\n")


if __name__ == "__main__":
    unittest.main()
