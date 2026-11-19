"""Regression checks for the stack-usage acceptance gate."""

import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from check_sram_budget import largest_frames


class StackUsageRecords(unittest.TestCase):
    def parse(self, record):
        data = record.encode("utf-8")
        with tempfile.NamedTemporaryFile(suffix=".tar") as archive:
            with tarfile.open(fileobj=archive, mode="w") as tar:
                info = tarfile.TarInfo("firmware/example.su")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            archive.flush()
            return largest_frames(archive.name)

    def test_static_frame_is_measured(self):
        self.assertEqual(
            [(128, "example.c:4:2:sign", "static")],
            self.parse("example.c:4:2:sign\t128\tstatic\n"),
        )

    def test_dynamic_frame_cannot_pass_the_gate(self):
        with self.assertRaisesRegex(SystemExit, "dynamic stack frame"):
            self.parse("example.c:4:2:sign\t128\tdynamic\n")

    def test_bounded_dynamic_frame_uses_compiler_maximum(self):
        self.assertEqual(
            [(128, "example.c:4:2:sign", "dynamic,bounded")],
            self.parse("example.c:4:2:sign\t128\tdynamic,bounded\n"),
        )

    def test_lto_requires_every_linked_partition(self):
        linked = "lto-su/firmware.keepkey.elf.ABC123.ltrans"
        with tempfile.TemporaryDirectory() as directory:
            link_map = Path(directory) / "firmware.map"
            archive = Path(directory) / "stack-usage.tgz"
            link_map.write_text("".join(
                f"LOAD /build/{linked}{i}.ltrans.o\n" for i in (0, 1)
            ))
            records = {
                "unrelated.su": b"other.c:1:1:other\t96\tstatic\n",
                f"./{linked}0.ltrans.su": b"example.c:1:1:first\t128\tstatic\n",
            }
            second = f"./{linked}1.ltrans.su"
            for report, valid in (
                (None, False),
                (b"", False),
                (b"no frame here\n", False),
                (b"x.c:2:1:second\t256\tstatic\n", True),
            ):
                if report is not None:
                    records[second] = report
                with tarfile.open(archive, "w:gz") as tar:
                    for name, data in records.items():
                        info = tarfile.TarInfo(name)
                        info.size = len(data)
                        tar.addfile(info, io.BytesIO(data))
                if valid:
                    self.assertEqual(largest_frames(archive, lto_map=link_map)[0][0], 256)
                else:
                    with self.assertRaisesRegex(SystemExit, "ltrans1.ltrans.su"):
                        largest_frames(archive, lto_map=link_map)
            link_map.write_text("LOAD /build/unrelated.o\n")
            with self.assertRaisesRegex(SystemExit, "no firmware LTO partitions"):
                largest_frames(archive, lto_map=link_map)


if __name__ == "__main__":
    unittest.main()
