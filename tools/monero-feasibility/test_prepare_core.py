#!/usr/bin/env python3
"""Safety and repeatability tests for public source archive preparation."""
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from prepare_core import extract_regular


def archive(path, entries):
    with tarfile.open(path, "w:gz") as output:
        for name, data, kind in entries:
            info = tarfile.TarInfo(name)
            if kind == "link":
                info.type, info.linkname = tarfile.SYMTYPE, "../../outside"
                output.addfile(info)
            else:
                info.size, info.mode = len(data), 0o755 if kind == "script" else 0o644
                output.addfile(info, io.BytesIO(data))


class PublicCoreSources(unittest.TestCase):
    def test_regular_files_and_executable_modes_match_pinned_tree_layout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); item = root / "source.tar.gz"; out = root / "source"
            archive(item, [("release/include/public.h", b"public data", "file"),
                           ("release/tools/check.sh", b"#!/bin/sh\nexit 0\n", "script"),
                           ("release/ignored-link", b"", "link")])
            self.assertEqual(extract_regular(item, out, "external/dependency"), 2)
            target = out / "external/dependency"
            self.assertEqual((target / "include/public.h").read_bytes(), b"public data")
            self.assertEqual((target / "tools/check.sh").stat().st_mode & 0o777, 0o755)
            self.assertFalse((target / "ignored-link").exists())
            self.assertEqual(extract_regular(item, out, "external/dependency"), 2)

    def test_traversal_and_existing_different_sources_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); item = root / "source.tar.gz"; out = root / "source"
            archive(item, [("release/../../outside", b"public data", "file")])
            with self.assertRaisesRegex(ValueError, "Unsafe"):
                extract_regular(item, out, "")
            archive(item, [("release/public.h", b"first", "file")])
            extract_regular(item, out, "")
            archive(item, [("release/public.h", b"different", "file")])
            with self.assertRaisesRegex(ValueError, "differs"):
                extract_regular(item, out, "")
            self.assertEqual((out / "public.h").read_bytes(), b"first")

    def test_duplicate_archive_paths_cannot_overwrite_verified_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); item = root / "source.tar.gz"
            archive(item, [("release/public.h", b"first", "file"),
                           ("release/public.h", b"second", "file")])
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                extract_regular(item, root / "source", "")


if __name__ == "__main__":
    unittest.main()
