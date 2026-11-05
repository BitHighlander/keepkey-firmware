#!/usr/bin/env python3
"""Public fake-frame regressions for the report's complete pixel evidence invariant."""
import ctypes
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_wire as wire


class FrameRing:
    def __init__(self, frames):
        self.frames = list(frames)

    def kkemu_pop_frame(self, destination):
        if not self.frames:
            return 0
        frame = self.frames.pop(0)
        ctypes.memmove(destination, frame, len(frame))
        return 1


def session(path, frames):
    value = wire.Session.__new__(wire.Session)
    value.out, value.label = Path(path), "public-frame-fixture"
    value.frames, value.frame_hashes = [], set()
    value.lib = FrameRing(frames)
    return value


def frame(index):
    return index.to_bytes(4, "little") + bytes(2044)


class ScreenCaptureEvidence(unittest.TestCase):
    def test_every_hash_has_saved_pixels_beyond_the_old_128_frame_limit(self):
        frames = [frame(index) for index in range(130)]
        with tempfile.TemporaryDirectory() as temporary:
            value = session(temporary, frames + [frames[1]])
            while value.lib.frames:
                value.capture("transaction-review")
            self.assertEqual(len(value.frames), 130)
            self.assertEqual(len(value.frame_hashes), 130)
            for expected, captured in zip(frames, value.frames):
                self.assertEqual((value.out / captured["raw_path"]).read_bytes(), expected)
                self.assertEqual(captured["sha256"], hashlib.sha256(expected).hexdigest())
                image = (value.out / captured["path"]).read_bytes()
                self.assertTrue(image.startswith(b"P5\n256 64\n255\n"))
                self.assertEqual(len(image), len(b"P5\n256 64\n255\n") + 256 * 64)
            # Raw bit zero is the top-left white OLED pixel; its neighbor stays black.
            image = (value.out / value.frames[1]["path"]).read_bytes()[len(b"P5\n256 64\n255\n"):]
            self.assertEqual(image[:2], bytes([255, 0]))

    def test_bound_is_a_failure_instead_of_a_pass_with_missing_screens(self):
        with tempfile.TemporaryDirectory() as temporary:
            value = session(temporary, [frame(1), frame(2), frame(3)])
            with patch.object(wire, "MAX_UNIQUE_CAPTURED_FRAMES", 2):
                with self.assertRaisesRegex(RuntimeError, "cannot be reported as complete"):
                    value.capture("transaction-review")
            self.assertEqual(len(value.frames), 2)
            self.assertEqual(len(value.frame_hashes), 2)
            self.assertEqual(len(list(value.out.glob("*.bin"))), 2)
            self.assertEqual(len(list(value.out.glob("*.pgm"))), 2)


if __name__ == "__main__":
    unittest.main()
