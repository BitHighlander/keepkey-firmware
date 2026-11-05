import importlib.util
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

spec = importlib.util.spec_from_file_location("resume_compatibility", Path(__file__).with_name("resume_compatibility.py"))
resume = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resume)


class ResumeParserTests(unittest.TestCase):
    def test_typed_parameterized_and_disabled_inventory(self):
        names = resume.parse_listing("Running main() from gmock_main.cc\nTyped/0. # TypeParam = int\n  Works\nParams/Storage.\n  Loads/0 # GetParam() = 16\n  DISABLED_Old/1 # GetParam() = 1\nDISABLED_Suite.\n  Exists\n")
        self.assertEqual(names, ["Typed/0.Works", "Params/Storage.Loads/0", "Params/Storage.DISABLED_Old/1", "DISABLED_Suite.Exists"])
        self.assertEqual([name for name in names if resume.is_disabled(name)], names[2:])

    def test_partial_log_credits_only_completed_cases(self):
        count, passed = resume.parse_passed_log("[==========] Running 3 tests from 1 test case.\n[ RUN      ] Suite.A\n[       OK ] Suite.A (12 ms)\n[ RUN      ] Suite.B\nTimed out after 1200 seconds\n")
        self.assertEqual(count, 3)
        self.assertEqual(passed, {"Suite.A": 12})

    def test_failures_duplicates_and_ambiguous_inventory_are_refused(self):
        prefix = "[==========] Running 2 tests from 1 test case.\n[       OK ] Suite.A (1 ms)\n"
        for suffix in ("[  FAILED  ] Suite.B\n", "file.cpp:42: Failure\n", "unknown file: Failure\n", "[       OK ] Suite.A (2 ms)\n"):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                resume.parse_passed_log(prefix + suffix)
        for listing in ("Suite.\n  A\n  A\n", "Suite.\n  A:*\n", "  A\n"):
            with self.subTest(listing=listing), self.assertRaises(ValueError):
                resume.parse_listing(listing)

    def test_merge_preserves_observed_passes_and_explicit_disabled_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "merged.xml"
            continuation = ET.fromstring('<testcase classname="Suite" name="B" status="run" time="0.023"/>')
            resume.merged_junit(["Suite.A", "Suite.B", "Suite.DISABLED_C"], {"Suite.A": 12},
                                {"Suite.B": (continuation, False)}, path)
            cases = resume.read_junit(path)
            self.assertEqual(set(cases), {"Suite.A", "Suite.B", "Suite.DISABLED_C"})
            self.assertEqual(cases["Suite.A"][0].get("time"), "0.012")
            self.assertEqual(cases["Suite.B"][0].get("time"), "0.023")
            self.assertTrue(cases["Suite.DISABLED_C"][1])
            self.assertEqual(cases["Suite.DISABLED_C"][0].get("status"), "notrun")


if __name__ == "__main__":
    unittest.main()
