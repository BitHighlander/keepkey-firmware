"""Exercise the release-evidence gate with complete and corrupted inputs."""

import importlib.util
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET


SPEC = importlib.util.spec_from_file_location(
    "report", Path(__file__).with_name("generate-test-report.py"))
report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(report)


class ContractEvidence(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.paths = []
        for variant, directory in report.CONTRACT_JUNIT_DIRS.items():
            for filename, variants in report.CONTRACT_JUNIT.items():
                path = self.root / directory / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                suite = ET.Element("testsuite")
                for name, status in variants[variant].items():
                    classname, method = name.rsplit(".", 1)
                    case = ET.SubElement(suite, "testcase", {
                        "classname": classname, "name": method})
                    if status == "skip":
                        ET.SubElement(case, "skipped")
                ET.ElementTree(suite).write(path)
                self.paths.append(path)

    def test_complete_variant_contracts_pass(self):
        evidence = report.validate_contract_junit(self.root)
        self.assertEqual(len(self.paths), len(evidence))
        self.assertEqual({"full", "bitcoin-only"},
                         {item["variant"] for item in evidence})

    def test_each_missing_contract_file_is_refused(self):
        for path in self.paths:
            with self.subTest(path=path):
                original = path.read_bytes()
                path.unlink()
                with self.assertRaisesRegex(RuntimeError, "JUnit missing"):
                    report.validate_contract_junit(self.root)
                path.write_bytes(original)

    def test_removed_failed_or_wrong_variant_case_is_refused(self):
        for path in self.paths:
            original = path.read_bytes()
            for mutation in ("remove", "failure", "invert", "duplicate"):
                with self.subTest(path=path, mutation=mutation):
                    tree = ET.parse(path)
                    suite = tree.getroot()
                    case = suite[0]
                    if mutation == "remove":
                        suite.remove(case)
                    elif mutation == "failure":
                        ET.SubElement(case, "failure")
                    elif mutation == "duplicate":
                        suite.append(ET.fromstring(ET.tostring(case)))
                    elif case.find("skipped") is None:
                        ET.SubElement(case, "skipped")
                    else:
                        case.remove(case.find("skipped"))
                    tree.write(path)
                    with self.assertRaises(RuntimeError):
                        report.validate_contract_junit(self.root)
                    path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
