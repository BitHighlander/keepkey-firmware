"""Exercise the release-evidence gate with complete and corrupted inputs."""

import importlib.util
from pathlib import Path
import tempfile
import unittest
import unittest.mock
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


def skipped(capability):
    return {"status": "skip",
            "skip_reason": report.CAPABILITY_SKIP_PREFIX + capability}


class CapabilityWaivers(unittest.TestCase):
    def setUp(self):
        self.environment = unittest.mock.patch.dict(
            "os.environ", {"KK_RELEASE_MISSING_CAPABILITIES": ""})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_unapproved_environment_cannot_shrink_the_gate(self):
        with unittest.mock.patch.dict(
                "os.environ", {"KK_RELEASE_MISSING_CAPABILITIES": "unapproved"}):
            with self.assertRaisesRegex(RuntimeError, "not in the ci.yml ledger"):
                report.release_missing_capabilities([], approved=set())

    def test_ledger_is_read_from_the_real_workflow(self):
        self.assertIn("osmosis-wire-guards", report.approved_capabilities())

    def test_ledger_must_be_unique(self):
        line = "    KK_RELEASE_MISSING_CAPABILITIES: a,b\n"
        with self.assertRaises(RuntimeError):
            report.approved_capabilities("")
        with self.assertRaises(RuntimeError):
            report.approved_capabilities(line + line)
        self.assertEqual({"a", "b"}, report.approved_capabilities(line))

    def test_approved_declaration_waives(self):
        self.assertEqual(
            {"evm-max-amount-review"},
            report.release_missing_capabilities(
                [skipped("evm-max-amount-review")],
                approved={"evm-max-amount-review"}))

    def test_unapproved_skip_reason_cannot_shrink_the_gate(self):
        for cases in ([skipped("evm-max-amount-review")],
                      [skipped("osmosis-wire-guards extra")],
                      [skipped("")]):
            with self.assertRaises(RuntimeError):
                report.release_missing_capabilities(cases, approved=set())


class RequiredCaseMatching(unittest.TestCase):
    REQUIRED = "Eip712.MalformedHexNeverPublishesEncodedOutput"

    def gate(self, passed_name):
        # Only the base set is required when every staged capability is
        # waived, so this exercises the name match alone.
        cases = [{"classname": passed_name.rsplit(".", 1)[0],
                  "name": passed_name.rsplit(".", 1)[1],
                  "status": "pass", "skip_reason": ""}]
        cases += [{"classname": "c", "name": "n", "status": "pass",
                   "skip_reason": ""}]
        original = report.BASE_REQUIRED_CASES
        report.BASE_REQUIRED_CASES = {self.REQUIRED}
        try:
            with unittest.mock.patch.object(
                    report, "release_missing_capabilities",
                    return_value={"evm-max-amount-review",
                                  "osmosis-wire-guards"}):
                report.validate_cases(cases)
        finally:
            report.BASE_REQUIRED_CASES = original

    def test_exact_and_module_prefixed_names_satisfy(self):
        self.gate(self.REQUIRED)
        self.gate("tests." + self.REQUIRED)

    def test_suffix_coincidence_does_not_satisfy(self):
        with self.assertRaises(RuntimeError):
            self.gate("X" + self.REQUIRED)


if __name__ == "__main__":
    unittest.main()
