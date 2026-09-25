"""Regression checks for the release report's capability-waiver gate."""

import importlib.util
from pathlib import Path
import unittest
import unittest.mock

SPEC = importlib.util.spec_from_file_location(
    "report", Path(__file__).with_name("generate-test-report.py"))
report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(report)


def skipped(capability):
    return {"status": "skip",
            "skip_reason": report.CAPABILITY_SKIP_PREFIX + capability}


class CapabilityWaivers(unittest.TestCase):
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
