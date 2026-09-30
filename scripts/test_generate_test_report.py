"""Exercise the release-evidence gate with complete and corrupted inputs."""

import importlib.util
import json
import os
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
                        ET.SubElement(case, "skipped", {"message": report.CONTRACT_SKIP_REASONS[name]})
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

    def test_every_expected_skip_requires_its_product_reason(self):
        for path in self.paths:
            original = path.read_bytes()
            for index, case in enumerate(ET.parse(path).getroot()):
                if case.find("skipped") is None:
                    continue
                for reason in ("", "unrelated infrastructure failure"):
                    with self.subTest(path=path, case=index, reason=reason):
                        tree = ET.parse(path)
                        tree.getroot()[index].find("skipped").set("message", reason)
                        tree.write(path)
                        with self.assertRaisesRegex(RuntimeError, "contract cases wrong"):
                            report.validate_contract_junit(self.root)
                        path.write_bytes(original)


class NativeContractEvidence(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.paths = {}
        for variant, relative in report.NATIVE_CONTRACT_JUNIT.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            suite = ET.Element("testsuite")
            for name in sorted(report.BLOCK13_NATIVE_CASES[variant]):
                classname, method = name.rsplit(".", 1)
                ET.SubElement(suite, "testcase", {
                    "classname": classname, "name": method, "status": "run"})
            # These survive every corruption: nonempty XML or unrelated green
            # native checks cannot substitute for an owned security contract.
            ET.SubElement(suite, "testcase", {
                "classname": "Unrelated", "name": "StillPasses", "status": "run"})
            ET.ElementTree(suite).write(path)
            self.paths[variant] = path

    def test_complete_product_contracts_pass_and_bind_both_files(self):
        # Binance is retired on alpha (ROM reclaim), so its five continuation cases
        # are no longer owned: 55 - 5.
        self.assertEqual(50, len(report.BLOCK13_NATIVE_CASES["full"]))
        self.assertEqual(18, len(report.BLOCK13_NATIVE_CASES["bitcoin-only"]))
        evidence = report.validate_native_contract_junit(self.root)
        self.assertEqual({"full", "bitcoin-only"},
                         {item["variant"] for item in evidence})
        for item in evidence:
            path = self.paths[item["variant"]]
            self.assertEqual(str(path.relative_to(self.root)), item["path"])
            self.assertEqual(report.sha256_file(path), item["sha256"])

    def test_each_missing_native_product_file_is_refused(self):
        for variant, path in self.paths.items():
            original = path.read_bytes()
            with self.subTest(variant=variant):
                path.unlink()
                with self.assertRaisesRegex(RuntimeError, "JUnit missing"):
                    report.validate_native_contract_junit(self.root)
                path.write_bytes(original)

    def test_each_owned_case_must_run_once_and_pass(self):
        for variant, path in self.paths.items():
            original = path.read_bytes()
            owned_count = len(report.BLOCK13_NATIVE_CASES[variant])
            for index in range(owned_count):
                for mutation in ("remove", "skip", "failure", "error",
                                 "duplicate", "notrun", "missing-status"):
                    with self.subTest(variant=variant, case=index,
                                      mutation=mutation):
                        tree = ET.parse(path)
                        suite = tree.getroot()
                        case = suite[index]
                        if mutation == "remove":
                            suite.remove(case)
                        elif mutation == "skip":
                            ET.SubElement(case, "skipped")
                        elif mutation in ("failure", "error"):
                            ET.SubElement(case, mutation)
                        elif mutation == "duplicate":
                            suite.append(ET.fromstring(ET.tostring(case)))
                        elif mutation == "notrun":
                            case.set("status", "notrun")
                        else:
                            case.attrib.pop("status")
                        tree.write(path)
                        self.assertTrue(any(
                            c.get("classname") == "Unrelated"
                            for c in suite))
                        with self.assertRaises(RuntimeError):
                            report.validate_native_contract_junit(self.root)
                        path.write_bytes(original)

    def test_wrong_product_evidence_is_refused(self):
        full = self.paths["full"]
        btc = self.paths["bitcoin-only"]
        full_bytes, btc_bytes = full.read_bytes(), btc.read_bytes()
        full.write_bytes(btc_bytes)
        with self.assertRaisesRegex(RuntimeError, "native contract cases"):
            report.validate_native_contract_junit(self.root)
        full.write_bytes(full_bytes)
        btc.write_bytes(full_bytes)
        with self.assertRaisesRegex(RuntimeError, "full-only cases"):
            report.validate_native_contract_junit(self.root)

    def test_coincident_suffix_cannot_replace_native_identity(self):
        path = self.paths["full"]
        tree = ET.parse(path)
        case = tree.getroot()[0]
        case.set("classname", "Lookalike." + case.get("classname"))
        tree.write(path)
        with self.assertRaisesRegex(RuntimeError, "native contract cases"):
            report.validate_native_contract_junit(self.root)


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
        approved = report.approved_capabilities()
        self.assertIn("storage-v19-kdf", approved)
        self.assertNotIn("osmosis-wire-guards", approved)
        self.assertNotIn("entropy-audit-budget", approved)

    def test_ledger_must_be_unique(self):
        line = "    KK_RELEASE_MISSING_CAPABILITIES: a,b\n"
        with self.assertRaises(RuntimeError):
            report.parse_capability_ledger("")
        with self.assertRaises(RuntimeError):
            report.parse_capability_ledger(line + line)
        self.assertEqual({"a", "b"}, report.parse_capability_ledger(line))
        self.assertEqual(set(), report.parse_capability_ledger(
            "    KK_RELEASE_MISSING_CAPABILITIES: \n"))

    def test_candidate_cannot_expand_immutable_ledger(self):
        candidate = report.CI_WORKFLOW.read_text().replace(
            "KK_RELEASE_MISSING_CAPABILITIES: ",
            "KK_RELEASE_MISSING_CAPABILITIES: unapproved,")
        with self.assertRaisesRegex(RuntimeError, "immutable authority"):
            report.approved_capabilities(candidate)

    def test_candidate_can_narrow_immutable_ledger(self):
        self.assertEqual({"osmosis-wire-guards"}, report.approved_capabilities(
            "    KK_RELEASE_MISSING_CAPABILITIES: osmosis-wire-guards\n"))

    def test_missing_authority_fails_closed(self):
        import subprocess
        with unittest.mock.patch.object(report, "waiver_authority_commit", return_value="a" * 40):
            with unittest.mock.patch.object(
                    report, "git", side_effect=subprocess.CalledProcessError(1, "git")):
                with self.assertRaisesRegex(RuntimeError, "authority is unavailable"):
                    report.approved_capabilities()

    def test_platform_event_selects_authority_independently(self):
        # The expected SHA is independent of candidate code/constants and
        # differs from both the PR head and an attacker-provided environment pin.
        base = "a" * 40
        with tempfile.TemporaryDirectory() as tmp:
            event = Path(tmp) / "event.json"
            event.write_text(json.dumps({"pull_request": {
                "base": {"sha": base}, "head": {"sha": "b" * 40}}}))
            with unittest.mock.patch.dict(os.environ, {
                    "GITHUB_ACTIONS": "true", "GITHUB_EVENT_PATH": str(event),
                    "GITHUB_EVENT_NAME": "pull_request",
                    "GITHUB_SHA": "b" * 40, "WAIVER_AUTHORITY_COMMIT": "HEAD"}):
                with unittest.mock.patch.object(report, "git", return_value=
                        "    KK_RELEASE_MISSING_CAPABILITIES: approved\n") as git:
                    self.assertEqual({"approved"}, report.approved_capabilities(
                        "    KK_RELEASE_MISSING_CAPABILITIES: approved\n"))
                git.assert_called_once_with("show", base + ":.github/workflows/ci.yml")
                for invalid in ({}, {"pull_request": {"base": {"sha": "HEAD"}}},
                                {"pull_request": {"base": {"sha": "0" * 40}}}):
                    event.write_text(json.dumps(invalid))
                    with self.assertRaises(RuntimeError):
                        report.waiver_authority_commit()

    def test_non_pr_events_require_independent_authority(self):
        accepted = "c" * 40
        with tempfile.TemporaryDirectory() as tmp:
            event = Path(tmp) / "event.json"
            event.write_text(json.dumps({"before": "a" * 40, "after": "b" * 40}))
            for mode in ("push", "workflow_dispatch"):
                with self.subTest(mode=mode):
                    with unittest.mock.patch.dict(os.environ, {
                            "GITHUB_ACTIONS": "true", "GITHUB_EVENT_PATH": str(event),
                            "GITHUB_EVENT_NAME": mode, "GITHUB_SHA": "b" * 40,
                            "KK_ACCEPTED_WAIVER_SHA": ""}):
                        with self.assertRaisesRegex(RuntimeError, "independently accepted"):
                            report.waiver_authority_commit()
                        with unittest.mock.patch.dict(os.environ, {
                                "KK_ACCEPTED_WAIVER_SHA": accepted}):
                            self.assertEqual(accepted, report.waiver_authority_commit())
                        for bad in ("HEAD", "0" * 40, "refs/heads/develop"):
                            with unittest.mock.patch.dict(os.environ, {
                                    "KK_ACCEPTED_WAIVER_SHA": bad}):
                                with self.assertRaisesRegex(RuntimeError, "full nonzero commit"):
                                    report.waiver_authority_commit()

    def test_pr_authority_does_not_use_non_pr_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            event = Path(tmp) / "event.json"
            event.write_text(json.dumps({"pull_request": {"base": {"sha": "a" * 40}}}))
            with unittest.mock.patch.dict(os.environ, {
                    "GITHUB_EVENT_PATH": str(event), "GITHUB_ACTIONS": "true",
                    "KK_ACCEPTED_WAIVER_SHA": "b" * 40}):
                self.assertEqual("a" * 40, report.waiver_authority_commit())

    def test_ci_without_platform_event_fails_closed(self):
        with unittest.mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "platform event payload"):
                report.waiver_authority_commit()

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
        original_hive = report.HIVE_REQUIRED_CASES
        report.HIVE_REQUIRED_CASES = set()
        report.BASE_REQUIRED_CASES = {self.REQUIRED}
        try:
            with unittest.mock.patch.object(
                    report, "release_missing_capabilities",
                    return_value={"evm-max-amount-review",
                                  "osmosis-wire-guards"}):
                report.validate_cases(cases)
        finally:
            report.BASE_REQUIRED_CASES = original
            report.HIVE_REQUIRED_CASES = original_hive

    def test_exact_and_module_prefixed_names_satisfy(self):
        self.gate(self.REQUIRED)
        self.gate("tests." + self.REQUIRED)

    def test_suffix_coincidence_does_not_satisfy(self):
        with self.assertRaises(RuntimeError):
            self.gate("X" + self.REQUIRED)


class HiveNativeEvidence(unittest.TestCase):
    def test_every_owned_native_identity_is_required(self):
        names = report.BASE_REQUIRED_CASES | report.HIVE_REQUIRED_CASES
        cases = [{"classname": n.rsplit(".", 1)[0],
                  "name": n.rsplit(".", 1)[1], "status": "pass", "skip_reason": ""}
                 for n in sorted(names)]
        with unittest.mock.patch.object(
                report, "release_missing_capabilities",
                return_value={"evm-max-amount-review", "osmosis-wire-guards"}):
            report.validate_cases(cases)
            for name in report.HIVE_REQUIRED_CASES:
                for status in ("skip", "fail"):
                    altered = [dict(case) for case in cases]
                    for case in altered:
                        if case["classname"] + "." + case["name"] == name:
                            case["status"] = status
                    with self.subTest(name=name, status=status):
                        with self.assertRaises(RuntimeError):
                            report.validate_cases(altered)

    def test_a_duplicated_native_identity_cannot_hide_behind_a_pass(self):
        names = report.BASE_REQUIRED_CASES | report.HIVE_REQUIRED_CASES
        cases = [{"classname": n.rsplit(".", 1)[0],
                  "name": n.rsplit(".", 1)[1], "status": "pass", "skip_reason": ""}
                 for n in sorted(names)]
        with unittest.mock.patch.object(
                report, "release_missing_capabilities",
                return_value={"evm-max-amount-review", "osmosis-wire-guards"}):
            report.validate_cases(cases)
            for name in sorted(report.HIVE_REQUIRED_CASES):
                for extra_status in ("pass", "skip"):
                    duplicate = dict(next(
                        case for case in cases
                        if case["classname"] + "." + case["name"] == name))
                    duplicate["status"] = extra_status
                    with self.subTest(name=name, extra=extra_status):
                        with self.assertRaises(RuntimeError):
                            report.validate_cases(cases + [duplicate])


if __name__ == "__main__":
    unittest.main()
