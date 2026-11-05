"""Public fixture exceptions must not hide credentials in the same files."""

import hashlib
import json
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(shutil.which("gitleaks"), "gitleaks is required")
class GitleaksAllowlists(unittest.TestCase):
    def scan(self, fixtures):
        config = Path(__file__).resolve().parents[1] / ".gitleaks.toml"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            for name, contents in fixtures.items():
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents)
            report = root / "report.json"
            result = subprocess.run([
                "gitleaks", "detect", "--no-git", "--source", str(source),
                "--config", str(config), "--redact", "--report-format=json",
                "--report-path", str(report)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            findings = json.loads(report.read_text())
            return sorted((str(Path(f["File"]).relative_to(source)),
                           f["StartLine"], f["RuleID"]) for f in findings)

    def test_documented_commit_does_not_exempt_credentials(self):
        credential = "synthetic_" + "39oG97AmQf6SvR8kT2uZhP0cE5jW4xBn"
        commit = "4ce2a07cbce95882f84b3a1aa6e88976af1f6c8b"
        actual = self.scan({
            "docs/release/probe.md": 'python-keepkey: "' + commit +
                                     '"\napi_key: "' + credential + '"\n',
            "outside.md": 'python-keepkey: "' + commit + '"\n',
        })
        self.assertEqual(actual, [
            ("docs/release/probe.md", 2, "generic-api-key"),
            ("outside.md", 1, "generic-api-key"),
        ])

    def test_token_address_does_not_exempt_credentials(self):
        credential = "synthetic_" + "39oG97AmQf6SvR8kT2uZhP0cE5jW4xBn"
        address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        actual = self.scan({
            "unittests/firmware/eip712_corpus.json": json.dumps(
                {"token": address, "api_key": credential}, indent=2),
            "outside.json": json.dumps({"token": address}, indent=2),
        })
        self.assertEqual(actual, [
            ("outside.json", 2, "generic-api-key"),
            ("unittests/firmware/eip712_corpus.json", 3, "generic-api-key"),
        ])

    def monero_reference(self):
        root = Path(__file__).resolve().parents[1]
        return json.loads((root / "tools/monero-feasibility/evidence/"
                           "2026-11-04-interoperability/host.json").read_text())["reference"]

    def test_monero_reference_is_derived_from_published_disposable_roots(self):
        root = Path(__file__).resolve().parents[1]
        generator = runpy.run_path(str(root / "tools/monero-feasibility/reference.py"))
        reference = self.monero_reference()
        self.assertEqual(reference["fixture_mnemonics_public"], generator["FIXTURES"])
        self.assertEqual(reference["bip39_passphrase"], "")
        self.assertEqual(len(reference["cases"]), 96)
        keys = {(name, account): generator["slip10"](mnemonic, account).hex()
                for name, mnemonic in generator["FIXTURES"].items() for account in [0, 1]}
        for case in reference["cases"]:
            label = re.fullmatch(r"(abandon|trezor)-account([01])-sub[0-9]+-[0-9]+-output[0-9]+", case["label"])
            self.assertIsNotNone(label)
            self.assertEqual(case["key_seed"], keys[(label[1], int(label[2]))])
            self.assertEqual(int.from_bytes(bytes.fromhex(case["spend_secret"]), "little"),
                             int.from_bytes(bytes.fromhex(case["key_seed"]), "little") % generator["L"])

    def test_monero_public_vectors_do_not_exempt_a_credential_on_the_same_line(self):
        credential = "synthetic_" + "39oG97AmQf6SvR8kT2uZhP0cE5jW4xBn"
        reference = self.monero_reference()
        reference["cases"][0]["api_key"] = credential
        path = "tools/monero-feasibility/evidence/2026-11-04-interoperability/host.json"
        actual = self.scan({path: json.dumps(reference, separators=(",", ":")),
                            "outside.json": json.dumps({"key_seed": reference["cases"][0]["key_seed"]})})
        self.assertEqual(actual, [("outside.json", 1, "generic-api-key"),
                                  (path, 1, "generic-api-key")])

    def test_monero_fixture_view_key_does_not_exempt_same_line_credentials(self):
        credential = "synthetic_" + "39oG97AmQf6SvR8kT2uZhP0cE5jW4xBn"
        root = Path(__file__).resolve().parents[1]
        path = "tools/monero-feasibility/evidence/2026-11-04-host/fixtures/base-request.json"
        fixture = json.loads((root / path).read_text())
        self.assertIn(fixture["view_key"], {case["view_secret"] for case in self.monero_reference()["cases"]})
        fixture["api_key"] = credential
        actual = self.scan({path: json.dumps(fixture, separators=(",", ":")),
                            "outside.json": json.dumps({"view_key": fixture["view_key"]})})
        self.assertEqual(actual, [("outside.json", 1, "generic-api-key"),
                                  (path, 1, "generic-api-key")])

    def test_monero_public_checksums_do_not_exempt_unknown_credentials(self):
        credential = "synthetic_" + "39oG97AmQf6SvR8kT2uZhP0cE5jW4xBn"
        root = Path(__file__).resolve().parents[1]
        summary_path = "tools/monero-feasibility/evidence/2026-11-04-alpha/summary.json"
        summary = json.loads((root / summary_path).read_text())
        field = "tools/monero-feasibility/commands/key-image.h"
        checksum = summary["source_sha256"][field]
        key_checksum = hashlib.sha256((root / "tools/monero-feasibility/host-binaryfate.asc").read_bytes()).hexdigest()
        actual = self.scan({summary_path: json.dumps({field: checksum, "api_key": credential}, indent=2),
                            "tools/monero-feasibility/prepare_host.py": 'KEY_SHA256 = "' + key_checksum +
                            '"\napi_key = "' + credential + '"\n',
                            "outside.py": 'KEY_SHA256 = "' + key_checksum + '"\n'})
        self.assertEqual(actual, [("outside.py", 1, "generic-api-key"),
                                  (summary_path, 3, "generic-api-key"),
                                  ("tools/monero-feasibility/prepare_host.py", 2, "generic-api-key")])


if __name__ == "__main__":
    unittest.main()
