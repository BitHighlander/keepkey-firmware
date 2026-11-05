"""Synthetic-only regression for the public exporter; no emulator is loaded."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("report_fixture", Path(__file__).with_name("test_monero_report.py"))
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)
SPEC = importlib.util.spec_from_file_location(
    "public_exporter", Path(__file__).resolve().parents[1] / "tools/monero-feasibility/report_evidence.py")
exporter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(exporter)


def transaction_bytes():
    vint = exporter.signing.wire.vint
    prefix = vint(2) + vint(0) + vint(1) + b"\x02" + vint(0) + vint(16)
    prefix += b"\0" + b"\1" * 15 + bytes.fromhex("e" * 64)
    prefix += vint(2) + b"\0\3" + b"\x11" * 32 + b"\xab" + b"\0\3" + b"\x22" * 32 + b"\xcd"
    prefix += vint(33) + b"\1" + b"\x33" * 32
    base = b"\6" + vint(4000000) + b"\x44" * 16 + b"\x55" * 64
    # Structurally valid dummy proof fields; never claimed as real proof outside these tests.
    proof = vint(1) + bytes(6 * 32) + vint(6) + bytes(6 * 32) + vint(6) + bytes(6 * 32)
    return prefix + base + proof + bytes(18 * 32) + bytes(32)


class PublicExport(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture.EvidenceFixture(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.wallet_dir, self.host_dir, self.compatibility_dir = [self.root / name for name in ("wallet", "host", "compatibility")]
        for directory in (self.wallet_dir, self.host_dir, self.compatibility_dir): directory.mkdir()
        library = self.wallet_dir / "SYNTHETIC-UNIT-libkkemu"
        library.write_bytes(b"SYNTHETIC UNIT LIBRARY - NOT EXECUTABLE")
        library_hash = fixture.report.sha256(library.read_bytes())
        engine = self.wallet_dir / "SYNTHETIC-UNIT-Core"
        engine.write_bytes(b"SYNTHETIC UNIT CORE - NOT EXECUTABLE")
        source = "tools/monero-feasibility/host_emulator.py"
        sources = {source: fixture.report.sha256((exporter.ROOT / source).read_bytes())}
        names = ("addresses", "watch", "key-images", "signing", "crypto", "ordinary-addresses",
                 "ordinary-watch", "ordinary-key-images", "ordinary-signing")
        self.wallet = {"status": "pass", "signing_enabled": True, "physical_device_accessed": False,
                       "firmware_commit": "a" * 40, "shared_library": str(library), "shared_library_sha256": library_hash,
                       "independent_core_sha256": "f" * 64, "source_sha256": sources,
                       "reports": {name: {"status": "pass", "library_sha256": library_hash} for name in names},
                       "engine": {"status": "pass", "library": str(engine),
                                  "library_sha256": fixture.report.sha256(engine.read_bytes()),
                                  "core_release": "SYNTHETIC-UNIT", "core_commit": "b" * 40},
                       "seed": "CANARY-MUST-NEVER-BE-EXPORTED"}
        self.wallet["reports"]["signing"]["reference_core_commit"] = "c" * 40
        self.host = {"status": "pass", "physical_device_accessed": False, "public_network_accessed": False,
                     "transactions_submitted_only_to_owned_loopback_regtest_daemon": True, "production_ready": False,
                     "library_sha256": library_hash, "source_sha256": sources[source], "frames": [],
                     "transactions": [], "rejection_cases": [], "checks": [],
                     "independent_core_sha256": "f" * 64, "host_adapter_sha256": "e" * 64,
                     "binary_sha256": {"monerod": "d" * 64, "monero-wallet-rpc": "c" * 64},
                     "private_view_key": "CANARY-MUST-NEVER-BE-EXPORTED"}
        record = self.fixture.manifest["screens"][0]
        for field in ("raw_file", "pgm_file"):
            (self.host_dir / record[field]).write_bytes((self.root / record[field]).read_bytes())
        self.host["frames"].append({"sha256": record["raw_frame_sha256"], "raw_path": record["raw_file"], "path": record["pgm_file"]})
        self.wire = []
        def screen(label, title="Monero", approval="approved"):
            value = {"label": label, "title": title, "body": "SYNTHETIC UNIT SCREEN", "frame_sha256": record["raw_frame_sha256"], "approval": approval}
            self.wire.append({"direction": "screen", **value})
            return value
        display = {"show_display": True, "address": fixture.SENDER,
                   "screens": [screen("receive-address", "Address"), screen("receive-qr", "Address QR")]}
        (self.host_dir / "address-display.json").write_text(json.dumps(display))
        for role in ("fee", "output", "final"):
            label = "reject-" + role
            self.host["rejection_cases"].append({"name": label, "target": role, "signed_response_returned": False,
                                                 "pool_empty": True, "derived_node_zero": True, "signing_context_zero": True,
                                                 "review_screens": [screen(label, approval="rejected")]})
            for suffix in ("-no-signature-returned", "-no-late-transaction", "-derived-node-zero", "-signing-context-zero", "-private-chain-pool-empty"):
                self.host["checks"].append({"name": label + suffix, "status": "pass"})
        raw = transaction_bytes()
        parsed = exporter.signing.parse_transaction(raw)
        for number in (1, 2):
            label = "send-%d" % number
            tx = copy.deepcopy(self.fixture.manifest["transactions"][0])
            outputs = tx["outputs"]
            for index, decoded in enumerate(outputs):
                public = parsed["outputs"][index]
                decoded.update(one_time_public_key=public["public_key"].hex(), view_tag=public["view_tag"].hex(),
                               encrypted_amount=public["encrypted_amount"].hex(), commitment=public["commitment"].hex())
            self.host["transactions"].append({"number": number, "tx_hash": str(number) * 64,
                    "raw_tx_sha256": fixture.report.sha256(raw), "bytes": len(raw), "fee": 4000000,
                    "recipient_amount": 1250000000000, "recipient_balance": 1250000000000 * number,
                    "input_total_atomic": tx["input_total_atomic"], "change_amount_atomic": tx["change_amount_atomic"],
                    "public_decoding": {"inputs": parsed["inputs"]}, "output_count": 2, "decoded_outputs": outputs,
                    "chain_receipt": {"txid": str(number) * 64, "raw_tx_sha256": fixture.report.sha256(raw), "in_pool": False, "block_height": 72},
                    "recipient_receipt": {"txid": str(number) * 64, "height": 72, "type": "in", "amount_atomic": "1250000000000"},
                    "official_core_verified": True, "daemon_accepted": True, "daemon_acceptance": {"status": "OK"},
                    "key_images_spent": [1], "recipient_payment_found": True,
                    "review_screens": [screen(label + "-" + str(i)) for i in range(3)]})
            (self.host_dir / (label + ".tx.bin")).write_bytes(raw)
            suffixes = ("-no-transaction-before-consent", "-ack-alone-does-not-sign", "-local-daemon-accepted",
                        "-exact-signed-bytes-mined", "-stock-recipient-decoded-exact-payment", "-input-key-images-spent-on-chain",
                        "-derived-node-zero-after-signing", "-signing-context-zero-after-signing", "-independent-transaction-hash",
                        "-official-core-verification", "-independent-recipient-change-decryption", "-fee-reviewed")
            suffixes += tuple("-output-%d-%s" % (i, suffix) for i in range(2)
                              for suffix in ("full-address-reviewed", "exact-amount-reviewed"))
            self.host["checks"] += [{"name": label + suffix, "status": "pass"} for suffix in suffixes]
        self.fixture.add_compatibility()
        self.compatibility = copy.deepcopy(self.fixture.manifest["compatibility"])
        self.compatibility.update(source_sha256={}, library_sha256=library_hash,
                                  core_library=str(engine), core_library_sha256=self.wallet["engine"]["library_sha256"],
                                  rpc_login="CANARY-MUST-NEVER-BE-EXPORTED")
        for suite in [self.compatibility["dylib_screenshot_suite"]] + self.compatibility["native_suites"]:
            suite["junit"] = suite.pop("junit_file")
            (self.compatibility_dir / suite["junit"]).write_bytes((self.root / suite["junit"]).read_bytes())
        self.write()

    def write(self):
        for directory, value in ((self.wallet_dir, self.wallet), (self.host_dir, self.host), (self.compatibility_dir, self.compatibility)):
            (directory / "result.json").write_text(json.dumps(value))
        (self.host_dir / "host-emulator-wire.json").write_text(json.dumps(self.wire))

    def export(self):
        self.write()
        with mock.patch.object(exporter.subprocess, "check_output", return_value="a" * 40):
            return exporter.export(self.wallet_dir, self.host_dir, self.compatibility_dir, self.root / "public")

    def test_allowlist_exports_pixels_transactions_and_junit_without_private_raw_fields(self):
        result = self.export()
        self.assertEqual(2, result["transactions"])
        self.assertEqual(11, result["screens"])
        for path in (self.root / "public").rglob("*"):
            if path.is_file(): self.assertNotIn(b"CANARY-MUST-NEVER-BE-EXPORTED", path.read_bytes())
        self.assertEqual(2, len(fixture.report.validate_evidence(result["manifest"])["manifest"]["transactions"]))

    def test_stale_wallet_artifact_cannot_be_exported(self):
        self.wallet["shared_library_sha256"] = "0" * 64
        with self.assertRaisesRegex(exporter.pdf.EvidenceError, "unchanged dylib"):
            self.export()

    def test_recovered_commitment_must_match_actual_raw_transaction(self):
        self.host["transactions"][0]["decoded_outputs"][0]["commitment"] = "0" * 64
        with self.assertRaisesRegex(exporter.pdf.EvidenceError, "fresh serialized transaction"):
            self.export()

    def test_signing_core_metadata_must_match_the_bridge_actually_linked_by_the_build(self):
        self.compatibility["core_library_sha256"] = "0" * 64
        with self.assertRaisesRegex(exporter.pdf.EvidenceError, "bridge linked by this firmware build"):
            self.export()


if __name__ == "__main__":
    unittest.main()
