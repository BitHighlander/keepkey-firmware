"""Tamper and rendering tests. Synthetic pixels here are never report evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock
import zlib


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


report = module("monero_report", "monero-report.py")
canonical = module("canonical_report", "generate-test-report.py")
SENDER = "44jKQv6ZKMd5ecLLmkNJGi7azgSptEq8ki7TFiat1TfLfdDQ1tQ7ZYa3cRh7X2uRwvLDjddWh97ajeyhR2seKSECQeDx1WR"
RECIPIENT = "4Ahp23WfMrMFK3wYL2hLWQFGt87ZTeRkufS6JoQZu6MEFDokAQeGWmu9MA3GFq1yVLSJQbKJqVAn9F9DLYGpRzRAEXqAXKM"


def png(pixels, row_filter=0):
    def chunk(kind, payload):
        return (struct.pack(">I", len(payload)) + kind + payload +
                struct.pack(">I", zlib.crc32(kind + payload) & 0xffffffff))
    rows, previous = [], bytes(256)
    for y in range(64):
        row = pixels[y * 256:(y + 1) * 256]
        encoded = bytearray()
        for x, value in enumerate(row):
            left, above, corner = row[x - 1] if x else 0, previous[x], previous[x - 1] if x else 0
            if row_filter == 4:
                p = left + above - corner
                candidates = (left, above, corner)
                prediction = min(candidates, key=lambda v: abs(p - v))
            else:
                prediction = (0, left, above, (left + above) // 2)[row_filter]
            encoded.append((value - prediction) & 255)
        rows.append(bytes([row_filter]) + encoded)
        previous = row
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 256, 64, 8, 0, 0, 0, 0)) +
            chunk(b"IDAT", zlib.compress(b"".join(rows))) + chunk(b"IEND", b""))


class EvidenceFixture(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.path = self.root / "manifest.json"
        self.manifest = {
            "schema_version": 1,
            "scope": {"execution": "native-emulator", "network": "offline-private-fakechain",
                      "physical_device_accessed": False, "public_network_accessed": False,
                      "production_ready": False},
            "provenance": {"firmware_commit": "a" * 40,
                           "source_sha256": {"tools/fixture.py": "b" * 64},
                           "artifacts": {key: {"sha256": "c" * 64} for key in
                                         ("library", "adapter", "daemon", "wallet_rpc",
                                          "independent_core", "signing_core")}},
            "receive": {"address": SENDER, "path": "m/44'/128'/0'", "screen_ids": ["receive", "qr"]},
            "screens": [], "transactions": [], "rejection_cases": []}
        for sequence, identity in enumerate(("receive", "qr", "fee", "output", "final", "refused")):
            frame = bytes(((i + sequence * 17) % 256) for i in range(2048))
            pixels = report.raw_pixels(frame)
            files = {"raw_file": (identity + ".bin", frame),
                     "file": (identity + ".png", png(pixels, sequence % 5)),
                     "pgm_file": (identity + ".pgm", b"P5\n256 64\n255\n" + pixels)}
            record = {"id": identity, "width": 256, "height": 64,
                      "sequence": sequence, "title": "TEST FIXTURE " + identity,
                      "body": "Synthetic test fixture only", "role": identity,
                      "approval": "observed" if sequence < 2 else "approved" if sequence < 5 else "rejected"}
            for field, (filename, data) in files.items():
                (self.root / filename).write_bytes(data)
                record[field] = filename
                record[{"raw_file": "raw_frame_sha256", "file": "png_sha256", "pgm_file": "pgm_sha256"}[field]] = report.sha256(data)
            self.manifest["screens"].append(record)
        raw = bytes(range(256))
        (self.root / "tx.bin").write_bytes(raw)
        tx = {"id": "synthetic-validator-unit-fixture", "txid": "d" * 64,
              "raw_tx_file": "tx.bin", "raw_tx_sha256": report.sha256(raw), "bytes": 256,
              "input_total_atomic": "10000000000000", "fee_atomic": "4000000",
              "recipient_amount_atomic": "1250000000000", "change_amount_atomic": "8749996000000",
              "outputs": [{"tx_output_index": 0, "plan_output_index": 1, "role": "change", "address": SENDER,
                           "amount_atomic": "8749996000000", "commitment_verified": True, "view_tag_verified": True},
                          {"tx_output_index": 1, "plan_output_index": 0, "role": "recipient", "address": RECIPIENT,
                           "amount_atomic": "1250000000000", "commitment_verified": True, "view_tag_verified": True}],
              "verification": {key: True for key in
                               ("raw_prefix_parsed", "txid_matches_firmware", "core_clsag_bulletproof_verified",
                                "outputs_scanned_and_commitments_verified", "fee_matches_review", "review_plan_matches_decoded_outputs")},
              "decoded": {"version": 2, "unlock_time": 0, "ringct_type": 6, "ring_size": 16,
                          "input_count": 1, "output_count": 2, "fee_atomic": "4000000"},
              "inputs": [{"key_image": "e" * 64, "indices": list(range(16))}],
              "review": [self.review(identity) for identity in ("fee", "output", "final")],
              "daemon": {"accepted": True, "confirmed_height": 72, "key_images_spent": True},
              "recipient_wallet": {"payment_found": True, "txid": "d" * 64,
                                   "received_amount_atomic": "1250000000000", "balance_atomic": "1250000000000"}}
        self.manifest["transactions"].append(tx)
        for output in tx["outputs"]:
            output.update(one_time_public_key="1" * 64, view_tag="ab",
                          encrypted_amount="2" * 16, commitment="3" * 64)
        self.manifest["rejection_cases"].append({"name": "final-refusal", "target": "final",
                                               "signed_response_returned": False, "pool_empty": True,
                                               "derived_node_zero": True, "review": [self.review("refused")]})
        self.write()

    def review(self, identity):
        record = next(item for item in self.manifest["screens"] if item["id"] == identity)
        return {"screen_id": identity, "frame_sha256": record["raw_frame_sha256"], "approval": record["approval"]}

    def write(self):
        self.path.write_text(json.dumps(self.manifest))

    def valid(self):
        self.write()
        return report.validate_evidence(self.path)

    def add_compatibility(self):
        def suite(name, count):
            data = ("<testsuite>" + "".join('<testcase classname="Fixture" name="case%d"/>' % i
                                           for i in range(count)) + "</testsuite>").encode()
            filename = name + ".xml"
            (self.root / filename).write_bytes(data)
            return {"name": name, "returncode": 0, "tests": count, "failures": 0,
                    "errors": 0, "skipped": 0, "junit_file": filename,
                    "junit_sha256": report.sha256(data), "binary_sha256": "f" * 64}
        self.manifest["compatibility"] = {
            "status": "pass", "firmware_commit": "a" * 40, "library_sha256": "c" * 64,
            "same_artifact_unchanged": True, "exhaustive_coin_coverage": False,
            "dylib_screenshot_suite": suite("dylib-screenshots", 4),
            "native_suites": [suite(name, 7) for name in
                              ("firmware-unit", "board-unit", "crypto-unit", "zcash-display-unit")]}

    def test_valid_bundle_has_exact_amounts_and_all_files(self):
        bundle = self.valid()
        self.assertEqual(6, len(bundle["screens"]))
        self.assertEqual(19, len(bundle["files"]))
        self.assertEqual("1.250000000000 XMR", report.xmr("1250000000000"))

    def test_every_png_row_filter_preserves_raw_pixels(self):
        pixels = report.raw_pixels((self.root / "fee.bin").read_bytes())
        for row_filter in range(5):
            with self.subTest(row_filter=row_filter):
                self.assertEqual(pixels, report.png_pixels(png(pixels, row_filter)))

    def test_file_corruption_and_rehashed_pixel_substitution_are_rejected(self):
        record = self.manifest["screens"][0]
        path = self.root / record["file"]
        original = path.read_bytes()
        path.write_bytes(original[:-1])
        with self.assertRaisesRegex(report.EvidenceError, "SHA256"):
            self.valid()
        replacement = png(report.raw_pixels(bytes([15]) * 2048))
        path.write_bytes(replacement)
        record["png_sha256"] = report.sha256(replacement)
        with self.assertRaisesRegex(report.EvidenceError, "pixels do not match"):
            self.valid()

    def test_missing_raw_frame_is_rejected(self):
        (self.root / "receive.bin").unlink()
        with self.assertRaisesRegex(report.EvidenceError, "missing"):
            self.valid()

    def test_path_escape_and_symlinks_are_rejected(self):
        record = self.manifest["screens"][0]
        record["raw_file"] = "../receive.bin"
        with self.assertRaisesRegex(report.EvidenceError, "remain inside"):
            self.valid()
        (self.root / "link.bin").symlink_to(self.root / "receive.bin")
        record["raw_file"] = "link.bin"
        with self.assertRaisesRegex(report.EvidenceError, "symlink"):
            self.valid()

    def test_noncanonical_amounts_and_unbalanced_plan_are_rejected(self):
        tx = self.manifest["transactions"][0]
        original = copy.deepcopy(tx)
        for invalid in (1.25, "1e12", "01250000000000", "-1", str(2**64)):
            with self.subTest(invalid=invalid):
                tx["recipient_amount_atomic"] = invalid
                with self.assertRaises(report.EvidenceError):
                    self.valid()
        tx.update(original)
        tx["fee_atomic"] = "4000001"
        with self.assertRaisesRegex(report.EvidenceError, "do not balance"):
            self.valid()

    def test_output_binding_and_core_proof_are_required(self):
        tx = self.manifest["transactions"][0]
        original = copy.deepcopy(tx)
        for mutation in ("address", "commitment", "order", "proof", "fee"):
            tx.clear(); tx.update(copy.deepcopy(original))
            with self.subTest(mutation=mutation):
                if mutation == "address": tx["outputs"][0]["address"] = RECIPIENT
                if mutation == "commitment": tx["outputs"][1]["commitment_verified"] = False
                if mutation == "order": tx["outputs"][1]["plan_output_index"] = 1
                if mutation == "proof": tx["verification"]["core_clsag_bulletproof_verified"] = False
                if mutation == "fee": tx["decoded"]["fee_atomic"] = "1"
                with self.assertRaises(report.EvidenceError): self.valid()

    def test_review_hash_sequence_and_approval_are_bound(self):
        tx = self.manifest["transactions"][0]
        original = copy.deepcopy(tx["review"])
        for mutation in ("hash", "sequence", "approval"):
            tx["review"] = copy.deepcopy(original)
            with self.subTest(mutation=mutation):
                if mutation == "hash": tx["review"][0]["frame_sha256"] = "0" * 64
                if mutation == "sequence": tx["review"].reverse()
                if mutation == "approval": tx["review"][0]["approval"] = "rejected"
                with self.assertRaises(report.EvidenceError): self.valid()

    def test_decoded_public_crypto_fields_and_ring_members_are_bounded(self):
        tx = self.manifest["transactions"][0]
        tx["outputs"][0]["view_tag"] = "not-hex"
        with self.assertRaisesRegex(report.EvidenceError, "cryptographic field"):
            self.valid()
        tx["outputs"][0]["view_tag"] = "ab"
        tx["inputs"][0]["indices"][-1] = tx["inputs"][0]["indices"][0]
        with self.assertRaisesRegex(report.EvidenceError, "public input ring"):
            self.valid()

    def test_daemon_mining_and_recipient_payment_must_match(self):
        tx = self.manifest["transactions"][0]
        for section, field, invalid in (("daemon", "confirmed_height", 0),
                                        ("daemon", "accepted", False),
                                        ("recipient_wallet", "txid", "0" * 64),
                                        ("recipient_wallet", "received_amount_atomic", "1")):
            original = tx[section][field]
            with self.subTest(field=field):
                tx[section][field] = invalid
                with self.assertRaises(report.EvidenceError): self.valid()
                tx[section][field] = original

    def test_private_fields_and_orphan_frames_are_rejected(self):
        self.manifest["private_view_key"] = "SYNTHETIC-PRIVATE-FIXTURE"
        with self.assertRaisesRegex(report.EvidenceError, "forbidden"):
            self.valid()
        del self.manifest["private_view_key"]
        self.manifest["receive"]["screen_ids"] = ["qr", "qr"]
        with self.assertRaisesRegex(report.EvidenceError, "unreferenced"):
            self.valid()

    def test_cancellation_must_not_release_signature(self):
        self.manifest["rejection_cases"][0]["signed_response_returned"] = True
        with self.assertRaisesRegex(report.EvidenceError, "Cancellation proof"):
            self.valid()

    def test_report_does_not_claim_refusal_proof_without_a_refusal_run(self):
        self.manifest["rejection_cases"] = []
        with self.assertRaisesRegex(report.EvidenceError, "review-refusal evidence"):
            self.valid()

    def test_ordinary_regressions_are_bound_to_the_exact_dylib_and_retained_junit(self):
        self.add_compatibility()
        self.assertEqual(24, len(self.valid()["files"]))
        compatibility = self.manifest["compatibility"]
        compatibility["library_sha256"] = "0" * 64
        with self.assertRaisesRegex(report.EvidenceError, "this Monero firmware artifact"):
            self.valid()
        compatibility["library_sha256"] = "c" * 64
        compatibility["native_suites"][0]["tests"] += 1
        with self.assertRaisesRegex(report.EvidenceError, "retained JUnit"):
            self.valid()

    def test_report_contains_all_verified_images_and_explicit_scope(self):
        renderer = report.load_renderer()
        pdf = renderer.PDF()
        pages = report.render_section(renderer, pdf, self.valid(), standalone=True)
        self.assertGreater(pages, 3)
        self.assertEqual(6, len(pdf.images))
        streams = "\n".join(page[0] for page in pdf.pages)
        self.assertIn(SENDER, streams)
        self.assertIn(RECIPIENT, streams)
        self.assertIn("1.250000000000 XMR", streams)
        self.assertIn("Physical-device signing: not implemented / not proven", streams)
        self.assertIn("Wire output 0 <- review output 1", streams)
        output = self.root / "test.pdf"
        pdf.write(output)
        receipt = report.report_receipt(output, self.valid(), report.DEFAULT_RENDERER, pages)
        self.assertEqual(report.sha256(output.read_bytes()), receipt["pdf_sha256"])

    def test_canonical_copy_excludes_unreferenced_private_files(self):
        (self.root / "wallet-private.json").write_text("SYNTHETIC-PRIVATE-FIXTURE")
        destination = self.root / "report"
        (self.root / "tools").mkdir()
        (self.root / "tools/fixture.py").write_text("synthetic checked-out source")
        self.manifest["provenance"]["source_sha256"]["tools/fixture.py"] = report.sha256((self.root / "tools/fixture.py").read_bytes())
        self.write()
        with mock.patch.multiple(canonical, ROOT=self.root, REPORT_DIR=destination):
            copied = canonical.prepare_monero_evidence(self.path, "a" * 40)
        self.assertEqual(self.valid()["manifest_sha256"], copied["manifest_sha256"])
        self.assertFalse((copied["source_root"] / "wallet-private.json").exists())
        self.assertEqual(20, sum(path.is_file() for path in destination.rglob("*")))

    def test_canonical_copy_rejects_other_firmware_commit(self):
        with mock.patch.object(canonical, "REPORT_DIR", self.root / "report"):
            with self.assertRaisesRegex(RuntimeError, "checked-out firmware commit"):
                canonical.prepare_monero_evidence(self.path, "e" * 40)

    def test_canonical_copy_rejects_changed_source_even_at_the_same_commit(self):
        with mock.patch.object(canonical, "REPORT_DIR", self.root / "report"):
            with self.assertRaisesRegex(RuntimeError, "checked-out firmware source"):
                canonical.prepare_monero_evidence(self.path, "a" * 40)

    def test_canonical_adapter_appends_to_existing_report_before_writing(self):
        renderer = report.load_renderer()
        output = self.root / "canonical.pdf"
        original_write = renderer.PDF.write
        def baseline_main():
            pdf = renderer.PDF()
            pdf.add_page([(755, 12, "Existing canonical report page")])
            pdf.write(output)
        with mock.patch.object(report, "load_renderer", return_value=renderer), \
                mock.patch.object(renderer, "main", side_effect=baseline_main), \
                mock.patch.object(sys, "argv", ["monero-report.py", "--evidence", str(self.path),
                                               "--canonical-renderer", str(report.DEFAULT_RENDERER),
                                               "--", "--output=" + str(output)]):
            report.main()
        receipt = json.loads(output.with_suffix(".pdf.monero.json").read_text())
        self.assertGreater(receipt["monero_pages"], 3)
        self.assertEqual(original_write, renderer.PDF.write)
        # The first page survives; images and appended pages share one PDF writer.
        self.assertIn(b"/Count " + str(receipt["monero_pages"] + 1).encode(), output.read_bytes())


if __name__ == "__main__":
    unittest.main()
