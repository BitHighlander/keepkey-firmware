#!/usr/bin/env python3
"""Export an allowlisted public bundle from fresh local emulator proof runs.

The raw directories are never copied. This reader exports only public pixels,
signed transactions, decoded public fields and bounded verification receipts.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import zlib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE / "commands"))
import test_signing as signing

SPEC = importlib.util.spec_from_file_location("monero_public_report", ROOT / "scripts/monero-report.py")
pdf = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pdf)
require = pdf.require


def read_json(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 64 * 1024 * 1024,
            "Required completed experiment result is missing or oversized")
    return json.loads(path.read_bytes())


def passed_checks(report):
    checks = report.get("checks", [])
    require(isinstance(checks, list) and checks and
            all(item.get("status") == "pass" for item in checks), "Experiment checks did not all pass")
    result = {item["name"] for item in checks}
    require(len(result) == len(checks), "Experiment check names are ambiguous")
    return result


def png(pixels):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)
    rows = b"".join(b"\0" + pixels[y * 256:(y + 1) * 256] for y in range(64))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 256, 64, 8, 0, 0, 0, 0)) +
            chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))


def export(wallet_dir, host_dir, compatibility_dir, output):
    wallet_dir, host_dir, compatibility_dir, output = map(Path, (wallet_dir, host_dir, compatibility_dir, output))
    wallet = read_json(wallet_dir / "result.json")
    host = read_json(host_dir / "result.json")
    compatibility = read_json(compatibility_dir / "result.json")
    require(all(item.get("status") == "pass" for item in (wallet, host, compatibility)),
            "All three fresh experiment runs must have completed successfully")
    require(wallet.get("signing_enabled") is True and wallet.get("physical_device_accessed") is False and
            host.get("physical_device_accessed") is False and host.get("public_network_accessed") is False and
            host.get("transactions_submitted_only_to_owned_loopback_regtest_daemon") is True and
            host.get("production_ready") is False and compatibility.get("same_artifact_unchanged") is True,
            "Experiment scope is not the approved native/local-chain scope")
    firmware_commit = wallet["firmware_commit"]
    current_commit = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    require(firmware_commit == current_commit == compatibility["firmware_commit"],
            "Fresh runs do not describe the current firmware commit")
    library_hash = wallet["shared_library_sha256"]
    require(library_hash == host["library_sha256"] == compatibility["library_sha256"] and
            pdf.sha256(Path(wallet["shared_library"]).read_bytes()) == library_hash,
            "Wallet, signed host payments and ordinary regressions did not use the same unchanged dylib")
    gates = wallet.get("reports", {})
    expected_gates = {"addresses", "watch", "key-images", "signing", "crypto", "ordinary-addresses",
                      "ordinary-watch", "ordinary-key-images", "ordinary-signing"}
    require(set(gates) == expected_gates and all(gate.get("status") == "pass" for gate in gates.values()),
            "The full workflow and ordinary-build negative controls are incomplete")
    for name in ("addresses", "watch", "key-images", "signing"):
        require(gates[name].get("library_sha256") == library_hash,
                "A workflow gate used a different research dylib")
    checks = passed_checks(host)
    sources = dict(wallet["source_sha256"])
    sources.update({"tools/monero-feasibility/host_emulator.py": host["source_sha256"]})
    for source, digest in compatibility["source_sha256"].items():
        require(source not in sources or sources[source] == digest,
                "Source changed between the fresh proof runs")
        sources[source] = digest
    for source, digest in sources.items():
        require(isinstance(source, str) and not Path(source).is_absolute() and ".." not in Path(source).parts and
                (ROOT / source).is_file() and pdf.sha256((ROOT / source).read_bytes()) == digest,
                "Fresh-run source hashes do not match this checkout")
    sources[str(Path(__file__).relative_to(ROOT))] = pdf.sha256(Path(__file__).read_bytes())
    engine = wallet["engine"]
    require(engine.get("status") == "pass" and
            engine["library_sha256"] == compatibility["core_library_sha256"] and
            Path(engine["library"]).resolve() == Path(compatibility["core_library"]).resolve() and
            pdf.sha256(Path(engine["library"]).read_bytes()) == engine["library_sha256"],
            "The signing Core metadata does not match the unchanged bridge linked by this firmware build")
    require(host["independent_core_sha256"] == wallet["independent_core_sha256"],
            "Independent arithmetic reference changed between runs")
    output.mkdir(parents=True, exist_ok=True)
    require(not output.is_symlink() and not any(output.iterdir()), "Public evidence output must be a new empty directory")

    def save(relative, data):
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return relative, pdf.sha256(data)

    frames = {item["sha256"]: item for item in host["frames"]}
    observed = [item for item in read_json(host_dir / "host-emulator-wire.json") if item.get("direction") == "screen"]
    labels = {}
    for index, item in enumerate(observed):
        labels.setdefault(item["label"], []).append((index, item))
    screens = []

    def screen(meta, role, approval):
        require(meta.get("label") in labels and meta.get("frame_sha256") in frames,
                "A reviewed screen has no retained raw firmware frame")
        matches = [(index, item) for index, item in labels[meta["label"]]
                   if all(meta.get(field) == item.get(field) for field in ("frame_sha256", "title", "body"))]
        require(len(matches) == 1, "Selected screen does not bind to one actual observed wire event")
        sequence, logged = matches[0]
        frame = frames[meta["frame_sha256"]]
        _, raw = pdf.public_file(host_dir, frame["raw_path"], meta["frame_sha256"], 2048)
        pixels = pdf.raw_pixels(raw)
        pgm_data = b"P5\n256 64\n255\n" + pixels
        pdf.public_file(host_dir, frame["path"], pdf.sha256(pgm_data), 20000)
        stem = "frames/screen-%03d" % len(screens)
        raw_file, raw_hash = save(stem + ".bin", raw)
        pgm_file, pgm_hash = save(stem + ".pgm", pgm_data)
        png_file, png_hash = save(stem + ".png", png(pixels))
        identity = "screen-%03d" % len(screens)
        screens.append({"id": identity, "file": png_file, "raw_file": raw_file, "pgm_file": pgm_file,
                        "png_sha256": png_hash, "raw_frame_sha256": raw_hash, "pgm_sha256": pgm_hash,
                        "width": 256, "height": 64, "title": meta["title"], "body": meta["body"],
                        "role": role, "sequence": sequence, "approval": approval})
        return {"screen_id": identity, "frame_sha256": raw_hash, "approval": approval}

    display = read_json(host_dir / "address-display.json")
    require(display.get("show_display") is True and display.get("screens") and
            {"Address", "Address QR"}.issubset({item["title"] for item in display["screens"]}),
            "Actual full address and QR display evidence is missing")
    receive_ids = [screen(item, "receive", "approved")["screen_id"] for item in display["screens"]]
    rejections = []
    require({item.get("target") for item in host["rejection_cases"]} == {"fee", "output", "final"},
            "Actual fee, output and final review refusals are all required")
    for case in host["rejection_cases"]:
        label = case["name"]
        require(case.get("signing_context_zero") is True and all(label + suffix in checks for suffix in
                ("-no-signature-returned", "-no-late-transaction", "-derived-node-zero",
                 "-signing-context-zero", "-private-chain-pool-empty")), "Review refusal checks are incomplete")
        rejections.append({field: case[field] for field in
                           ("name", "target", "signed_response_returned", "pool_empty", "derived_node_zero")})
        rejections[-1]["review"] = [screen(item, "refusal-" + case["target"], item["approval"])
                                     for item in case["review_screens"]]

    transactions = []
    require(len(host["transactions"]) == 2, "Both real private-chain signed transactions are required")
    for tx in host["transactions"]:
        label = "send-%d" % tx["number"]
        require(all(label + suffix in checks for suffix in
                ("-no-transaction-before-consent", "-ack-alone-does-not-sign", "-local-daemon-accepted",
                 "-exact-signed-bytes-mined", "-stock-recipient-decoded-exact-payment",
                 "-input-key-images-spent-on-chain", "-derived-node-zero-after-signing",
                 "-signing-context-zero-after-signing")), "Signed payment consent and chain checks are incomplete")
        _, raw = pdf.public_file(host_dir, label + ".tx.bin", tx["raw_tx_sha256"], 65536)
        parsed = signing.parse_transaction(raw)
        require(tx["bytes"] == len(raw) and parsed["inputs"] == tx["public_decoding"]["inputs"] and
                parsed["fee"] == tx["fee"] and len(parsed["outputs"]) == tx["output_count"],
                "Fresh raw transaction does not match its captured public decoding")
        outputs = []
        output_fields = ("tx_output_index", "plan_output_index", "address", "role", "amount_atomic",
                         "one_time_public_key", "view_tag", "encrypted_amount", "commitment",
                         "commitment_verified", "view_tag_verified")
        for index, decoded in enumerate(tx["decoded_outputs"]):
            public = parsed["outputs"][index]
            require(decoded["tx_output_index"] == index and all(decoded[field] == public[other].hex()
                    for field, other in (("one_time_public_key", "public_key"), ("view_tag", "view_tag"),
                                         ("encrypted_amount", "encrypted_amount"), ("commitment", "commitment"))),
                    "Recovered output does not match the fresh serialized transaction")
            outputs.append({field: decoded[field] for field in output_fields})
        receipt, payment = tx["chain_receipt"], tx["recipient_receipt"]
        require(receipt["txid"] == payment["txid"] == tx["tx_hash"] and
                receipt["raw_tx_sha256"] == pdf.sha256(raw) and receipt["in_pool"] is False and
                receipt["block_height"] == payment["height"] and payment["type"] == "in" and
                payment["amount_atomic"] == str(tx["recipient_amount"]),
                "Mined transaction and stock recipient payment do not bind to the signed bytes")
        public_file, public_hash = save("transactions/" + label + ".bin", raw)
        verification = {
            "raw_prefix_parsed": True,
            "txid_matches_firmware": label + "-independent-transaction-hash" in checks,
            "core_clsag_bulletproof_verified": tx.get("official_core_verified") is True and label + "-official-core-verification" in checks,
            "outputs_scanned_and_commitments_verified": label + "-independent-recipient-change-decryption" in checks,
            "fee_matches_review": label + "-fee-reviewed" in checks,
            "review_plan_matches_decoded_outputs": all(label + "-output-%d-%s" % (i, suffix) in checks
                    for i in range(tx["output_count"]) for suffix in ("full-address-reviewed", "exact-amount-reviewed")),
        }
        require(all(verification.values()), "Signed transaction verification layers are incomplete")
        transactions.append({"id": label, "txid": tx["tx_hash"], "raw_tx_file": public_file,
                             "raw_tx_sha256": public_hash, "bytes": len(raw),
                             "input_total_atomic": tx["input_total_atomic"], "fee_atomic": str(tx["fee"]),
                             "recipient_amount_atomic": str(tx["recipient_amount"]),
                             "change_amount_atomic": tx["change_amount_atomic"], "outputs": outputs,
                             "inputs": parsed["inputs"], "verification": verification,
                             "decoded": {"version": parsed["version"], "unlock_time": parsed["unlock_time"],
                                         "ringct_type": parsed["rct_type"], "ring_size": 16,
                                         "input_count": len(parsed["inputs"]), "output_count": len(parsed["outputs"]),
                                         "fee_atomic": str(parsed["fee"])},
                             "review": [screen(item, "signing-" + label, "approved") for item in tx["review_screens"]],
                             "daemon": {"accepted": tx["daemon_accepted"], "status": tx["daemon_acceptance"]["status"],
                                        "confirmed_height": receipt["block_height"],
                                        "key_images_spent": tx["key_images_spent"] == [1] * len(parsed["inputs"])},
                             "recipient_wallet": {"payment_found": tx["recipient_payment_found"], "txid": payment["txid"],
                                                  "received_amount_atomic": payment["amount_atomic"],
                                                  "balance_atomic": str(tx["recipient_balance"])}})

    def public_suite(suite, name):
        require(name in ("dylib-screenshots", "firmware-unit", "board-unit", "crypto-unit", "zcash-display-unit"),
                "Unknown regression suite cannot be exported")
        _, xml = pdf.public_file(compatibility_dir, suite["junit"], suite["junit_sha256"], 4 * 1024 * 1024)
        filename, digest = save("compatibility/" + name + ".xml", xml)
        value = {field: suite[field] for field in ("returncode", "tests", "failures", "errors", "skipped")}
        value.update(junit_file=filename, junit_sha256=digest)
        if name != "dylib-screenshots":
            value.update(name=name, binary_sha256=suite["binary_sha256"])
        return value

    public_compatibility = {
        "status": compatibility["status"], "firmware_commit": firmware_commit, "library_sha256": library_hash,
        "same_artifact_unchanged": compatibility["same_artifact_unchanged"], "exhaustive_coin_coverage": False,
        "dylib_screenshot_suite": public_suite(compatibility["dylib_screenshot_suite"], "dylib-screenshots"),
        "native_suites": [public_suite(suite, suite["name"]) for suite in compatibility["native_suites"]],
    }
    artifacts = {
        "library": {"sha256": library_hash, "filename": Path(wallet["shared_library"]).name},
        "adapter": {"sha256": host["host_adapter_sha256"], "filename": "monero-host-adapter"},
        "daemon": {"sha256": host["binary_sha256"]["monerod"], "filename": "monerod"},
        "wallet_rpc": {"sha256": host["binary_sha256"]["monero-wallet-rpc"], "filename": "monero-wallet-rpc"},
        "independent_core": {"sha256": host["independent_core_sha256"], "filename": "core-reference",
                             "reference_commit": gates["signing"]["reference_core_commit"]},
        "signing_core": {"sha256": engine["library_sha256"], "filename": Path(engine["library"]).name,
                         "release": engine["core_release"], "commit": engine["core_commit"]},
    }
    manifest = {
        "schema_version": 1,
        "scope": {"execution": "native-emulator", "network": "offline-private-fakechain",
                  "physical_device_accessed": False, "public_network_accessed": False, "production_ready": False},
        "provenance": {"firmware_commit": firmware_commit, "source_sha256": sources, "artifacts": artifacts},
        "receive": {"address": display["address"], "path": "m/44'/128'/0'", "screen_ids": receive_ids},
        "transactions": transactions, "rejection_cases": rejections, "screens": screens,
        "compatibility": public_compatibility,
        "workflow_gates": {name: {"status": gate["status"], "check_count": len(gate.get("checks", []))}
                           for name, gate in sorted(gates.items())},
        "host_checks": [{"name": name, "status": "pass"} for name in sorted(checks)],
    }
    pdf.reject_private_fields(manifest)
    path = output / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    bundle = pdf.validate_evidence(path)
    return {"manifest": str(path), "manifest_sha256": bundle["manifest_sha256"],
            "transactions": len(transactions), "screens": len(screens), "physical_device_ready": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("wallet", "host", "compatibility", "output"):
        parser.add_argument("--" + argument, required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(export(args.wallet, args.host, args.compatibility, args.output), indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        print("ERROR: Public Monero evidence was not exported: " + str(error), file=sys.stderr)
        sys.exit(1)
