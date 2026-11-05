#!/usr/bin/env python3
"""Render public Monero emulator proof with the pinned firmware PDF writer.

No screenshot is synthesized here. Each PNG must match both its SHA256 and the
pixels reconstructed from a retained 2048-byte firmware OLED frame. The same
section can be appended to the canonical report without changing a submodule.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import sys
import xml.etree.ElementTree as ET
import zlib


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RENDERER = ROOT / "deps/python-keepkey/scripts/generate-test-report.py"
SHA = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
ADDRESS = re.compile(r"[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{95}\Z")
ATOMIC = re.compile(r"(?:0|[1-9][0-9]{0,19})\Z")
UINT64 = 2**64 - 1
FORBIDDEN_FIELDS = {
    "seed", "mnemonic", "mnemonicphrase", "walletmnemonic", "privatekey",
    "privatespendkey", "privateviewkey", "viewkey", "spendkey", "txkey",
    "txsecretkey", "nodeprivatekey", "password", "rpclogin", "secret",
}


class EvidenceError(ValueError):
    """Fixed diagnostics deliberately avoid echoing arbitrary input values."""


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def atomic(value):
    require(isinstance(value, str) and ATOMIC.fullmatch(value) is not None,
            "Atomic amounts must be canonical unsigned decimal strings")
    result = int(value)
    require(result <= UINT64, "Atomic amount exceeds uint64")
    return result


def xmr(value):
    number = atomic(value)
    return "%d.%012d XMR" % (number // 10**12, number % 10**12)


def clean_text(value, maximum=4096):
    require(isinstance(value, str) and len(value) <= maximum,
            "Evidence text exceeds its bound")
    require(not any(ord(c) < 32 and c not in "\n\t" for c in value),
            "Evidence text contains control characters")
    return value


def reject_private_fields(value, depth=0):
    require(depth <= 32, "Evidence nesting exceeds its bound")
    if isinstance(value, dict):
        for key, child in value.items():
            require(isinstance(key, str), "Evidence object keys must be strings")
            normalized = re.sub(r"[^a-z0-9]", "", key.lower())
            require(normalized not in FORBIDDEN_FIELDS,
                    "Private-key, seed and credential fields are forbidden in public evidence")
            reject_private_fields(child, depth + 1)
    elif isinstance(value, list):
        require(len(value) <= 10000, "Evidence array exceeds its bound")
        for child in value:
            reject_private_fields(child, depth + 1)


def public_file(root, relative, digest, maximum):
    require(isinstance(relative, str) and relative and len(relative) <= 512,
            "Evidence file path is invalid")
    path = Path(relative)
    require(not path.is_absolute() and ".." not in path.parts,
            "Evidence file must remain inside its public bundle")
    current = root
    for part in path.parts:
        current = current / part
        require(not current.is_symlink(), "Evidence files must not use symlinks")
    require(current.is_file() and current.stat().st_size <= maximum,
            "Evidence file is missing or exceeds its bound")
    require(isinstance(digest, str) and SHA.fullmatch(digest) is not None,
            "Evidence file digest is invalid")
    data = current.read_bytes()
    require(sha256(data) == digest, "Evidence file SHA256 does not match")
    return current, data


def png_pixels(data):
    """Decode bounded 256x64 8-bit grayscale PNGs, including all row filters."""
    require(data[:8] == b"\x89PNG\r\n\x1a\n", "OLED file is not a PNG")
    offset, chunks, header, ended = 8, [], None, False
    while offset < len(data):
        require(offset + 12 <= len(data), "OLED PNG chunk is truncated")
        length = struct.unpack(">I", data[offset:offset + 4])[0]
        kind = data[offset + 4:offset + 8]
        require(length <= 1024 * 1024 and offset + 12 + length <= len(data),
                "OLED PNG chunk exceeds its bound")
        body = data[offset + 8:offset + 8 + length]
        crc = struct.unpack(">I", data[offset + 8 + length:offset + 12 + length])[0]
        require(zlib.crc32(kind + body) & 0xffffffff == crc,
                "OLED PNG checksum is invalid")
        if kind == b"IHDR":
            require(header is None and length == 13, "OLED PNG header is invalid")
            header = struct.unpack(">IIBBBBB", body)
        elif kind == b"IDAT":
            chunks.append(body)
        elif kind == b"IEND":
            require(length == 0, "OLED PNG end marker is invalid")
            ended = True
            offset += 12
            break
        elif kind in (b"tEXt", b"iTXt", b"zTXt"):
            raise EvidenceError("Text metadata is not allowed in public OLED PNGs")
        elif kind[:1].isupper():
            raise EvidenceError("Unsupported critical OLED PNG chunk")
        offset += 12 + length
    require(ended and offset == len(data) and header == (256, 64, 8, 0, 0, 0, 0),
            "OLED PNG must be non-interlaced 256x64 8-bit grayscale")
    decompressor = zlib.decompressobj()
    raw = decompressor.decompress(b"".join(chunks), 64 * 257 + 1)
    require(decompressor.eof and not decompressor.unused_data and
            not decompressor.unconsumed_tail and len(raw) == 64 * 257,
            "OLED PNG pixel stream is invalid")
    pixels, previous = bytearray(), bytearray(256)
    for y in range(64):
        filter_type = raw[y * 257]
        require(filter_type <= 4, "OLED PNG row filter is invalid")
        row = bytearray(raw[y * 257 + 1:(y + 1) * 257])
        for x in range(256):
            left = row[x - 1] if x else 0
            above = previous[x]
            corner = previous[x - 1] if x else 0
            if filter_type == 1:
                prediction = left
            elif filter_type == 2:
                prediction = above
            elif filter_type == 3:
                prediction = (left + above) // 2
            elif filter_type == 4:
                p = left + above - corner
                distances = [abs(p - left), abs(p - above), abs(p - corner)]
                prediction = (left, above, corner)[distances.index(min(distances))]
            else:
                prediction = 0
            row[x] = (row[x] + prediction) & 255
        require(all(p in (0, 255) for p in row), "OLED PNG is not a monochrome firmware frame")
        pixels.extend(row)
        previous = row
    return bytes(pixels)


def raw_pixels(frame):
    require(len(frame) == 2048, "Raw OLED frame must contain exactly 2048 bytes")
    return bytes(255 if frame[x + (y // 8) * 256] & (1 << (y % 8)) else 0
                 for y in range(64) for x in range(256))


def validate_compatibility(manifest, root, files):
    compatibility = manifest.get("compatibility")
    if compatibility is None:
        return
    require(isinstance(compatibility, dict) and compatibility.get("status") == "pass" and
            compatibility.get("same_artifact_unchanged") is True and
            compatibility.get("exhaustive_coin_coverage") is False and
            compatibility.get("firmware_commit") == manifest["provenance"]["firmware_commit"] and
            compatibility.get("library_sha256") == manifest["provenance"]["artifacts"]["library"]["sha256"],
            "Ordinary regression evidence does not match this Monero firmware artifact")
    dylib = compatibility.get("dylib_screenshot_suite", {})
    require(dylib.get("tests") == 4 and dylib.get("skipped") == 0,
            "Exact dylib must pass all four standard screenshot controls")
    native = compatibility.get("native_suites", [])
    require(isinstance(native, list) and len(native) == 4 and
            {suite.get("name") for suite in native} ==
            {"firmware-unit", "board-unit", "crypto-unit", "zcash-display-unit"},
            "Ordinary native regression suites are incomplete")
    for suite in [dylib] + native:
        require(suite.get("returncode") == 0 and type(suite.get("tests")) is int and
                suite["tests"] > 0 and suite.get("failures") == 0 and suite.get("errors") == 0 and
                type(suite.get("skipped")) is int and 0 <= suite["skipped"] < suite["tests"],
                "Ordinary regression suite failed or is empty")
        xml_path, xml = public_file(root, suite.get("junit_file"), suite.get("junit_sha256"), 4 * 1024 * 1024)
        cases = list(ET.fromstring(xml).iter("testcase"))
        failures = sum(case.find("failure") is not None for case in cases)
        errors = sum(case.find("error") is not None for case in cases)
        skipped = sum(case.find("skipped") is not None or case.get("status") == "notrun" for case in cases)
        require((len(cases), failures, errors, skipped) ==
                tuple(suite[key] for key in ("tests", "failures", "errors", "skipped")),
                "Ordinary regression counts do not match their retained JUnit")
        if suite is not dylib:
            require(isinstance(suite.get("binary_sha256"), str) and
                    SHA.fullmatch(suite["binary_sha256"]) is not None,
                    "Native regression executable identity is missing")
        files.append(xml_path)


def validate_evidence(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 16 * 1024 * 1024,
            "Monero evidence manifest is missing or exceeds its bound")
    payload = path.read_bytes()
    manifest = json.loads(payload)
    require(isinstance(manifest, dict) and manifest.get("schema_version") == 1,
            "Unsupported Monero evidence schema")
    reject_private_fields(manifest)
    scope = manifest.get("scope", {})
    require(scope.get("execution") == "native-emulator" and
            scope.get("network") == "offline-private-fakechain" and
            scope.get("physical_device_accessed") is False and
            scope.get("public_network_accessed") is False and
            scope.get("production_ready") is False,
            "This report requires explicit native-emulator/private-chain scope")
    provenance = manifest.get("provenance", {})
    require(COMMIT.fullmatch(provenance.get("firmware_commit", "")) is not None,
            "Firmware commit identity is invalid")
    sources = provenance.get("source_sha256", {})
    require(isinstance(sources, dict) and 1 <= len(sources) <= 512,
            "Source provenance is missing")
    for source, digest in sources.items():
        require(isinstance(source, str) and 0 < len(source) <= 512 and not Path(source).is_absolute() and
                ".." not in Path(source).parts and isinstance(digest, str) and SHA.fullmatch(digest) is not None,
                "Source provenance is invalid")
    artifacts = provenance.get("artifacts", {})
    require(isinstance(artifacts, dict), "Artifact provenance is missing")
    for role in ("library", "adapter", "daemon", "wallet_rpc", "independent_core", "signing_core"):
        require(isinstance(artifacts.get(role), dict) and
                SHA.fullmatch(artifacts[role].get("sha256", "")) is not None,
                "Required artifact identity is missing")
    root = path.resolve().parent
    screens, files = {}, []
    records = manifest.get("screens", [])
    require(isinstance(records, list) and 1 <= len(records) <= 512,
            "Actual OLED evidence is missing")
    for record in records:
        require(isinstance(record, dict), "OLED evidence record is invalid")
        identity = clean_text(record.get("id"), 128)
        require(identity and identity not in screens and record.get("width") == 256 and
                record.get("height") == 64 and record.get("approval") in ("approved", "rejected", "observed"),
                "OLED identity, dimensions or decision is invalid")
        require(type(record.get("sequence")) is int and record["sequence"] >= 0,
                "OLED review sequence is invalid")
        for field in ("title", "body", "role"):
            clean_text(record.get(field, ""))
        png_path, png = public_file(root, record.get("file"), record.get("png_sha256"), 1024 * 1024)
        raw_path, frame = public_file(root, record.get("raw_file"), record.get("raw_frame_sha256"), 2048)
        pixels = png_pixels(png)
        require(pixels == raw_pixels(frame), "OLED PNG pixels do not match the captured firmware frame")
        require(any(frame) and any(pixel == 0 for pixel in pixels),
                "OLED evidence must contain a nonblank firmware frame")
        pgm_path, pgm = public_file(root, record.get("pgm_file"), record.get("pgm_sha256"), 20000)
        require(pgm == b"P5\n256 64\n255\n" + pixels,
                "OLED PGM does not match the captured firmware frame")
        screens[identity] = {"record": record, "path": png_path, "pixels": pixels}
        files.extend((png_path, raw_path, pgm_path))
    receive = manifest.get("receive", {})
    require(ADDRESS.fullmatch(receive.get("address", "")) is not None,
            "Receive address is invalid")
    clean_text(receive.get("path", ""), 128)
    receive_ids = receive.get("screen_ids", [])
    require(isinstance(receive_ids, list) and len(receive_ids) >= 2 and
            all(identity in screens for identity in receive_ids),
            "Receive address and QR screen evidence is missing")
    transactions = manifest.get("transactions", [])
    require(isinstance(transactions, list) and 1 <= len(transactions) <= 32,
            "Signed transaction evidence is missing")
    used = set(receive_ids)
    for tx in transactions:
        require(isinstance(tx, dict) and SHA.fullmatch(tx.get("txid", "")) is not None,
                "Transaction identity is invalid")
        clean_text(tx.get("id"), 128)
        raw_path, raw = public_file(root, tx.get("raw_tx_file"), tx.get("raw_tx_sha256"), 65536)
        require(type(tx.get("bytes")) is int and tx["bytes"] == len(raw) and len(raw) > 128,
                "Serialized transaction evidence is inconsistent")
        files.append(raw_path)
        incoming = atomic(tx.get("input_total_atomic"))
        fee = atomic(tx.get("fee_atomic"))
        recipient = atomic(tx.get("recipient_amount_atomic"))
        change = atomic(tx.get("change_amount_atomic"))
        require(incoming == recipient + change + fee and fee > 0 and recipient > 0,
                "Reviewed input, output, change and fee amounts do not balance")
        outputs = tx.get("outputs", [])
        require(isinstance(outputs, list) and 2 <= len(outputs) <= 4,
                "Decoded transaction outputs are missing")
        indices, plan_indices, amounts = set(), set(), {"recipient": 0, "change": 0}
        for output in outputs:
            require(output.get("role") in amounts and
                    ADDRESS.fullmatch(output.get("address", "")) is not None and
                    output.get("commitment_verified") is True and
                    output.get("view_tag_verified") is True,
                    "Decoded output binding is incomplete")
            for field, length in (("one_time_public_key", 64), ("commitment", 64),
                                  ("view_tag", 2), ("encrypted_amount", 16)):
                if field in output:
                    require(isinstance(output[field], str) and
                            re.fullmatch(r"[0-9a-f]{%d}" % length, output[field]) is not None,
                            "Decoded output cryptographic field is invalid")
            index, plan = output.get("tx_output_index"), output.get("plan_output_index")
            require(type(index) is int and type(plan) is int and index not in indices and plan not in plan_indices,
                    "Decoded output order is ambiguous")
            indices.add(index); plan_indices.add(plan)
            amounts[output["role"]] += atomic(output.get("amount_atomic"))
            if output["role"] == "change":
                require(output["address"] == receive["address"], "Change is not bound to the reviewed wallet")
        require(indices == set(range(len(outputs))) and plan_indices == indices and
                amounts == {"recipient": recipient, "change": change},
                "Decoded outputs do not match the reviewed amount plan")
        verification = tx.get("verification", {})
        require(all(verification.get(name) is True for name in (
            "raw_prefix_parsed", "txid_matches_firmware", "core_clsag_bulletproof_verified",
            "outputs_scanned_and_commitments_verified", "fee_matches_review",
            "review_plan_matches_decoded_outputs")),
            "Transaction verification layers are incomplete")
        decoded = tx.get("decoded", {})
        require(decoded.get("version") == 2 and decoded.get("unlock_time") == 0 and
                decoded.get("ringct_type") == 6 and decoded.get("ring_size") == 16 and
                type(decoded.get("input_count")) is int and 1 <= decoded["input_count"] <= 4 and
                decoded.get("output_count") == len(outputs) and atomic(decoded.get("fee_atomic")) == fee,
                "Public Monero transaction parse is inconsistent")
        if "inputs" in tx:
            require(isinstance(tx["inputs"], list) and len(tx["inputs"]) == decoded["input_count"],
                    "Decoded input count does not match the public prefix")
            for member in tx["inputs"]:
                indices = member.get("indices", [])
                require(isinstance(member.get("key_image"), str) and
                        SHA.fullmatch(member["key_image"]) is not None and
                        isinstance(indices, list) and len(indices) == 16 and
                        all(type(value) is int and 0 <= value <= UINT64 for value in indices) and
                        indices == sorted(set(indices)), "Decoded public input ring is invalid")
        review = tx.get("review", [])
        require(isinstance(review, list) and len(review) >= 3, "Signing review evidence is missing")
        order = []
        for item in review:
            identity = item.get("screen_id")
            require(identity in screens, "Signing review refers to a missing OLED frame")
            screen = screens[identity]["record"]
            require(item.get("frame_sha256") == screen["raw_frame_sha256"] and
                    item.get("approval") == "approved" and screen["approval"] == "approved",
                    "Signing review frame or approval is not bound")
            if "title" in item:
                require(item["title"] == screen["title"], "Signing review title is inconsistent")
            if "body" in item:
                require(item["body"] == screen["body"], "Signing review body is inconsistent")
            order.append(screen["sequence"]); used.add(identity)
        require(order == sorted(set(order)), "Signing review screen order is invalid")
        daemon = tx.get("daemon", {})
        require(daemon.get("accepted") is True and type(daemon.get("confirmed_height")) is int and
                daemon["confirmed_height"] > 0 and daemon.get("key_images_spent") is True,
                "Official daemon acceptance, mining or spent-key-image proof is missing")
        wallet = tx.get("recipient_wallet", {})
        require(wallet.get("payment_found") is True and wallet.get("txid") == tx["txid"] and
                atomic(wallet.get("received_amount_atomic")) == recipient and
                atomic(wallet.get("balance_atomic")) >= recipient,
                "Stock recipient wallet did not prove receipt")
    rejection_cases = manifest.get("rejection_cases", [])
    require(isinstance(rejection_cases, list) and 1 <= len(rejection_cases) <= 32,
            "Actual review-refusal evidence is missing")
    for case in rejection_cases:
        require(case.get("signed_response_returned") is False and case.get("pool_empty") is True and
                case.get("derived_node_zero") is True, "Cancellation proof is incomplete")
        review = case.get("review", [])
        require(isinstance(review, list) and review, "Cancellation OLED proof is missing")
        rejected, order = 0, []
        for item in review:
            identity = item.get("screen_id")
            require(identity in screens, "Cancellation refers to a missing OLED frame")
            screen = screens[identity]["record"]
            require(item.get("approval") == screen["approval"] and
                    item.get("frame_sha256") == screen["raw_frame_sha256"],
                    "Cancellation frame or decision is inconsistent")
            rejected += screen["approval"] == "rejected"
            order.append(screen["sequence"])
            used.add(identity)
        require(rejected == 1 and review[-1]["approval"] == "rejected" and
                order == sorted(set(order)),
                "Cancellation must end at its exact rejected screen in observed order")
    require(used == set(screens), "The report bundle contains unreferenced OLED frames")
    validate_compatibility(manifest, root, files)
    return {"manifest": manifest, "manifest_path": path.resolve(), "manifest_sha256": sha256(payload),
            "screens": screens, "files": sorted(set(files)), "source_root": root}


def load_renderer(path=DEFAULT_RENDERER):
    path = Path(path)
    require(path.is_file(), "The pinned firmware PDF renderer is unavailable")
    spec = importlib.util.spec_from_file_location("monero_pinned_pdf_renderer", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    require(all(hasattr(module, name) for name in ("PDF", "PB", "GREEN", "RED", "GRAY")),
            "The pinned PDF writer has an incompatible interface")
    return module


def _paragraph(builder, text, size=9, bold=False, color=None):
    for line in str(text).splitlines() or [""]:
        builder.text(size, line, bold=bold, color=color)


def _new_page(builder):
    builder.finish()


def _screen(builder, bundle, identity, caption):
    item = bundle["screens"][identity]
    record, path = item["record"], str(item["path"])
    builder.need(240)
    _paragraph(builder, caption, 10, True)
    # Register verified decoded pixels directly. The older pinned writer's
    # minimal PNG reader does not implement row filters, so do not re-read it.
    if path not in builder.pdf.images:
        name = "Im%d" % builder.pdf._img_counter
        builder.pdf._img_counter += 1
        builder.pdf.images[path] = (name, item["pixels"], 256, 64)
    builder.image(path, display_w=512, display_h=128)
    _paragraph(builder, "Recorded device title: " + record["title"], 8, True)
    _paragraph(builder, "Recorded device body: " + record["body"], 8)
    _paragraph(builder, "Decision: %s | capture sequence: %d | frame SHA256: %s" %
               (record["approval"], record["sequence"], record["raw_frame_sha256"]), 6, color=(.4, .4, .4))
    builder.gap(9)


def render_section(renderer, pdf, bundle, standalone=False):
    start = len(pdf.pages)
    pb = renderer.PB(pdf)
    m = bundle["manifest"]
    _paragraph(pb, "Monero firmware verification", 22, True)
    _paragraph(pb, "Bounded native-emulator workflow", 13, True, renderer.GREEN)
    _paragraph(pb, "Physical-device signing: not implemented / not proven", 12, True, renderer.RED)
    pb.gap(8)
    _paragraph(pb, "The screenshots in this report are actual firmware OLED output. Every PNG was checked against the retained 2048-byte framebuffer, not redrawn as a mockup.")
    _paragraph(pb, "Transactions use real Monero encoding and signatures on an isolated local Monero Core chain. The test driver uses published disposable fixtures and automated button decisions. No public-network payment or physical-device execution is established by this run.")
    pb.gap(5)
    _paragraph(pb, "What the evidence establishes", 12, True)
    for text in (
            "Actual seed-derived XMR address, full-address review and QR frames.",
            "Exact destination/change amounts and fee reviewed on the firmware screen before the signed response.",
            "Serialized signed transaction, parser/output-scan binding, official daemon acceptance and mining, and stock recipient-wallet credit.",
            "Recorded review refusals with no signed response and an empty transaction pool."):
        _paragraph(pb, "- " + text)
    pb.gap(5)
    _paragraph(pb, "Proof boundaries", 12, True)
    _paragraph(pb, "Public transaction parsing proves structure, rings and plaintext fee. Recipient addresses and amounts are confidential in Monero; the report separately shows output recovery with the published fixture view keys and commitment checks. Those keys are not included in this public evidence bundle.")
    _paragraph(pb, "Monero Core constructs and verifies CLSAG/Bulletproof+ proofs. That verification is not an independent second implementation. A separate parser, transaction hashing, output scanner and recipient-wallet observation provide additional binding checks.")
    _paragraph(pb, "Full signing here depends on a native Monero Core bridge. An MCU signer, hardware RAM/stack/timing evidence and physical approval tests remain required before calling this complete device firmware.", bold=True)
    pb.gap(6)
    _paragraph(pb, "Firmware commit: " + m["provenance"]["firmware_commit"], 8)
    _paragraph(pb, "Public manifest SHA256: " + bundle["manifest_sha256"], 8)
    _paragraph(pb, "Signed/accepted transactions: %d | retained OLED decisions: %d" %
               (len(m["transactions"]), len(m["screens"])), 9, True)
    _new_page(pb)

    compatibility = m.get("compatibility")
    if compatibility:
        _paragraph(pb, "Ordinary firmware regression coverage", 16, True)
        _paragraph(pb, "The four standard screenshot/transport controls executed the exact full Monero-enabled dylib used for this report. Native controls ran as separate executables linked to the unchanged firmware archive and objects from that same build.", 10)
        _paragraph(pb, "Library SHA256: " + compatibility["library_sha256"], 8)
        pb.gap(6)
        suites = [("Exact dylib screenshot controls", compatibility["dylib_screenshot_suite"])]
        suites += [(suite["name"], suite) for suite in compatibility["native_suites"]]
        for label, suite in suites:
            _paragraph(pb, "%s: %d passed; %d skipped; 0 failures; 0 errors" %
                       (label, suite["tests"] - suite["skipped"], suite["skipped"]), 10, True, renderer.GREEN)
            _paragraph(pb, "Retained JUnit SHA256: " + suite["junit_sha256"], 7)
            if "binary_sha256" in suite:
                _paragraph(pb, "Native executable SHA256: " + suite["binary_sha256"], 7)
            pb.gap(5)
        _paragraph(pb, "This broad regression sample does not establish exhaustive coin coverage, MCU signing, a device flash/boot test, or physical approval behavior.", 10, True)
        _new_page(pb)

    _paragraph(pb, "1. Receive address displayed by firmware", 16, True)
    _paragraph(pb, "Address: " + m["receive"]["address"], 10, True)
    _paragraph(pb, "Derivation path: " + m["receive"].get("path", ""), 9)
    _paragraph(pb, "The local-chain run uses the actual address returned through the normal HID/protobuf command path. Readable address pages and the QR are retained in their observed order.", 9)
    pb.gap(8)
    for index, identity in enumerate(m["receive"]["screen_ids"], 1):
        _screen(pb, bundle, identity, "Receive screen %d" % index)
    _new_page(pb)

    for number, tx in enumerate(m["transactions"], 1):
        _paragraph(pb, "2.%d Signed transaction: %s" % (number, tx["id"]), 16, True)
        _paragraph(pb, "Transaction id: " + tx["txid"], 9, True)
        _paragraph(pb, "Serialized bytes: %d | SHA256: %s" % (tx["bytes"], tx["raw_tx_sha256"]), 8)
        for label, key in (("Input total", "input_total_atomic"), ("Recipient total", "recipient_amount_atomic"),
                           ("Owned change", "change_amount_atomic"), ("Fee", "fee_atomic")):
            _paragraph(pb, "%s: %s (%s atomic units)" % (label, xmr(tx[key]), tx[key]), 10, True)
        pb.gap(5)
        _paragraph(pb, "Decoded and view-key-scanned outputs", 12, True)
        _paragraph(pb, "Addresses/amounts below come from output recovery and commitment checks; they are not plaintext destination fields read directly from the raw transaction.", 8)
        for output in sorted(tx["outputs"], key=lambda value: value["tx_output_index"]):
            _paragraph(pb, "Wire output %d <- review output %d | %s | %s" %
                       (output["tx_output_index"], output["plan_output_index"], output["role"], xmr(output["amount_atomic"])), 9, True)
            _paragraph(pb, "Address: " + output["address"], 8)
            _paragraph(pb, "Amount commitment and view tag: verified", 8, color=renderer.GREEN)
            for field in ("one_time_public_key", "view_tag", "encrypted_amount", "commitment"):
                if field in output:
                    _paragraph(pb, field.replace("_", " ") + ": " + output[field], 7)
        decoded = tx.get("decoded", {})
        if decoded:
            pb.gap(4)
            _paragraph(pb, "Public transaction parse", 11, True)
            for key in ("version", "unlock_time", "ringct_type", "ring_size", "input_count", "output_count", "fee_atomic"):
                if key in decoded:
                    _paragraph(pb, "%s: %s" % (key.replace("_", " "), decoded[key]), 8)
        for index, member in enumerate(tx.get("inputs", [])):
            _paragraph(pb, "Input %d key image: %s" % (index, member["key_image"]), 8)
            _paragraph(pb, "Public ring absolute output indices: " + ", ".join(map(str, member["indices"])), 7)
        daemon = tx["daemon"]
        pb.gap(5)
        _paragraph(pb, "Official Core node: accepted; mined at height %d; input key images spent." % daemon["confirmed_height"], 9, True, renderer.GREEN)
        _paragraph(pb, "Stock recipient wallet found this payment; observed balance: " + xmr(tx["recipient_wallet"]["balance_atomic"]), 9, True, renderer.GREEN)
        _paragraph(pb, "Input = recipient + owned change + fee: verified exactly in atomic units.", 9)
        _new_page(pb)
        _paragraph(pb, "2.%d Firmware review screens, in actual order" % number, 15, True)
        for index, review in enumerate(tx["review"], 1):
            _screen(pb, bundle, review["screen_id"], "Transaction %d / review %d" % (number, index))
        _new_page(pb)

    rejections = m.get("rejection_cases", [])
    if rejections:
        _paragraph(pb, "3. Refusal prevents signature release", 16, True)
        _paragraph(pb, "These are actual firmware review cancellations. The host observed a failure, no signed-transaction response, an empty local daemon pool, and cleared candidate-owned derivation scratch.", 9)
        for case in rejections:
            pb.gap(5)
            _paragraph(pb, "Case: " + case.get("name", case.get("target", "review refusal")), 11, True)
            _paragraph(pb, "No signed response: PASS | pool empty: PASS | owned derived-node scratch cleared: PASS", 8, True, renderer.GREEN)
            for index, item in enumerate(case["review"], 1):
                _screen(pb, bundle, item["screen_id"], "Cancellation review %d: %s" %
                        (index, item["approval"]))
        _new_page(pb)

    _paragraph(pb, "4. Provenance and reproducibility", 16, True)
    _paragraph(pb, "Every listed image and raw transaction was hashed and validated before rendering. A missing frame, pixel mismatch, changed file, missing acceptance proof or inconsistent amount equation stops report generation.", 9)
    _paragraph(pb, "Evidence manifest SHA256: " + bundle["manifest_sha256"], 8)
    _paragraph(pb, "Firmware commit: " + m["provenance"]["firmware_commit"], 8)
    for role, artifact in sorted(m["provenance"]["artifacts"].items()):
        if isinstance(artifact, dict) and SHA.fullmatch(artifact.get("sha256", "")):
            _paragraph(pb, role.replace("_", " ") + " SHA256: " + artifact["sha256"], 8, True)
            for field in ("filename", "release", "commit", "reference_commit"):
                if field in artifact:
                    _paragraph(pb, field.replace("_", " ") + ": " + clean_text(artifact[field], 256), 8)
    pb.gap(6)
    _paragraph(pb, "Source file SHA256", 11, True)
    for source, digest in sorted(m["provenance"]["source_sha256"].items()):
        _paragraph(pb, source, 7, True)
        _paragraph(pb, digest, 7)
    pb.finish()
    count = len(pdf.pages) - start
    for index in range(start, len(pdf.pages)):
        content, width, height, images = pdf.pages[index]
        footer = "Native-emulator evidence | XMR page %d/%d | Physical readiness not proven" % (index - start + 1, count)
        content += "\n0.4 0.4 0.4 rg BT /F1 7 Tf 40 25 Td (%s) Tj ET 0 0 0 rg" % footer
        pdf.pages[index] = (content, width, height, images)
    return count


def report_receipt(output, bundle, renderer_path, pages):
    output = Path(output)
    receipt = {"schema_version": 1, "scope": bundle["manifest"]["scope"],
               "evidence_manifest_sha256": bundle["manifest_sha256"],
               "renderer_sha256": sha256(Path(renderer_path).read_bytes()),
               "monero_report_generator_sha256": sha256(Path(__file__).read_bytes()),
               "pdf_sha256": sha256(output.read_bytes()), "monero_pages": pages,
               "transaction_count": len(bundle["manifest"]["transactions"]),
               "screen_count": len(bundle["screens"])}
    output.with_suffix(output.suffix + ".monero.json").write_text(json.dumps(receipt, indent=2) + "\n")
    output.with_suffix(output.suffix + ".sha256").write_text(receipt["pdf_sha256"] + "  " + output.name + "\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=Path("monero-firmware-report.pdf"))
    parser.add_argument("--canonical-renderer", type=Path)
    parser.add_argument("renderer_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    bundle = validate_evidence(args.evidence)
    renderer_path = args.canonical_renderer or DEFAULT_RENDERER
    renderer = load_renderer(renderer_path)
    if args.canonical_renderer:
        require(args.renderer_args[:1] == ["--"], "Canonical renderer arguments require a separator")
        original_write = renderer.PDF.write
        def write_with_monero(pdf, output):
            pages = render_section(renderer, pdf, bundle)
            original_write(pdf, output)
            report_receipt(output, bundle, renderer_path, pages)
        renderer.PDF.write = write_with_monero
        original_argv = sys.argv
        try:
            sys.argv = [str(renderer_path)] + args.renderer_args[1:]
            renderer.main()
        finally:
            sys.argv = original_argv
            renderer.PDF.write = original_write
    else:
        require(not args.renderer_args, "Unexpected standalone report arguments")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        pdf = renderer.PDF()
        pages = render_section(renderer, pdf, bundle, standalone=True)
        pdf.write(args.output)
        report_receipt(args.output, bundle, renderer_path, pages)
        print(json.dumps({"pdf": str(args.output), "pages": pages,
                          "evidence_manifest_sha256": bundle["manifest_sha256"],
                          "physical_device_ready": False}))


if __name__ == "__main__":
    try:
        main()
    except (EvidenceError, OSError, ValueError, KeyError, TypeError, zlib.error, ET.ParseError) as error:
        print("ERROR: Monero report evidence could not be validated: " + str(error), file=sys.stderr)
        sys.exit(1)
