#!/usr/bin/env python3
"""Rerun encrypted public wallet-export fixtures without a daemon or emulator.

The expected binary plans were created independently before official wallet2
serialized and authenticated the request containers. The four-input fixture
deliberately reverses selected_transfers relative to the source order.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from host_emulator import plan_from_adapter, signing

HERE = Path(__file__).resolve().parent
NAMES = ("base", "subaddress", "four-inputs-reversed-selection")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def invoke(executable, request, out, label, expected_status):
    process = subprocess.run([str(executable)], input=json.dumps(request).encode(),
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    require(len(process.stdout) <= 1024 * 1024, label + ": adapter response exceeds fixture bound")
    require(not process.stderr, label + ": unexpected adapter stderr")
    # json.loads also rejects multiple protocol responses or trailing text.
    value = json.loads(process.stdout)
    require(type(value) is dict and value.get("status") == expected_status,
            label + ": unexpected adapter status")
    expected_returncode = 0 if expected_status == "pass" else 1
    require(process.returncode == expected_returncode, label + ": unexpected adapter exit status")
    if expected_status == "error":
        require(isinstance(value.get("error"), str) and 0 < len(value["error"]) <= 160,
                label + ": missing bounded public diagnostic")
    (out / (label + ".json")).write_text(json.dumps(value, indent=2) + "\n")
    return value


def expected_outputs(plan):
    result = []
    for index in range(plan.input_count):
        source = plan.sources[index]
        real = source.ring[source.real_member]
        result.append({
            "transfer_index": index, "amount": source.amount, "global_index": real.global_index,
            "out_key": bytes(real.public_key).hex(), "tx_public_key": bytes(source.tx_public_key).hex(),
            "additional_tx_public_keys": [bytes(source.additional_tx_public_keys[n]).hex()
                                           for n in range(source.additional_key_count)],
            "output_index": source.output_index, "subaddress_major": source.subaddress_major,
            "subaddress_minor": source.subaddress_minor,
        })
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-adapter", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--fixtures-dir", type=Path,
                        default=HERE / "evidence/2026-11-04-host/fixtures")
    args = parser.parse_args()
    executable, out, fixtures = args.host_adapter.resolve(), args.output.resolve(), args.fixtures_dir.resolve()
    require(executable.is_file(), "Missing host adapter executable")
    out.mkdir(parents=True, exist_ok=True)
    require(not any(out.iterdir()), "Output directory must be empty")
    report = {
        "status": "running", "adapter": str(executable),
        "adapter_sha256": digest(executable.read_bytes()), "fixtures_dir": str(fixtures),
        "public_fixtures_only": True, "daemon_started": False, "socket_opened": False,
        "fixture_sha256": {}, "cases": [],
    }
    sources = [Path(__file__), HERE / "host_emulator.py", HERE / "host-adapter.cpp",
               HERE / "build_host.py", HERE / "build_core.py",
               HERE / "commands/test_signing.py", HERE / "commands/test_key_image.py",
               HERE / "commands/test_wire.py", HERE / "commands/core-signing.h"]
    report["source_sha256"] = {str(path.relative_to(HERE)): digest(path.read_bytes()) for path in sources}
    try:
        baseline = None
        for name in NAMES:
            request_path, plan_path = fixtures / (name + "-request.json"), fixtures / (name + "-plan.bin")
            request_bytes, plan_bytes = request_path.read_bytes(), plan_path.read_bytes()
            report["fixture_sha256"][request_path.name] = digest(request_bytes)
            report["fixture_sha256"][plan_path.name] = digest(plan_bytes)
            require(len(plan_bytes) == ctypes.sizeof(signing.Plan), name + ": unexpected native plan ABI size")
            expected = signing.Plan.from_buffer_copy(plan_bytes)
            require(expected.network == 0 and expected.output_count == 2 and 1 <= expected.input_count <= 4,
                    name + ": unexpected fixture plan shape")
            request = json.loads(request_bytes)
            require(set(request) == {"op", "address", "view_key", "outputs_data_hex", "unsigned_txset"}
                    and request["op"] == "plan", name + ": unexpected fixture request schema")
            require(request["address"] == bytes(expected.destinations[1].address).decode("ascii"),
                    name + ": fixture wallet address mismatch")
            if baseline is None:
                baseline = request
            else:
                require(request["address"] == baseline["address"] and request["view_key"] == baseline["view_key"],
                        name + ": fixtures must use the same published watch wallet")
            plan_reply = invoke(executable, request, out, name + "-plan", "pass")
            actual = plan_from_adapter(plan_reply)
            require(bytes(actual) == plan_bytes, name + ": adapter plan differs from independent expected binary plan")
            metadata_request = dict(request, op="outputs")
            metadata = invoke(executable, metadata_request, out, name + "-outputs", "pass")
            expected_metadata = {"status": "pass", "offset": 0, "total": expected.input_count,
                                 "outputs": expected_outputs(expected)}
            require(metadata == expected_metadata, name + ": exported output metadata mismatch")
            report["cases"].append({"name": name, "status": "pass", "checks": [
                "exact-binary-plan", "exact-output-metadata", "clean-json-protocol"],
                "inputs": expected.input_count, "outputs": expected.output_count})

        for field in ("outputs_data_hex", "unsigned_txset"):
            request = dict(baseline)
            corrupt = bytearray.fromhex(request[field])
            require(bool(corrupt), "Empty encrypted fixture")
            corrupt[-1] ^= 1
            request[field] = corrupt.hex()
            name = "tamper-" + field
            invoke(executable, request, out, name, "error")
            report["cases"].append({"name": name, "status": "pass",
                                    "checks": ["authenticated-container-tamper-rejected", "clean-json-protocol"]})

        request = dict(baseline, spendkey="never accepted")
        invoke(executable, request, out, "spendkey-field-rejected", "error")
        report["cases"].append({"name": "spendkey-field-rejected", "status": "pass",
                                "checks": ["spend-key-request-field-rejected", "clean-json-protocol"]})
        report["status"] = "pass"
        report["case_count"] = len(report["cases"])
        require(report["case_count"] == 6, "Incomplete adapter regression suite")
    except Exception as error:
        report["status"] = "fail"
        report["error"] = str(error)
        raise
    finally:
        (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "case_count": report["case_count"],
                      "adapter_sha256": report["adapter_sha256"], "report": str(out / "result.json")}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
