#!/usr/bin/env python3
"""Run the emulator wallet against an isolated, offline Monero regtest chain.

The emulator owns the public BIP39 fixture. Its host wallet receives only the
explicitly exported view key and encrypted key-image proofs. Stock wallet RPC
selects real chain outputs and decoys; the emulator authorizes both spends.
"""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "commands"))
import test_key_image as key_images
import test_signing as signing
import test_wire as wire

ATOMIC = 10**12
FUNDING = 12 * ATOMIC
SEND_AMOUNTS = [ATOMIC, 2 * ATOMIC]


class RpcError(RuntimeError):
    def __init__(self, name, method, error):
        self.error = error
        super().__init__(f"{name}.{method}: {error}")


class SessionStop(Exception):
    def __init__(self, signum):
        self.signum = signum
        super().__init__(f"Stopped by {signal.Signals(signum).name}")


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Rpc:
    def __init__(self, name, port, transcript):
        self.name = name
        self.url = f"http://127.0.0.1:{port}"
        self.log = transcript
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def post(self, path, params, timeout=60):
        payload = json.dumps(params).encode()
        request = urllib.request.Request(self.url + path, payload, {"Content-Type": "application/json"})
        with self.opener.open(request, timeout=timeout) as response:
            raw = response.read(32 * 1024 * 1024 + 1)
        if len(raw) > 32 * 1024 * 1024:
            raise RuntimeError("local RPC response exceeds the host experiment bound")
        value = json.loads(raw)
        self.log.append({"endpoint": self.name, "path": path,
                         "method": params.get("method", path),
                         "request_sha256": digest(payload), "response_sha256": digest(raw),
                         "response_bytes": len(raw)})
        return value

    def call(self, method, params=None, timeout=60):
        value = self.post("/json_rpc", {"jsonrpc": "2.0", "id": "0", "method": method,
                                        "params": params or {}}, timeout)
        if "error" in value:
            raise RpcError(self.name, method, value["error"])
        if "result" not in value:
            raise RuntimeError(f"{self.name}.{method} returned no result")
        return value["result"]


def ports(count):
    held, values = [], []
    try:
        for _ in range(count):
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            held.append(sock)
            values.append(sock.getsockname()[1])
        return values
    finally:
        for sock in held:
            sock.close()


class Processes:
    def __init__(self, out):
        self.out, self.items = out, []

    def start(self, name, command):
        log = (self.out / f"{name}-process.log").open("w")
        log.write(json.dumps(list(map(str, command))) + "\n")
        log.flush()
        process = subprocess.Popen(list(map(str, command)), cwd=self.out, stdin=subprocess.DEVNULL,
                                   stdout=log, stderr=subprocess.STDOUT)
        self.items.append((name, process, log))
        return process

    def close(self):
        errors = []
        for _, process, _ in reversed(self.items):
            if process.poll() is None:
                try:
                    process.terminate()
                except OSError as error:
                    errors.append(str(error))
        for _, process, log in reversed(self.items):
            try:
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired) as error:
                errors.append(str(error))
            finally:
                log.close()
        if errors:
            raise RuntimeError("local process cleanup failed: " + "; ".join(errors))


def wait_ready(rpc, process, method):
    until = time.monotonic() + 60
    while time.monotonic() < until:
        if process.poll() is not None:
            raise RuntimeError(f"{rpc.name} stopped during startup; see its process log")
        try:
            return rpc.call(method, timeout=2)
        except (OSError, ValueError, urllib.error.URLError, RpcError):
            time.sleep(.1)
    raise RuntimeError(f"{rpc.name} did not start within sixty seconds")


def checked_int(value, maximum=2**64-1):
    if type(value) is not int or not 0 <= value <= maximum:
        raise RuntimeError("host adapter returned an invalid integer")
    return value


def bytes32(value):
    if not isinstance(value, str) or len(value) != 64:
        raise RuntimeError("host adapter returned a malformed 32-byte field")
    result = bytes.fromhex(value)
    if len(result) != 32:
        raise RuntimeError("host adapter returned a malformed 32-byte field")
    return result


def plan_from_adapter(value):
    plan = signing.Plan()
    if value.get("status") != "pass" or value.get("network") != 0:
        raise RuntimeError("host adapter did not return a fakechain-compatible plan")
    inputs, outputs = value["inputs"], value["outputs"]
    if not 1 <= len(inputs) <= 4 or not 2 <= len(outputs) <= 4:
        raise RuntimeError("stock wallet selection exceeds the emulator experiment bounds")
    plan.input_count, plan.output_count = len(inputs), len(outputs)
    plan.fee = checked_int(value["fee"])
    for n, item in enumerate(inputs):
        source = plan.sources[n]
        source.amount = checked_int(item["amount"])
        for field in ["real_member", "output_index", "subaddress_major", "subaddress_minor"]:
            setattr(source, field, checked_int(item[field], 2**32-1))
        if source.real_member >= 16 or len(item["ring"]) != 16:
            raise RuntimeError("stock wallet plan must use sixteen-member rings")
        signing.set_bytes(source.tx_public_key, bytes32(item["tx_public_key"]))
        signing.set_bytes(source.mask, bytes32(item["mask"]))
        additional = item.get("additional_tx_public_keys", [])
        if len(additional) > 16:
            raise RuntimeError("stock wallet source has too many additional transaction keys")
        source.additional_key_count = len(additional)
        for i, point in enumerate(additional):
            signing.set_bytes(source.additional_tx_public_keys[i], bytes32(point))
        for i, member in enumerate(item["ring"]):
            source.ring[i].global_index = checked_int(member["global_index"])
            signing.set_bytes(source.ring[i].public_key, bytes32(member["public_key"]))
            signing.set_bytes(source.ring[i].commitment, bytes32(member["commitment"]))
    for n, item in enumerate(outputs):
        output = plan.destinations[n]
        output.amount = checked_int(item["amount"])
        address = item["address"].encode("ascii")
        if not output.amount or len(address) != 95 or type(item["is_change"]) is not bool:
            raise RuntimeError("stock wallet output is outside the positive base/subaddress experiment")
        output.address = address
        output.is_change = int(item["is_change"])
        output.change_major = checked_int(item.get("change_major", 0), 2**32-1)
        output.change_minor = checked_int(item.get("change_minor", 0), 2**32-1)
    return plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--host-adapter", type=Path, required=True)
    parser.add_argument("--core-library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--keep-running", action="store_true",
                        help="Keep the verified local emulator and RPC services running until SIGINT/SIGTERM")
    parser.add_argument("--reference", type=Path, default=HERE / "evidence/2026-11-04-interoperability/host.json")
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        parser.error("output directory must be empty")
    for path in [args.bin_dir / "monerod", args.bin_dir / "monero-wallet-rpc", args.host_adapter,
                 args.library, args.core_library]:
        if not path.is_file():
            parser.error(f"required local artifact is missing: {path}")
    ref = json.loads(args.reference.read_text()); ref = ref.get("reference", ref)
    if ref.get("fixture_mnemonics_public") != wire.PUBLIC_FIXTURES:
        parser.error("only the checked-in public emulator fixture is permitted")
    watch_case = next(c for c in ref["cases"] if c["label"] == "abandon-account0-sub0-0-output0")
    recipient_case = next(c for c in ref["cases"] if c["label"] == "trezor-account0-sub0-0-output0")
    spec = importlib.util.spec_from_file_location("host_reference", HERE / "reference.py")
    reference = importlib.util.module_from_spec(spec); spec.loader.exec_module(reference)
    core = reference.Core(args.core_library.resolve()); reference.known_anchors(core)
    sodium = key_images.Sodium()
    checks = wire.Checks()
    processes = Processes(out)
    rpc_log, stages, transactions = [], [], []
    session = None
    daemon_port, p2p_port, faucet_port, watch_port, recipient_port = ports(5)
    daemon = Rpc("daemon", daemon_port, rpc_log)
    faucet = Rpc("faucet", faucet_port, rpc_log)
    watch = Rpc("watch", watch_port, rpc_log)
    recipient = Rpc("recipient", recipient_port, rpc_log)
    endpoints = {"daemon": daemon_port, "p2p": p2p_port, "faucet": faucet_port,
                 "watch": watch_port, "recipient": recipient_port}
    views, address, imported = {}, None, {}
    status, failure = "error", None
    live_session, stop_signal = None, None
    previous_signals = {}

    def write_report(lifecycle):
        report = {"schema_version": 1, "status": status, "error": failure, "stages": stages,
                  "checks": checks.items, "check_count": len(checks.items), "transactions": transactions,
                  "endpoints": endpoints, "network": "isolated offline regtest (mainnet-format fixture addresses)",
                  "scope": "stock daemon and watch-only wallet RPC with emulator view export, encrypted key images, two authorized spends and real local-chain confirmation",
                  "funding": "ordinary confidential faucet transfer funded by private-chain block rewards",
                  "physical_device_accessed": False, "public_network_accessed": False,
                  "transactions_submitted_only_to_owned_loopback_regtest_daemon": True,
                  "host_wallet_has_emulator_spend_key": False, "production_ready": False,
                  "keep_running_requested": args.keep_running, "session_lifecycle": lifecycle,
                  "source_sha256": digest(Path(__file__).read_bytes()),
                  "library_sha256": digest(args.library.read_bytes()),
                  "host_adapter_sha256": digest(args.host_adapter.read_bytes()),
                  "independent_core_sha256": digest(args.core_library.read_bytes()),
                  "binary_sha256": {name: digest((args.bin_dir/name).read_bytes()) for name in ["monerod", "monero-wallet-rpc"]},
                  "frames": session.frames if session else [], "rpc_transcript": rpc_log}
        (out / "result.json").write_text(json.dumps(report, indent=2)+"\n")

    def request_stop(signum, _frame):
        raise SessionStop(signum)

    def stage(name, **detail):
        stages.append({"stage": len(stages)+1, "name": name, "status": "pass", **detail})
        (out / "stages.json").write_text(json.dumps(stages, indent=2) + "\n")
        print(f"stage {len(stages)}/9: {name}", flush=True)

    def refresh(wallet):
        wallet.call("refresh", {"start_height": 0})
        return wallet.call("get_balance", {"account_index": 0})

    def mine(count):
        daemon.call("generateblocks", {"wallet_address": faucet_address, "amount_of_blocks": count}, timeout=180)
        return daemon.post("/get_height", {})["height"]

    def adapter(op, label, outputs_hex, unsigned=None):
        request = {"op": op, "address": address, "view_key": views["watch"],
                   "outputs_data_hex": outputs_hex}
        if unsigned is not None:
            request["unsigned_txset"] = unsigned
        raw = json.dumps(request).encode()
        result = subprocess.run([str(args.host_adapter.resolve())], input=raw,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        (out / f"{label}-adapter.stderr").write_bytes(result.stderr)
        if len(result.stdout) > 4 * 1024 * 1024:
            raise RuntimeError("read-only host adapter exceeded the response bound")
        value = json.loads(result.stdout)
        (out / f"{label}-adapter.json").write_text(json.dumps(value, indent=2) + "\n")
        if result.returncode or value.get("status") != "pass":
            raise RuntimeError(f"host adapter failed: {value.get('error', 'no public diagnostic')}")
        return value

    def synchronize(label):
        encoded = watch.call("export_outputs", {"all": True})["outputs_data_hex"]
        (out / f"{label}-outputs.hex").write_text(encoded+"\n")
        decoded = adapter("outputs", label, encoded)
        items = decoded["outputs"]
        offset = checked_int(decoded["offset"], 2**32-1)
        if not 1 <= len(items) <= 64 or offset != 0:
            raise RuntimeError("full watch-wallet output export is outside key-image bounds")
        records = []
        for i, item in enumerate(items):
            if checked_int(item["transfer_index"]) != offset+i:
                raise RuntimeError("adapter changed wallet transfer ordering")
            case = {"output_public": bytes32(item["out_key"]).hex(),
                    "tx_public": bytes32(item["tx_public_key"]).hex(),
                    "output_index": checked_int(item["output_index"], 2**32-1),
                    "major": checked_int(item["subaddress_major"], 2**32-1),
                    "minor": checked_int(item["subaddress_minor"], 2**32-1)}
            records.append(key_images.transfer(case, additional=[bytes32(p) for p in item["additional_tx_public_keys"]]))
        msg, events, screens = session.rpc(530, key_images.init_request(core, records))
        checks.record(label+"-key-image-consent", msg[0] == 531 and 26 in events and bool(screens))
        encrypted = []
        for start in range(0, len(records), 4):
            batch = records[start:start+4]
            msg, _, _ = session.rpc(532, b"".join(wire.fb(1, record["body"]) for record in batch))
            checks.record(label+f"-encrypted-batch-{start}", msg[0] == 533)
            values = wire.fields(msg[1]).get(1, [])
            checks.record(label+f"-batch-count-{start}", len(values) == len(batch))
            for value in values:
                data = wire.fields(value)
                nonce, blob = wire.only(data, 1), wire.only(data, 3)
                if len(nonce) != 12 or len(blob) != 112:
                    raise RuntimeError("unexpected encrypted key-image dimensions")
                encrypted.append((nonce, blob))
        msg, _, _ = session.rpc(534)
        checks.record(label+"-bound-final-releases-key", msg[0] == 535)
        encryption_key = wire.only(wire.fields(msg[1]), 1)
        proofs = []
        for i, (record, value) in enumerate(zip(records, encrypted)):
            plaintext = sodium.decrypt(encryption_key, *value)
            checks.record(label+f"-independent-ring-one-proof-{i}", key_images.verify_proof(core, plaintext, record["output"]))
            proof = {"key_image": plaintext[:32].hex(), "signature": plaintext[32:].hex()}
            proofs.append(proof)
            imported[record["output"].hex()] = {**proof, "amount": items[i]["amount"],
                                                 "transfer_index": items[i]["transfer_index"]}
        result = watch.call("import_key_images", {"offset": offset, "signed_key_images": proofs})
        checks.record(label+"-stock-wallet-imported-proofs", result["height"] > 0)
        (out / f"{label}-key-images.json").write_text(json.dumps({"offset": offset, "proofs": proofs, "import_result": result}, indent=2)+"\n")
        return encoded, items, result

    def make_signed(number, amount, outputs_hex, allowed_inputs):
        label = f"send-{number}"
        selected = watch.call("transfer", {"destinations": [{"address": recipient_address, "amount": amount}],
                                           "account_index": 0, "ring_size": 16, "priority": 1,
                                           "unlock_time": 0, "do_not_relay": True, "get_tx_hex": True})
        unsigned = selected.get("unsigned_txset", "")
        checks.record(label+"-stock-watch-wallet-generated-unsigned-txset", bool(unsigned))
        (out / f"{label}-unsigned-txset.hex").write_text(unsigned+"\n")
        decoded = adapter("plan", label, outputs_hex, unsigned)
        plan = plan_from_adapter(decoded)
        checks.record(label+"-wallet-selected-fee", plan.fee == selected["fee"] and plan.fee > 0)
        checks.record(label+"-requested-recipient-amount", sum(d.amount for d in plan.destinations[:plan.output_count] if bytes(d.address).decode() == recipient_address and not d.is_change) == amount)
        checks.record(label+"-positive-owned-change", sum(d.is_change for d in plan.destinations[:plan.output_count]) == 1 and all(not d.is_change or bytes(d.address).decode() == address for d in plan.destinations[:plan.output_count]))
        expected_images, real_keys = {}, []
        for source in plan.sources[:plan.input_count]:
            real = bytes(source.ring[source.real_member].public_key).hex()
            checks.record(label+f"-selected-input-{len(real_keys)}-is-owned-unspent-output", real in allowed_inputs and real in imported)
            real_keys.append(real)
            expected_images[imported[real]["key_image"]] = source
        session.send(65000, signing.encode_plan(plan))
        screens = []
        while True:
            msg = session.receive(60)
            if not msg:
                raise RuntimeError("emulator signing timed out")
            if msg[0] != 26:
                break
            meta = session.observe_screen(label+f"-review-{len(screens)}")
            screens.append(meta)
            session.log.append({"direction": "screen", **meta})
            if len(screens) == 1:
                checks.record(label+"-no-transaction-before-consent", session.receive(.03) is None)
                checks.record(label+"-derived-node-zero-during-review", session.derived_node_zero(parked=True))
                session.send(27)
                checks.record(label+"-ack-alone-does-not-sign", session.receive(.03) is None)
            else:
                session.send(27)
            session.send(100, wire.fv(1, 1), iface=1)
            if len(screens) > 64:
                raise RuntimeError("too many signing review screens")
        if msg[0] != 65001:
            raise RuntimeError(f"emulator refused actual wallet plan: {wire.fields(msg[1])}")
        result = wire.fields(msg[1]); blob, tx_hash = wire.only(result, 1), wire.only(result, 2)
        parsed = signing.parse_transaction(blob)
        checks.record(label+"-actual-ringct-clsag-bulletproof-plus", parsed["rct_type"] == 6 and parsed["fee"] == plan.fee)
        expected_hash = core.hash(core.hash(blob[:parsed["prefix_end"]]) + core.hash(blob[parsed["prefix_end"]:parsed["base_end"]]) + core.hash(blob[parsed["base_end"]:]))
        checks.record(label+"-independent-transaction-hash", tx_hash == expected_hash)
        checks.record(label+"-actual-chain-input-key-images", set(i["key_image"] for i in parsed["inputs"]) == set(expected_images))
        for i, member in enumerate(parsed["inputs"]):
            source = expected_images[member["key_image"]]
            checks.record(label+f"-ring-{i}-matches-stock-decoy-selection", member["indices"] == [p.global_index for p in source.ring])
        cases = [watch_case if bytes(d.address).decode() == address else recipient_case for d in plan.destinations[:plan.output_count]]
        scanned = signing.scan_outputs(core, parsed, cases)
        checks.record(label+"-independent-recipient-change-decryption", sorted(scanned) == sorted((i, d.amount) for i, d in enumerate(plan.destinations[:plan.output_count])))
        lib = session.lib
        lib.monero_core_verify.argtypes = [ctypes.POINTER(signing.Plan), ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        lib.monero_core_verify.restype = ctypes.c_int
        error = ctypes.create_string_buffer(192)
        checks.record(label+"-official-core-verification", lib.monero_core_verify(ctypes.byref(plan), blob, len(blob), error) == 1, error=error.value.decode())
        checks.record(label+"-fee-reviewed", any(signing.displayed_atomic(s["body"], "Fee") == plan.fee for s in screens))
        bodies = "\n".join(s["body"] for s in screens)
        for i, dest in enumerate(plan.destinations[:plan.output_count]):
            details = [s["body"] for s in screens if f"Output {i+1}/{plan.output_count}:" in s["body"]]
            checks.record(label+f"-output-{i}-full-address-reviewed", bytes(dest.address).decode() in bodies)
            checks.record(label+f"-output-{i}-exact-amount-reviewed", len(details) == 1 and signing.displayed_atomic(details[0], "Amount") == dest.amount)
        checks.record(label+"-derived-node-zero-after-signing", session.derived_node_zero())
        (out / f"{label}.tx.bin").write_bytes(blob)
        (out / f"{label}.tx.hex").write_text(blob.hex()+"\n")
        entry = {"number": number, "tx_hash": tx_hash.hex(), "bytes": len(blob), "fee": plan.fee,
                 "recipient_amount": amount, "input_count": plan.input_count, "output_count": plan.output_count,
                 "real_output_keys": real_keys, "key_images": list(expected_images),
                 "independent_scanned_outputs": scanned, "review_stages": [s["title"] for s in screens]}
        transactions.append(entry)
        return blob, entry

    def relay_and_confirm(blob, entry, expected_balance):
        number = entry["number"]
        accepted = daemon.post("/send_raw_transaction", {"tx_as_hex": blob.hex(), "do_not_relay": False})
        checks.record(f"send-{number}-local-daemon-accepted", accepted.get("status") == "OK", result=accepted)
        height = mine(11)
        received, remaining = refresh(recipient), refresh(watch)
        checks.record(f"send-{number}-recipient-balance-confirmed", received["balance"] == sum(SEND_AMOUNTS[:number]))
        checks.record(f"send-{number}-watch-change-balance-confirmed", remaining["balance"] == expected_balance and remaining["unlocked_balance"] == expected_balance)
        spent = daemon.post("/is_key_image_spent", {"key_images": entry["key_images"]})
        checks.record(f"send-{number}-input-key-images-spent-on-chain", spent.get("spent_status") == [1] * len(entry["key_images"]))
        incoming = watch.call("incoming_transfers", {"transfer_type": "all", "account_index": 0})
        by_image = {x.get("key_image"): x for x in incoming.get("transfers", [])}
        checks.record(f"send-{number}-watch-wallet-tracks-spent-inputs", all(by_image.get(image, {}).get("spent") for image in entry["key_images"]))
        entry.update({"confirmed_height": height, "recipient_balance": received["balance"],
                      "watch_balance": remaining["balance"], "unlocked_change": remaining["unlocked_balance"]})
        return remaining

    if args.keep_running:
        for signum in [signal.SIGINT, signal.SIGTERM]:
            previous_signals[signum] = signal.signal(signum, request_stop)
    try:
        daemon_data = out / "daemon-data"; daemon_data.mkdir()
        daemon_command = [args.bin_dir / "monerod", "--regtest", "--offline", "--fixed-difficulty", "1",
                          "--data-dir", daemon_data, "--p2p-bind-ip", "127.0.0.1", "--p2p-bind-port", p2p_port,
                          "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", daemon_port,
                          "--rpc-ssl", "disabled", "--no-zmq", "--non-interactive", "--no-igd",
                          "--disable-dns-checkpoints", "--check-updates", "disabled", "--log-level", "0",
                          "--log-file", out / "daemon.log"]
        process = processes.start("daemon", daemon_command)
        info = wait_ready(daemon, process, "get_info")
        checks.record("fresh-isolated-regtest-daemon", info["height"] == 1 and info.get("nettype") == "fakechain")
        for name, port, rpc in [("faucet", faucet_port, faucet), ("watch", watch_port, watch), ("recipient", recipient_port, recipient)]:
            wallet_dir = out / f"{name}-wallet"; wallet_dir.mkdir()
            command = [args.bin_dir / "monero-wallet-rpc", "--wallet-dir", wallet_dir,
                       "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", port, "--disable-rpc-login",
                       "--rpc-ssl", "disabled", "--daemon-ssl", "disabled", "--trusted-daemon",
                       "--allow-mismatched-daemon-version",
                       "--daemon-address", f"127.0.0.1:{daemon_port}", "--log-level", "0",
                       "--shared-ringdb-dir", out / f"{name}-ringdb", "--log-file", out / f"{name}.log"]
            process = processes.start(name, command)
            wait_ready(rpc, process, "get_version")
        faucet.call("create_wallet", {"filename": "faucet", "password": "", "language": "English"})
        faucet_address = faucet.call("get_address", {"account_index": 0})["address"]
        recipient.call("generate_from_keys", {"filename": "recipient", "address": recipient_case["address"],
                        "viewkey": recipient_case["view_secret"], "spendkey": recipient_case["spend_secret"],
                        "password": "", "language": "English", "restore_height": 0})
        recipient_address = recipient.call("get_address", {"account_index": 0})["address"]
        stage("isolated offline daemon and stock wallet RPC processes", endpoints=endpoints)

        session = wire.Session(args.library.resolve(), out, "host-emulator")
        wire.load_wallet(session, checks, "abandon")
        displayed, events, screens = session.rpc(540, wire.request(display=True))
        displayed_address = wire.only(wire.fields(displayed[1]), 1).decode() if displayed[0] == 541 else ""
        checks.record("get-address-display-returns-public-fixture", displayed[0] == 541 and displayed_address == watch_case["address"])
        checks.record("get-address-display-request-reviewed", 26 in events and bool(screens))
        checks.record("get-address-full-address-observed-on-emulator", any(displayed_address in screen["body"] for screen in screens))
        checks.record("get-address-derived-node-zero", session.derived_node_zero())
        (out / "address-display.json").write_text(json.dumps({"show_display": True, "address": displayed_address,
                                                             "events": events, "screens": screens}, indent=2)+"\n")
        request = b"".join(wire.fv(1, n) for n in [0x8000002c, 0x80000080, 0x80000000]) + wire.fv(2, 0)
        msg, events, screens = session.rpc(542, request)
        checks.record("explicit-watch-key-export-consent", msg[0] == 543 and 26 in events and bool(screens))
        exported = wire.fields(msg[1]); view = wire.only(exported, 1); address = wire.only(exported, 2).decode()
        checks.record("public-fixture-watch-credentials", address == watch_case["address"] and view.hex() == watch_case["view_secret"])
        views["watch"] = view.hex()
        watch.call("generate_from_keys", {"filename": "watch", "address": address, "viewkey": view.hex(),
                                          "spendkey": "", "password": "", "language": "English", "restore_height": 0})
        try:
            watch.call("query_key", {"key_type": "spend_key"})
        except RpcError as error:
            checks.record("stock-wallet-is-watch-only", "watch-only" in str(error).lower())
        else:
            raise RuntimeError("host wallet unexpectedly contains a spend key")
        stage("normal emulator load and consented view-only wallet import", address=address,
              recipient=recipient_address, view_key_sha256=digest(view))

        mine(100)
        mature = refresh(faucet)
        checks.record("faucet-has-mature-private-chain-rewards", mature["unlocked_balance"] > FUNDING)
        funding = faucet.call("transfer", {"destinations": [{"address": address, "amount": FUNDING}],
                                            "ring_size": 16, "priority": 1, "get_tx_hex": True})
        funding_parsed = signing.parse_transaction(bytes.fromhex(funding["tx_blob"]))
        checks.record("funding-is-confidential-ringct-not-direct-coinbase", funding_parsed["rct_type"] == 6)
        mine(11)
        balance = refresh(watch)
        checks.record("watch-wallet-scanned-mature-confidential-funding", balance["balance"] == FUNDING and balance["unlocked_balance"] == FUNDING)
        stage("mined faucet and confirmed ordinary confidential funding", tx_hash=funding["tx_hash"], amount=FUNDING)

        encoded, initial, import_result = synchronize("funding")
        initial_keys = {item["out_key"] for item in initial}
        checks.record("only-confidential-funding-owned", len(initial) == 1 and initial[0]["amount"] == FUNDING)
        stage("stock output export, encrypted emulator key images and stock proof import", outputs=len(initial), imported=import_result)

        blob, first = make_signed(1, SEND_AMOUNTS[0], encoded, initial_keys)
        stage("stock unsigned transaction authorized and signed in emulator", tx_hash=first["tx_hash"], fee=first["fee"])
        expected = FUNDING - SEND_AMOUNTS[0] - first["fee"]
        relay_and_confirm(blob, first, expected)
        stage("first raw transaction accepted and confirmed on isolated chain", **first)

        encoded, after_first, imported_first = synchronize("first-change")
        change_keys = {item["out_key"] for item in after_first} - initial_keys
        checks.record("first-spend-created-one-owned-change-output", len(change_keys) == 1)
        checks.record("stock-import-reports-original-funding-spent", imported_first["spent"] == FUNDING)
        stage("new change synchronized and original spent input tracked", change_output_count=len(change_keys), imported=imported_first)

        blob, second = make_signed(2, SEND_AMOUNTS[1], encoded, change_keys)
        expected -= SEND_AMOUNTS[1] + second["fee"]
        relay_and_confirm(blob, second, expected)
        stage("second transaction spent only first transaction change", **second)

        _, final_outputs, final_import = synchronize("second-change")
        final_balance = refresh(watch)
        checks.record("final-watch-wallet-balance-includes-both-fees", final_balance["balance"] == FUNDING-sum(SEND_AMOUNTS)-sum(tx["fee"] for tx in transactions))
        checks.record("final-recipient-confirmed-both-payments", refresh(recipient)["balance"] == sum(SEND_AMOUNTS))
        checks.record("both-spent-inputs-imported", final_import["spent"] == FUNDING + first["watch_balance"])
        checks.record("nine-complete-host-stages", len(stages) == 8)
        stage("confirmed recipient balances, spent tracking and second change", outputs=len(final_outputs),
              watch_balance=final_balance["balance"], recipient_balance=sum(SEND_AMOUNTS), imported=final_import)
        status = "pass"
        if args.keep_running:
            checks.record("live-emulator-and-local-services-ready", session.lib.kkemu_is_running() == 1 and
                          all(process.poll() is None for _, process, _ in processes.items))
            live_session = {"schema_version": 1, "ready": True, "state": "running", "pid": os.getpid(),
                            "address": address, "network": "fakechain", "offline": True,
                            "address_format": "mainnet", "public_fixture": True,
                            "endpoints": {rpc.name: rpc.url for rpc in [daemon, faucet, watch, recipient]},
                            "p2p_endpoint": f"127.0.0.1:{p2p_port}", "faucet_address": faucet_address,
                            "balance_atomic": final_balance["balance"],
                            "unlocked_balance_atomic": final_balance["unlocked_balance"],
                            "balance_observed_at_height": daemon.post("/get_height", {})["height"],
                            "library": str(args.library.resolve()), "library_sha256": digest(args.library.read_bytes()),
                            "processes": {name: process.pid for name, process, _ in processes.items}}
            write_report("running")
            (out / "live-session.json").write_text(json.dumps(live_session, indent=2)+"\n")
            print(json.dumps({"status": "ready", "address": address, "network": "fakechain",
                              "live_session": str(out / "live-session.json")}), flush=True)
            while True:
                time.sleep(1)
                if session.lib.kkemu_is_running() != 1 or any(process.poll() is not None for _, process, _ in processes.items):
                    raise RuntimeError("A live emulator or local RPC process stopped unexpectedly")
    except SessionStop as error:
        stop_signal = signal.Signals(error.signum).name
        if status != "pass":
            failure = str(error)
            raise RuntimeError(failure) from error
    except Exception as error:
        status = "error"
        failure = str(error)
        raise
    finally:
        for signum in previous_signals:
            signal.signal(signum, signal.SIG_IGN)
        cleanup_errors = []
        try:
            if session is not None:
                session.close()
        except (OSError, RuntimeError) as error:
            cleanup_errors.append(str(error))
        try:
            processes.close()
        except (OSError, RuntimeError) as error:
            cleanup_errors.append(str(error))
        if cleanup_errors:
            status = "error"
            failure = "; ".join(filter(None, [failure, *cleanup_errors]))
        if live_session is not None:
            live_session.update({"ready": False, "state": "stopped" if status == "pass" else "error",
                                 "stopped_by_signal": stop_signal, "error": failure, "cleanup_errors": cleanup_errors})
            (out / "live-session.json").write_text(json.dumps(live_session, indent=2)+"\n")
        write_report("stopped")
        for signum, previous in previous_signals.items():
            signal.signal(signum, previous)
        if cleanup_errors:
            raise RuntimeError(failure)
    print(json.dumps({"status": status, "stages": len(stages), "checks": len(checks.items),
                      "transactions": [tx["tx_hash"] for tx in transactions], "output": str(out)}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError, urllib.error.URLError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
