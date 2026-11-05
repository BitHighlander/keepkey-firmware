#!/usr/bin/env python3
"""Watch a sealed private mainnet wallet through authenticated loopback RPC.

This process never has the emulator spend key and has no transfer, signing or
relay operations. Wallet credentials remain in memory; stock wallet files and
logs stay inside the caller's private wallet directory.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import resource
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import private_keystore

CA_FILE = "/etc/ssl/cert.pem"
ALLOWED_NODES = frozenset(["https://node.sethforprivacy.com", "https://xmr.triplebit.org"])
ALPHABET = frozenset("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")


class WatchError(RuntimeError):
    """Only fixed public diagnostics may leave this module."""


class RpcError(WatchError):
    def __init__(self, code):
        self.code = code if type(code) is int else None
        super().__init__("The local watch wallet rejected a request")


class LocalHttpError(WatchError):
    def __init__(self, code):
        self.code = code
        super().__init__("The authenticated local watch HTTP request failed")


class StopWatch(Exception):
    pass


def checked_uint(value):
    if type(value) is not int or not 0 <= value <= 2**64-1:
        raise WatchError("Invalid public wallet metadata")
    return value


def private_directory(path):
    if path.is_symlink() or not path.is_dir():
        raise WatchError("A private wallet directory is required")
    if path.stat().st_mode & 0o077:
        raise WatchError("The wallet directory must have mode 0700")


def private_file(path):
    if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        raise WatchError("A required private wallet file is unavailable")
    if path.stat().st_mode & 0o077:
        raise WatchError("Private wallet files must have mode 0600")


def validate_address(value):
    if type(value) is not str or len(value) != 95 or any(c not in ALPHABET for c in value):
        raise WatchError("Invalid public wallet address")
    return value


def validate_node(value):
    if value not in ALLOWED_NODES:
        raise WatchError("The daemon must be one of the verified mainnet HTTPS endpoints")
    return value


def load_configuration(wallet_dir):
    manifest_path, sealed_path = wallet_dir / "wallet.json", wallet_dir / "watch.enc"
    private_file(manifest_path); private_file(sealed_path)
    if manifest_path.stat().st_size > 65536 or sealed_path.stat().st_size > 65536:
        raise WatchError("Private wallet configuration exceeds its bound")
    try:
        manifest = json.loads(manifest_path.read_bytes())
        if (manifest.get("network") != "mainnet" or manifest.get("status") != "ready" or
                manifest.get("restore_verified") is not True or manifest.get("restored_in_separate_process") is not True):
            raise WatchError("A verified restored mainnet wallet is required")
        if manifest.get("keystore_backend") != "login":
            raise WatchError("The explicit login Keychain backend is required")
        wallet_id = manifest["wallet_id"]
        if type(wallet_id) is not str or not 1 <= len(wallet_id) <= 256:
            raise WatchError("Invalid public wallet identifier")
        address = validate_address(manifest["address"])
        restore = checked_uint(manifest["restore_height"])
        nodes = [validate_node(manifest["daemon_url"]), validate_node(manifest["fallback_daemon_url"])]
        private_keystore.set_backend("login")
        plaintext = bytearray(private_keystore.open_sealed(wallet_id, sealed_path.read_bytes()))
        try:
            credentials = json.loads(plaintext)
        finally:
            plaintext[:] = b"\0" * len(plaintext)
        if credentials.get("type") != "watch_credentials" or credentials.get("address") != address or credentials.get("restore_height") != restore:
            raise WatchError("Sealed watch credentials do not match the public wallet metadata")
        for field in ["view_key", "wallet_password"]:
            if type(credentials.get(field)) is not str or re.fullmatch("[0-9a-fA-F]{64}", credentials[field]) is None:
                raise WatchError("Invalid sealed watch credentials")
        return manifest, credentials, list(dict.fromkeys(nodes))
    except (WatchError, private_keystore.KeyStoreError):
        raise
    except Exception:
        raise WatchError("Cannot read the private watch configuration") from None


def probe_node(url, minimum_height):
    context = ssl.create_default_context(cafile=CA_FILE)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    data = json.dumps({"jsonrpc": "2.0", "id": "0", "method": "get_info", "params": {}}).encode()
    request = urllib.request.Request(url + "/json_rpc", data, {"Content-Type": "application/json"})
    try:
        with opener.open(request, timeout=20) as response:
            raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise WatchError("The mainnet daemon response exceeds its bound")
        info = json.loads(raw)["result"]
        if info.get("nettype") != "mainnet" or info.get("testnet") or info.get("stagenet") or not info.get("synchronized"):
            raise WatchError("The selected daemon is not synchronized on mainnet")
        if checked_uint(info["height"]) < minimum_height:
            raise WatchError("The selected daemon is behind the wallet restore height")
        return info["height"]
    except WatchError:
        raise
    except StopWatch:
        raise
    except Exception:
        raise WatchError("The verified mainnet daemon is unavailable") from None


def verified_leaf_pin(url):
    """Bind Core's fingerprint mode to a CA- and hostname-verified leaf."""
    host = urllib.parse.urlparse(validate_node(url)).hostname
    context = ssl.create_default_context(cafile=CA_FILE)
    try:
        with socket.create_connection((host, 443), timeout=20) as connection:
            with context.wrap_socket(connection, server_hostname=host) as secured:
                certificate = secured.getpeercert(binary_form=True)
        if not certificate:
            raise WatchError("The verified daemon did not provide a TLS certificate")
        return hashlib.sha256(certificate).hexdigest()
    except (WatchError, StopWatch):
        raise
    except Exception:
        raise WatchError("Cannot verify the mainnet daemon TLS identity") from None


class WalletRpc:
    _METHODS = frozenset(["get_version", "generate_from_keys", "open_wallet", "get_address",
                          "query_key", "refresh", "get_balance", "get_transfers", "get_height"])

    def __init__(self, port, login_file):
        private_file(login_file)
        if login_file.stat().st_size > 4096:
            raise WatchError("Invalid local RPC login file")
        try:
            login = login_file.read_text()
            username, password = login.strip().split(":", 1)
            if not username or not password:
                raise ValueError()
            self.url = f"http://127.0.0.1:{port}"
            self.port = port
            manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
            manager.add_password(None, self.url, username, password)
            self.digest = urllib.request.HTTPDigestAuthHandler(manager)
            self.connection = None
            self.challenge = None
        except StopWatch:
            raise
        except Exception:
            raise WatchError("Cannot use the private local RPC login") from None

    def _disconnect(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        self.challenge = None

    def close(self):
        self._disconnect()
        self.digest.passwd.passwd.clear()

    @staticmethod
    def _challenge(headers):
        for value in headers.get_all("WWW-Authenticate", []):
            if len(value) > 8192 or not value.lower().startswith("digest "):
                continue
            fields = urllib.request.parse_keqv_list(urllib.request.parse_http_list(value.split(" ", 1)[1]))
            if fields.get("algorithm", "MD5").upper() == "MD5" and fields.get("realm") and fields.get("nonce"):
                fields["algorithm"] = "MD5"
                return fields
        raise LocalHttpError(401)

    def call(self, method, parameters=None, timeout=60):
        if method not in self._METHODS:
            raise WatchError("Operation is unavailable in the receiving-only monitor")
        request = urllib.request.Request(self.url + "/json_rpc",
                    json.dumps({"jsonrpc": "2.0", "id": "0", "method": method,
                                "params": parameters or {}}).encode(), {"Content-Type": "application/json"})
        try:
            # Core binds each Digest nonce/counter to its TCP connection.
            # urllib's automatic retry opens another connection, so use its
            # Digest header builder while retaining our explicit HTTP socket.
            for _ in range(3):
                if self.connection is None:
                    self.connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
                self.connection.timeout = timeout
                if self.connection.sock is not None:
                    self.connection.sock.settimeout(timeout)
                headers = {"Content-Type": "application/json", "Connection": "keep-alive"}
                if self.challenge is not None:
                    authorization = self.digest.get_authorization(request, self.challenge)
                    if not authorization:
                        raise LocalHttpError(401)
                    headers["Authorization"] = "Digest " + authorization
                self.connection.request("POST", "/json_rpc", request.data, headers)
                response = self.connection.getresponse()
                # Fully consume every challenge and result before reusing the
                # same socket; no response body or authentication header logs.
                raw = response.read(4 * 1024 * 1024 + 1)
                if len(raw) > 4 * 1024 * 1024:
                    raise WatchError("The local watch response exceeds its bound")
                if response.status == 401:
                    if response.will_close:
                        raise LocalHttpError(401)
                    self.challenge = self._challenge(response.headers)
                    continue
                if response.status != 200:
                    raise LocalHttpError(response.status)
                if response.will_close:
                    self._disconnect()
                break
            else:
                raise LocalHttpError(401)
            value = json.loads(raw)
        except WatchError:
            self._disconnect()
            raise
        except StopWatch:
            raise
        except Exception:
            self._disconnect()
            raise WatchError("The local watch service is unavailable") from None
        if "error" in value:
            raise RpcError(value["error"].get("code"))
        if "result" not in value:
            raise WatchError("Invalid local watch response")
        return value["result"]


def choose_port():
    with socket.socket() as held:
        held.bind(("127.0.0.1", 0))
        return held.getsockname()[1]


def public_transactions(value):
    result = []
    for category in ["in", "pool"]:
        entries = value.get(category, [])
        if not isinstance(entries, list) or len(entries) > 10000:
            raise WatchError("The incoming transaction result exceeds its bound")
        for entry in entries:
            txid = entry.get("txid")
            if type(txid) is not str or re.fullmatch("[0-9a-fA-F]{64}", txid) is None:
                raise WatchError("Invalid incoming transaction identifier")
            result.append({"txid": txid, "type": category, "amount_atomic": checked_uint(entry["amount"]),
                           "height": checked_uint(entry.get("height", 0)),
                           "confirmations": checked_uint(entry.get("confirmations", 0)),
                           "locked": bool(entry.get("locked", True)),
                           "double_spend_seen": bool(entry.get("double_spend_seen", False))})
    return result


def atomic_status(path, value):
    name = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", prefix=".watch-status-", dir=path.parent,
                                         delete=False) as handle:
            name = handle.name
            json.dump(value, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    finally:
        if name is not None and os.path.exists(name):
            os.unlink(name)


def diagnose_auth(wallet_dir):
    """Probe only an existing RPC's public version, without opening Keychain."""
    candidates = []
    for path in wallet_dir.glob("monero-wallet-rpc.*.login"):
        match = re.fullmatch(r"monero-wallet-rpc\.(\d{1,5})\.login", path.name)
        try:
            if match and path.stat().st_uid == os.geteuid():
                candidates.append((path.stat().st_mtime_ns, path, int(match[1])))
        except OSError:
            pass
    report = {"status": "error", "exception_chain": [], "http_codes": []}
    if not candidates:
        report["exception_chain"] = ["NoActiveOwnedRpcLogin"]
    else:
        _, path, port = max(candidates)
        try:
            WalletRpc(port, path).call("get_version", timeout=5)
            report["status"] = "pass"
        except Exception as error:
            seen = set()
            for _ in range(8):
                if id(error) in seen:
                    break
                seen.add(id(error))
                name = type(error).__name__
                report["exception_chain"].append(name if re.fullmatch(r"[A-Za-z_]{1,64}", name) else "Exception")
                code = getattr(error, "code", None)
                if type(code) is int and 100 <= code <= 599:
                    report["http_codes"].append(code)
                error = error.__cause__ or error.__context__
                if error is None:
                    break
    print(json.dumps(report), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wallet-dir", type=Path, required=True)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--diagnose-auth", action="store_true",
                        help="Probe only get_version on the existing owned local RPC; do not decrypt credentials")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (OSError, ValueError):
        raise WatchError("Cannot disable private process core dumps") from None
    wallet_dir = args.wallet_dir.absolute()
    private_directory(wallet_dir)
    wallet_dir = wallet_dir.resolve()
    if wallet_dir.is_relative_to(Path(__file__).resolve().parents[4]):
        raise WatchError("The private wallet directory must be outside the repository")
    if args.diagnose_auth:
        diagnose_auth(wallet_dir)
        return
    binary = (args.bin_dir / "monero-wallet-rpc").resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise WatchError("The verified stock wallet RPC executable is unavailable")
    manifest, credentials, nodes = load_configuration(wallet_dir)
    address = manifest["address"]
    process, output, client = None, None, None
    status = {"schema_version": 1, "ready": False, "status": "starting", "network": "mainnet",
              "address": address, "pid": os.getpid(), "watch_only": True,
              "restore_height": manifest["restore_height"], "transactions": [],
              "balance_atomic": 0, "unlocked_balance_atomic": 0}
    status_path = wallet_dir / "mainnet-watch.json"
    previous = {}
    operation = "configuration"

    def stop(_signum, _frame):
        raise StopWatch()

    def publish(state, ready, **updates):
        if ready:
            for key in ["error", "failed_stage", "error_kind", "rpc_error_code", "http_status"]:
                status.pop(key, None)
        status.update({"status": state, "ready": ready,
                       "updated_utc": datetime.now(timezone.utc).isoformat(), **updates})
        atomic_status(status_path, status)

    def stop_rpc():
        nonlocal process, output, client
        if client is not None:
            client.close()
            client = None
        if process is not None:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
            process = None
        if output is not None:
            output.close()
            output = None

    def start_rpc(node):
        nonlocal process, output, client, operation
        operation = "daemon_tls_identity"
        fingerprint = verified_leaf_pin(node)
        operation = "rpc_startup"
        port = choose_port()
        log_path = wallet_dir / "watch-rpc-process.log"
        descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        os.fchmod(descriptor, 0o600)
        output = os.fdopen(descriptor, "ab", buffering=0)
        ringdb = wallet_dir / "ringdb"
        ringdb.mkdir(mode=0o700, exist_ok=True)
        private_directory(ringdb)
        command = [str(binary), "--wallet-dir", str(wallet_dir), "--rpc-bind-ip", "127.0.0.1",
                   "--rpc-bind-port", str(port), "--rpc-ssl", "disabled", "--untrusted-daemon",
                   "--daemon-address", node, "--daemon-ssl", "enabled",
                   "--daemon-ssl-allowed-fingerprints", fingerprint,
                   "--no-initial-sync", "--shared-ringdb-dir", str(ringdb), "--log-level", "0",
                   "--log-file", str(wallet_dir / "watch-rpc.log")]
        process = subprocess.Popen(command, cwd=wallet_dir, stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT)
        login_path = wallet_dir / f"monero-wallet-rpc.{port}.login"
        until = time.monotonic()+60
        operation = "rpc_authentication"
        while True:
            if process.poll() is not None:
                raise WatchError("The private watch service stopped during startup")
            try:
                client = WalletRpc(port, login_path)
                client.call("get_version", timeout=2)
                break
            except WatchError:
                if time.monotonic() >= until:
                    raise WatchError("The private watch service did not become ready") from None
                time.sleep(.1)
        keys, cache, address_file = wallet_dir / "watch.keys", wallet_dir / "watch", wallet_dir / "watch.address.txt"
        if keys.exists():
            operation = "open_watch_wallet"
            private_file(keys)
            if cache.exists():
                private_file(cache)
            client.call("open_wallet", {"filename": "watch", "password": credentials["wallet_password"]})
        else:
            operation = "create_watch_wallet"
            if cache.exists() or address_file.exists() or keys.is_symlink():
                raise WatchError("Incomplete existing watch wallet; refusing to overwrite it")
            client.call("generate_from_keys", {"filename": "watch", "address": address,
                        "viewkey": credentials["view_key"], "spendkey": "", "password": credentials["wallet_password"],
                        "restore_height": manifest["restore_height"], "language": "English"})
        operation = "verify_watch_address"
        if client.call("get_address", {"account_index": 0}).get("address") != address:
            raise WatchError("The stock watch wallet address does not match the emulator")
        try:
            operation = "verify_watch_only"
            client.call("query_key", {"key_type": "spend_key"})
        except RpcError as error:
            if error.code != -29:
                raise WatchError("Cannot verify that the stock wallet is watch-only") from None
        else:
            raise WatchError("The stock wallet unexpectedly contains a spend key")
        publish("syncing", False, daemon_url=node, rpc_url=client.url, wallet_rpc_pid=process.pid,
                daemon_tls_leaf_sha256=fingerprint, daemon_tls_identity_verified=True,
                daemon_tls_mode="CA-and-hostname-verified leaf fingerprint")

    for signum in [signal.SIGINT, signal.SIGTERM]:
        previous[signum] = signal.signal(signum, stop)
    stopped = False
    try:
        node_index = 0
        while True:
            node = nodes[node_index % len(nodes)]
            try:
                operation = "daemon_probe"
                probe_node(node, manifest["restore_height"])
                start_rpc(node)
                announced = False
                while True:
                    if process.poll() is not None:
                        raise WatchError("The private watch service stopped unexpectedly")
                    operation = "refresh"
                    client.call("refresh")
                    operation = "get_balance"
                    balance = client.call("get_balance", {"account_index": 0})
                    operation = "get_transfers"
                    transfers = client.call("get_transfers", {"in": True, "out": False, "pending": False,
                                             "failed": False, "pool": True, "account_index": 0})
                    operation = "get_height"
                    height = checked_uint(client.call("get_height")["height"])
                    if height < manifest["restore_height"]:
                        raise WatchError("The watch wallet has not reached its restore height")
                    publish("watching", True, balance_atomic=checked_uint(balance["balance"]),
                            unlocked_balance_atomic=checked_uint(balance["unlocked_balance"]),
                            wallet_height=height, transactions=public_transactions(transfers))
                    if not announced:
                        print(json.dumps({"status": "ready", "network": "mainnet", "address": address,
                                          "status_file": str(status_path)}), flush=True)
                        announced = True
                    time.sleep(15)
            except WatchError as error:
                diagnostic = {"failed_stage": operation, "error_kind": type(error).__name__}
                if isinstance(error, RpcError) and type(error.code) is int and -2**31 <= error.code < 2**31:
                    diagnostic["rpc_error_code"] = error.code
                if isinstance(error, LocalHttpError) and type(error.code) is int and 100 <= error.code <= 599:
                    diagnostic["http_status"] = error.code
                publish("reconnecting", False, error="Watch service or verified mainnet node unavailable", **diagnostic)
                stop_rpc()
                node_index += 1
                time.sleep(5)
    except StopWatch:
        stopped = True
    except Exception:
        publish("error", False, error="Private watch monitoring failed")
        raise WatchError("Private watch monitoring failed") from None
    finally:
        for signum in previous:
            signal.signal(signum, signal.SIG_IGN)
        try:
            stop_rpc()
        finally:
            credentials.clear()
            publish("stopped" if stopped else "error", False)
            for signum, handler in previous.items():
                signal.signal(signum, handler)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Private watch service could not start or continue; no signing or relay was performed", file=sys.stderr)
        sys.exit(1)
