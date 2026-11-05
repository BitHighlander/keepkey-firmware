#!/usr/bin/env python3
"""Run Safe incident regressions against an owned emulator with a test root.

No hardware autodetection, production issuer keys, or persistent wallet state.
The normal alpha-root suite remains on its own emulator.
"""
import argparse
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emulator", required=True, type=Path)
    parser.add_argument("--python-keepkey", required=True, type=Path)
    parser.add_argument("--junit", required=True, type=Path)
    args = parser.parse_args()
    emulator = args.emulator.resolve()
    pyk = args.python_keepkey.resolve()
    report = args.junit.resolve()
    report.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, KK_FORCE_UDP="1", KEEPKEY_UDP_PORT="11964",
               KK_TRANSPORT_MAIN="127.0.0.1:11964",
               KK_TRANSPORT_DEBUG="127.0.0.1:11965",
               KK_CLEARSIGN_TEST_ROOT=(
                   "0288bbff17897c34aa5c0e92c2068f3396e3786fb0356f589417111db59016d147"))
    env.pop("KK_TRANSPORT", None)
    env.pop("KK_SAFE_CERTIFIED_FIXTURE", None)
    env.pop("KK_SAFE_TEST_CHAIN", None)
    env["PYTHONPATH"] = str(pyk)
    with tempfile.TemporaryDirectory(prefix="kk-safe-incident-") as state:
        with open(report.with_suffix(".emulator.log"), "w") as log:
            process = subprocess.Popen([str(emulator)], cwd=state, env=env,
                                       stdout=log, stderr=subprocess.STDOUT)
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                    probe.settimeout(0.2)
                    for _ in range(25):
                        if process.poll() is not None:
                            raise RuntimeError("Safe emulator exited before readiness")
                        probe.sendto(b"PINGPING", ("127.0.0.1", 11964))
                        try:
                            if probe.recv(64) == b"PONGPONG":
                                break
                        except socket.timeout:
                            pass
                        time.sleep(0.05)
                    else:
                        raise RuntimeError("Safe emulator did not become ready")
                subprocess.run([
                    sys.executable, "-m", "pytest", "-q", "--tb=short",
                    "test_msg_ethereum_erc7730_safe.py",
                    "--junitxml=" + str(report)], cwd=pyk / "tests", env=env,
                    check=True, timeout=300)
                cases = list(ET.parse(report).iter("testcase"))
                if len(cases) < 15 or any(c.find("skipped") is not None for c in cases):
                    raise RuntimeError("Safe regression evidence is missing or skipped")
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    main()
