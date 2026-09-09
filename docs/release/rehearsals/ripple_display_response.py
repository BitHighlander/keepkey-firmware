"""Verify the displayed Ripple address survives debug screenshot requests.
Requires the pinned host suite dependencies on PYTHONPATH; never uses hardware.
This rehearsal strengthens the legacy host test that ignored the response.
"""
import os, sys, subprocess, tempfile, time, unittest, signal
from pathlib import Path
if len(sys.argv) != 2:
    raise SystemExit('usage: ripple_display_response.py CHECKOUT (7.15 full native build required)')
root = Path(sys.argv[1]).resolve()
os.environ['KK_FORCE_UDP'] = '1'
os.environ['KEEPKEY_SCREENSHOT'] = '1'
sys.path[:0] = [str(root / 'deps/python-keepkey/tests'), str(root / 'deps/python-keepkey')]

def timed_out(signum, frame):
    raise TimeoutError('Ripple display rehearsal exceeded 60 seconds')
signal.signal(signal.SIGALRM, timed_out)
signal.alarm(60)
from test_msg_ripple_get_address import TestMsgRippleGetAddress
from keepkeylib.tools import parse_path

def check_display_response(self):
    self.requires_fullFeature()
    self.setup_mnemonic_allallall()
    address = self.client.ripple_get_address(parse_path("m/44'/144'/0'/0/0"), show_display=True)
    self.assertEqual(address, "rNaqKtKrMSwpwZSzRckPf7S96DkimjkF4H")
TestMsgRippleGetAddress.test_ripple_show_address = check_display_response
with tempfile.TemporaryDirectory(prefix='ripple-memo-') as directory:
    os.environ['KEEPKEY_SCREENSHOT'] = '1'
    os.environ['SCREENSHOT_DIR'] = os.path.join(directory, 'screenshots')
    with open(os.path.join(directory, 'emulator.log'), 'w') as log:
        proc = subprocess.Popen([str(root / 'build-native/bin/kkemu')], cwd=directory, stdout=log, stderr=subprocess.STDOUT)
        try:
            time.sleep(1)
            if proc.poll() is not None:
                raise RuntimeError('emulator exited')
            result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([TestMsgRippleGetAddress('test_ripple_show_address')]))
            if not list(Path(directory).rglob('btn*.png')):
                raise RuntimeError('No screenshot evidence captured')
            if not result.wasSuccessful() or result.skipped:
                raise SystemExit(1)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
