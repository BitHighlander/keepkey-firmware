"""Run the existing skipped memo assertion unchanged against an owned emulator.
Requires the pinned host suite dependencies on PYTHONPATH; never uses hardware.
This is a rehearsal, not a replacement for fixing the host suite version gate.
"""
import os, sys, subprocess, tempfile, time, unittest, signal
from pathlib import Path
if len(sys.argv) != 2:
    raise SystemExit('usage: ripple_memo.py CHECKOUT (7.15 full native build required)')
root = Path(sys.argv[1]).resolve()
os.environ['KK_FORCE_UDP'] = '1'
sys.path[:0] = [str(root / 'deps/python-keepkey/tests'), str(root / 'deps/python-keepkey')]

def timed_out(signum, frame):
    raise TimeoutError('Ripple memo rehearsal exceeded 60 seconds')
signal.signal(signal.SIGALRM, timed_out)
signal.alarm(60)
from test_msg_ripple_sign_tx import TestMsgRippleSignTx
method = TestMsgRippleSignTx.test_sign_with_thorchain_memo
TestMsgRippleSignTx.test_sign_with_thorchain_memo = method.__wrapped__
with tempfile.TemporaryDirectory(prefix='ripple-memo-') as directory:
    with open(os.path.join(directory, 'emulator.log'), 'w') as log:
        proc = subprocess.Popen([str(root / 'build-native/bin/kkemu')], cwd=directory, stdout=log, stderr=subprocess.STDOUT)
        try:
            time.sleep(1)
            if proc.poll() is not None:
                raise RuntimeError('emulator exited')
            result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([TestMsgRippleSignTx('test_sign_with_thorchain_memo')]))
            if not result.wasSuccessful() or result.skipped:
                raise SystemExit(1)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
