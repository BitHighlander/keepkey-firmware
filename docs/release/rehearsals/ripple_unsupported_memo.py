import os, sys, subprocess, tempfile, time, unittest, signal
from pathlib import Path
if len(sys.argv) != 2:
    raise SystemExit('usage: ripple_unsupported_memo.py CHECKOUT (7.14.3 full native build)')
root = Path(sys.argv[1]).resolve()
os.environ['KK_FORCE_UDP'] = '1'
sys.path[:0] = [str(root / 'deps/python-keepkey/tests'), str(root / 'deps/python-keepkey')]

def timed_out(signum, frame):
    raise TimeoutError('rehearsal exceeded 60 seconds')
signal.signal(signal.SIGALRM, timed_out)
signal.alarm(60)
from test_msg_ripple_sign_tx import TestMsgRippleSignTx
from keepkeylib import messages_ripple_pb2 as messages
from keepkeylib import types_pb2 as types
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path

def test_unsupported_memo(self):
    self.requires_fullFeature()
    self.setup_mnemonic_allallall()
    msg = messages.RippleSignTx(address_n=parse_path("m/44'/144'/0'/0/0"), payment=messages.RipplePayment(amount=100000000, destination='rBKz5MC2iXdoS3XgnNSYmF69K1Yo4NS3Ws'), flags=2147483648, fee=100000, sequence=25, memo='routing-memo')
    with self.assertRaises(CallException) as caught:
        self.client.call(msg)
    self.assertEqual(caught.exception.args[0], types.Failure_SyntaxError)
TestMsgRippleSignTx.test_unsupported_memo = test_unsupported_memo
with tempfile.TemporaryDirectory(prefix='ripple-memo-') as directory:
    with open(os.path.join(directory, 'emulator.log'), 'w') as log:
        proc = subprocess.Popen([str(root / 'build-native-full/bin/kkemu')], cwd=directory, stdout=log, stderr=subprocess.STDOUT)
        try:
            time.sleep(1)
            if proc.poll() is not None:
                raise RuntimeError('emulator exited')
            result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([TestMsgRippleSignTx('test_unsupported_memo'), TestMsgRippleSignTx('test_sign'), TestMsgRippleSignTx('test_ripple_sign_invalid_fee')]))
            if not result.wasSuccessful() or result.skipped:
                raise SystemExit(1)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
