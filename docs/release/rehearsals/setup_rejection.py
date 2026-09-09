import os,sys,subprocess,tempfile,time,unittest
from pathlib import Path
if len(sys.argv) != 3:
 raise SystemExit('usage: setup_rejection.py CHECKOUT BUILD_DIRECTORY')
root=Path(sys.argv[1]).resolve()
build_directory=sys.argv[2]
os.environ['KK_FORCE_UDP']='1'
sys.path[:0]=[str(root/'deps/python-keepkey/tests'),str(root/'deps/python-keepkey')]
import signal
def timed_out(signum,frame): raise TimeoutError('rehearsal timeout')
signal.signal(signal.SIGALRM,timed_out)
signal.alarm(30)
from test_msg_ping import TestPing
from keepkeylib import messages_pb2 as proto
def interrupted_reset(self):
 response=self.client.call_raw(proto.ResetDevice(strength=128, pin_protection=False, passphrase_protection=False, display_random=False))
 self.assertIsInstance(response,proto.EntropyRequest)
 response=self.client.call_raw(proto.EntropyAck(entropy=b'a'*32))
 self.assertIsInstance(response,proto.ButtonRequest)
 response=self.client.call_raw(proto.GetCoinTable())
 self.assertIsInstance(response,proto.Failure)
 print('transport rejection:',response.code,response.message)
 self.client.debug.press_yes()
 response=self.client.call_raw(proto.ButtonAck())
 for _ in range(12):
  if not isinstance(response,proto.ButtonRequest): break
  self.client.debug.press_yes()
  response=self.client.call_raw(proto.ButtonAck())
 print('resumed reset response type:',type(response).__name__)
 self.assertIsInstance(response,proto.Failure,'rejected reset did not terminate with Failure')
TestPing.test_interrupted_reset=interrupted_reset
with tempfile.TemporaryDirectory(prefix='setup-rejection-') as directory:
 with open(Path(directory)/'emulator.log','w') as log:
  proc=subprocess.Popen([str(root/build_directory/'bin/kkemu')],cwd=directory,stdout=log,stderr=subprocess.STDOUT)
  try:
   time.sleep(1)
   if proc.poll() is not None:raise RuntimeError('emulator exited')
   result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([TestPing('test_interrupted_reset')]))
   if not result.wasSuccessful() or result.skipped:raise SystemExit(1)
  finally:
   proc.terminate()
   try:proc.wait(timeout=5)
   except subprocess.TimeoutExpired:proc.kill();proc.wait()
