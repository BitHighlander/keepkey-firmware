"""Owned-emulator terminal-failure regression. Never selects hardware.

Run with the target checkout's host dependencies available. Set KK_TEST_DICE=0
for the 7.14.2 product, which has no dice feature. Every selected case must run
and pass; skips are rejected. The process is bounded and cleaned up on failure.
"""
import os,sys,subprocess,tempfile,time,unittest
from pathlib import Path
if len(sys.argv) != 3:
 raise SystemExit('usage: terminal_tiny_failure.py CHECKOUT BUILD_DIRECTORY (KK_TEST_DICE=0 for 7.14.2)')
root=Path(sys.argv[1]).resolve()
build_directory=sys.argv[2]
os.environ['KK_FORCE_UDP']='1'
sys.path[:0]=[str(root/'deps/python-keepkey/tests'),str(root/'deps/python-keepkey')]
import signal
def timed_out(signum,frame): raise TimeoutError('rehearsal timeout')
signal.signal(signal.SIGALRM,timed_out)
signal.alarm(60)
import common
from keepkeylib import types_pb2 as types
from keepkeylib import messages_pb2 as proto
class TinyFailureBoundary(common.KeepKeyTest):
 def test_failure_does_not_resume_old_confirmation(self):
  r=self.client.call_raw(proto.Ping(message='old operation',button_protection=True))
  self.assertIsInstance(r,proto.ButtonRequest)
  r=self.client.call_raw(proto.GetCoinTable())
  self.assertIsInstance(r,proto.Failure)
  r=self.client.call_raw(proto.Ping(message='fresh operation'))
  self.assertIsInstance(r,proto.Success)
  self.assertEqual(r.message,'fresh operation')

 def test_failure_unwinds_each_protection_loop(self):
  self.setup_mnemonic_pin_passphrase()
  for field,expected in [('button_protection',proto.ButtonRequest),('pin_protection',proto.PinMatrixRequest),('passphrase_protection',proto.PassphraseRequest)]:
   self.client.clear_session()
   r=self.client.call_raw(proto.Ping(message='old',**{field:True}))
   self.assertIsInstance(r,expected)
   self.assertIsInstance(self.client.call_raw(proto.GetCoinTable()),proto.Failure)
   r=self.client.call_raw(proto.Ping(message='fresh'))
   self.assertIsInstance(r,proto.Success)
   self.assertEqual(r.message,'fresh')
   self.assertIsInstance(self.client.call_raw(proto.Initialize()),proto.Features)

 def test_malformed_tiny_frames_unwind(self):
  import struct
  from keepkeylib import mapping
  packets=[bytes(64),b'?##'+struct.pack('>HI',mapping.get_type(proto.PinMatrixAck()),56)+bytes(55),b'?##'+struct.pack('>HI',mapping.get_type(proto.PinMatrixAck()),1)+b'\x0a'+bytes(54)]
  self.setup_mnemonic_pin_passphrase()
  for field,expected in [('button_protection',proto.ButtonRequest),('pin_protection',proto.PinMatrixRequest),('passphrase_protection',proto.PassphraseRequest)]:
   for packet in packets:
    self.client.clear_session()
    self.assertIsInstance(self.client.call_raw(proto.Ping(**{field:True})),expected)
    self.client.transport.socket.send(packet)
    self.assertIsInstance(self.client.transport.read_blocking(),proto.Failure)
    r=self.client.call_raw(proto.Ping(message='after malformed'))
    self.assertIsInstance(r,proto.Success)
    self.assertEqual(r.message,'after malformed')

 def test_dice_failure_unwinds(self):
  r=self.client.call_raw(proto.ResetDevice(strength=128,pin_protection=False,passphrase_protection=False,dice_entropy=True))
  self.assertIsInstance(r,proto.ButtonRequest)
  self.assertEqual(r.code,types.ButtonRequest_DiceRoll)
  self.assertIsInstance(self.client.call_raw(proto.GetCoinTable()),proto.Failure)
  r=self.client.call_raw(proto.Ping(message='after dice'))
  self.assertIsInstance(r,proto.Success)
  self.assertEqual(r.message,'after dice')
  self.assertIsInstance(self.client.call_raw(proto.EntropyAck(entropy=b'x'*32)),proto.Failure)
  r=self.client.call_raw(proto.Initialize())
  self.assertIsInstance(r,proto.Features)
  self.assertFalse(r.initialized)

with tempfile.TemporaryDirectory(prefix='terminal-tiny-failure-') as directory:
 with open(Path(directory)/'emulator.log','w') as log:
  proc=subprocess.Popen([str(root/build_directory/'bin/kkemu')],cwd=directory,stdout=log,stderr=subprocess.STDOUT)
  try:
   time.sleep(1)
   if proc.poll() is not None:raise RuntimeError('emulator exited')
   result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(TinyFailureBoundary(n) for n in unittest.defaultTestLoader.getTestCaseNames(TinyFailureBoundary) if n != 'test_dice_failure_unwinds' or os.environ.get('KK_TEST_DICE','1') == '1'))
   if not result.wasSuccessful() or result.skipped:raise SystemExit(1)
  finally:
   proc.terminate()
   try:proc.wait(timeout=5)
   except subprocess.TimeoutExpired:proc.kill();proc.wait()
