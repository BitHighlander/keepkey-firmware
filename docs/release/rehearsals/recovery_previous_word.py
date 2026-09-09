import os,sys,subprocess,tempfile,time,unittest
from pathlib import Path
if len(sys.argv) != 3:
 raise SystemExit('usage: recovery_previous_word.py CHECKOUT BUILD_DIRECTORY')
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
class RecoveryCleanup(common.KeepKeyTest):
 def test_previous_word_after_crossing_boundary(self):
  r=self.client.call_raw(proto.RecoveryDevice(word_count=12,pin_protection=False,passphrase_protection=False,enforce_wordlist=True,use_character_cipher=True))
  self.assertIsInstance(r,proto.ButtonRequest)
  self.client.debug.press_yes()
  r=self.client.call_raw(proto.ButtonAck())
  initial=self.client.debug.read_layout()
  def enter(word):
   for char in word:
    cipher=self.client.debug.read_recovery_cipher()
    self.assertIsInstance(self.client.call_raw(proto.CharacterAck(character=cipher[ord(char)-97])),proto.CharacterRequest)
   self.assertIsInstance(self.client.call_raw(proto.CharacterAck(character=' ')),proto.CharacterRequest)
  enter('all')
  first=self.client.debug.read_layout()
  self.assertEqual(len(first),2048)
  enter('zoo')
  self.assertIsInstance(self.client.call_raw(proto.CharacterAck(delete=True)),proto.CharacterRequest)
  edited=self.client.debug.read_layout()
  self.assertEqual(first[:72],edited[:72])
  # Delete zoo and the separator before it: no completed word precedes word 1.
  for _ in range(4):
   self.assertIsInstance(self.client.call_raw(proto.CharacterAck(delete=True)),proto.CharacterRequest)
  self.assertEqual(initial[:72],self.client.debug.read_layout()[:72])
  # Re-accept word 1 and check that forward navigation restores its indicator.
  self.assertIsInstance(self.client.call_raw(proto.CharacterAck(character=' ')),proto.CharacterRequest)
  self.assertEqual(first[:72],self.client.debug.read_layout()[:72])

with tempfile.TemporaryDirectory(prefix='setup-rejection-') as directory:
 with open(Path(directory)/'emulator.log','w') as log:
  proc=subprocess.Popen([str(root/build_directory/'bin/kkemu')],cwd=directory,stdout=log,stderr=subprocess.STDOUT)
  try:
   time.sleep(1)
   if proc.poll() is not None:raise RuntimeError('emulator exited')
   result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RecoveryCleanup))
   if not result.wasSuccessful() or result.skipped:raise SystemExit(1)
  finally:
   proc.terminate()
   try:proc.wait(timeout=5)
   except subprocess.TimeoutExpired:proc.kill();proc.wait()
