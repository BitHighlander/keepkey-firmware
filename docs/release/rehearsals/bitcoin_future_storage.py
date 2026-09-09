import os, sys, unittest, signal
from pathlib import Path
if len(sys.argv) != 3:
 raise SystemExit('usage: bitcoin_future_storage.py CHECKOUT BUILD_DIRECTORY')
def timed_out(signum,frame):
 raise TimeoutError('future storage rehearsal exceeded 60 seconds')
signal.signal(signal.SIGALRM,timed_out)
signal.alarm(60)
root=Path(sys.argv[1]).resolve()
os.environ['KK_FORCE_UDP']='1'
os.environ['KK_FIRMWARE_ROOT']=str(root)
os.environ['KK_EMULATOR_BIN']=str(root/sys.argv[2]/'bin/kkemu')
sys.path[:0]=[str(root/'deps/python-keepkey/tests'),str(root/'deps/python-keepkey')]
from test_storage_version_gate import TestStorageUpgradePreservation, OFF_VERSION

def check_future(self):
 _,off=self._create_wallet()
 self.assertTrue(self.bitcoin_only)
 self.emu.write_u32(off,OFF_VERSION,self.emu.read_u32(off,OFF_VERSION)+1)
 before=self.emu.image()
 self.emu.boot()
 client=self.emu.client(self.method)
 try:
  client.init_device()
  self.assertFalse(client.features.initialized)
 finally:
  client.close()
  self.emu.halt()
 self.assertEqual(before,self.emu.image(),'newer Bitcoin-only wallet was modified')
TestStorageUpgradePreservation.test_future_band_preserves_image=check_future
result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([TestStorageUpgradePreservation('test_future_band_preserves_image')]))
if not result.wasSuccessful() or result.skipped: raise SystemExit(1)
