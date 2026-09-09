import os,sys,subprocess,tempfile,time,unittest
from pathlib import Path
if len(sys.argv) != 3:
 raise SystemExit('usage: coin_table_bounds.py CHECKOUT BUILD_DIRECTORY')
root=Path(sys.argv[1]).resolve()
build_directory=sys.argv[2]
os.environ['KK_FORCE_UDP']='1'
sys.path[:0]=[str(root/'deps/python-keepkey/tests'),str(root/'deps/python-keepkey')]
import signal
def timed_out(signum, frame):
 raise TimeoutError('coin table rehearsal exceeded 60 seconds')
signal.signal(signal.SIGALRM,timed_out)
signal.alarm(60)
from test_msg_ping import TestPing
from keepkeylib import messages_pb2 as proto
def coin_bounds(self):
 meta = self.client.call_raw(proto.GetCoinTable())
 self.assertIsInstance(meta, proto.CoinTable)
 self.assertGreater(meta.num_coins, 0)
 self.assertGreater(meta.chunk_size, 0)
 count = meta.num_coins
 chunk = meta.chunk_size
 cases = [proto.GetCoinTable(start=0), proto.GetCoinTable(end=1),
          proto.GetCoinTable(start=count, end=count),
          proto.GetCoinTable(start=0, end=count+1),
          proto.GetCoinTable(start=1, end=0),
          proto.GetCoinTable(start=0xffffffff, end=0xffffffff)]
 if count > chunk:
  cases.append(proto.GetCoinTable(start=0, end=chunk+1))
 for request in cases:
  self.assertIsInstance(self.client.call_raw(request), proto.Failure)
 names=[]
 for start in range(0, count, chunk):
  end=min(start+chunk,count)
  reply=self.client.call_raw(proto.GetCoinTable(start=start,end=end))
  self.assertIsInstance(reply, proto.CoinTable)
  self.assertEqual(len(reply.table), end-start)
  names.extend(coin.coin_name for coin in reply.table)
 self.assertIn('Bitcoin', names)
 self.assertIn('Testnet', names)
 print('Enumerated',count,'coins in bounded chunks of',chunk)
TestPing.test_coin_bounds=coin_bounds
with tempfile.TemporaryDirectory(prefix='coin-table-') as directory:
 with open(Path(directory)/'emulator.log','w') as log:
  proc=subprocess.Popen([str(root/build_directory/'bin/kkemu')],cwd=directory,stdout=log,stderr=subprocess.STDOUT)
  try:
   time.sleep(1)
   if proc.poll() is not None:raise RuntimeError('emulator exited')
   result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([TestPing('test_coin_bounds')]))
   if not result.wasSuccessful() or result.skipped:raise SystemExit(1)
  finally:
   proc.terminate()
   try:proc.wait(timeout=5)
   except subprocess.TimeoutExpired:proc.kill();proc.wait()
