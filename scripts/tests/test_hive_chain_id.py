"""Block 12 wire regression; run only against a disposable debug emulator.

Example (with python-keepkey test dependencies installed):
  KK_FORCE_UDP=1 python3 -m pytest scripts/tests/test_hive_chain_id.py
The native companion is registered in unittests/firmware/CMakeLists.txt.
"""
import os
from pathlib import Path
import sys

if os.environ.get("KK_FORCE_UDP") != "1":
    raise RuntimeError("This test wipes its emulator; set KK_FORCE_UDP=1")

ROOT = Path(__file__).resolve().parents[2]
PYTHON = ROOT / "deps" / "python-keepkey"
sys.path[:0] = [str(PYTHON / "tests"), str(PYTHON)]

import common
from keepkeylib import messages_pb2 as proto
from keepkeylib import messages_hive_pb2 as hive
from keepkeylib import types_pb2 as types

MAINNET = bytes.fromhex("beeab0de" + "00" * 28)


class TestHiveChainId(common.KeepKeyTest):
    def check_operation(self, request, response_type):
        self.setup_mnemonic_nopin_nopassphrase()
        # All short values are transport-valid but semantically malformed.
        for size in range(32):
            with self.subTest(size=size):
                request.chain_id = b"\xa5" * size
                response = self.client.call_raw(request)
                # Drain old-code consent so the negative control does not
                # leave an outstanding request or approve malformed input.
                if isinstance(response, proto.ButtonRequest):
                    self.client.call_raw(proto.Cancel())
                self.assertIsInstance(response, proto.Failure)
                self.assertEqual(response.code, types.Failure_SyntaxError)

        # Retry through the actual handler after rejection. Omission and an
        # explicit mainnet domain must produce the same deterministic result.
        request.ClearField("chain_id")
        default = self.client.call(request)
        self.assertIsInstance(default, response_type)
        self.assertEqual(len(default.signature), 65)
        request.chain_id = MAINNET
        explicit = self.client.call(request)
        self.assertIsInstance(explicit, response_type)
        self.assertEqual(default.serialized_tx, explicit.serialized_tx)
        self.assertEqual(default.signature, explicit.signature)
        request.chain_id = bytes([MAINNET[0] ^ 1]) + MAINNET[1:]
        custom = self.client.call(request)
        self.assertIsInstance(custom, response_type)
        self.assertEqual(default.serialized_tx, custom.serialized_tx)
        self.assertNotEqual(default.signature, custom.signature)

    def test_transfer_chain_id(self):
        self.check_operation(hive.HiveSignTx(**{
            "address_n": [0x80000030, 0x8000000d, 0x80000001,
                          0x80000000, 0x80000000],
            "ref_block_num": 1, "ref_block_prefix": 2, "expiration": 3,
            "from": "alice", "to": "bob", "amount": 1000,
        }), hive.HiveSignedTx)

    def test_account_create_chain_id(self):
        self.check_operation(hive.HiveSignAccountCreate(
            address_n=[0x80000030, 0x8000000d, 0x80000000,
                       0x80000000, 0x80000000],
            ref_block_num=1, ref_block_prefix=2, expiration=3,
            creator="alice", new_account_name="bob",
        ), hive.HiveSignedAccountCreate)

    def test_account_update_chain_id(self):
        self.check_operation(hive.HiveSignAccountUpdate(
            address_n=[0x80000030, 0x8000000d, 0x80000000,
                       0x80000000, 0x80000000],
            ref_block_num=1, ref_block_prefix=2, expiration=3,
            account="alice",
        ), hive.HiveSignedAccountUpdate)
