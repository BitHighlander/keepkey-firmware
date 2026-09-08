"""Run with python-keepkey/tests on PYTHONPATH against an isolated emulator.

The legacy host pin lacks wire ID 117. Define only that wire contract locally;
this exercises firmware transport without importing a later host feature set.
"""
import unittest
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from keepkeylib import mapping
from keepkeylib.client import CallException
import common

spec = descriptor_pb2.FileDescriptorProto(name="staging_provider.proto", syntax="proto2")
message = spec.message_type.add(name="StagingLoadClearsignSigner")
for number, name, kind in [(1, "key_id", 13), (2, "pubkey", 12),
                           (3, "alias", 9), (7, "persist", 8)]:
    message.field.add(name=name, number=number, type=kind, label=1)
pool = descriptor_pool.DescriptorPool()
pool.Add(spec)
LoadSigner = message_factory.MessageFactory(pool).GetPrototype(
    pool.FindMessageTypeByName("StagingLoadClearsignSigner"))
mapping.map_class_to_type[LoadSigner] = 117
mapping.map_type_to_class[117] = LoadSigner

class RuntimeProvider(common.KeepKeyTest):
    def setUp(self):
        super().setUp()
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy("AdvancedMode", True)
        self.request = LoadSigner(
            key_id=3, alias="Integration provider", persist=False,
            pubkey=bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))

    def test_load_requires_confirmation(self):
        with self.client:
            from keepkeylib import messages_pb2 as proto
            self.client.set_expected_responses([proto.ButtonRequest(), proto.Success()])
            self.client.call(self.request)

    def test_cancel_rejects_load(self):
        self.client.setup_debuglink(False, True)
        with self.assertRaises(CallException):
            self.client.call(self.request)

    def test_persistence_rejected(self):
        self.request.persist = True
        with self.assertRaises(CallException):
            self.client.call(self.request)

    def test_disabled_policy_rejects_load(self):
        self.client.apply_policy("AdvancedMode", False)
        with self.assertRaises(CallException):
            self.client.call(self.request)

    def _sign_transaction(self):
        return self.client.ethereum_sign_tx(
            n=[0x8000002c, 0x8000003c, 0x80000000, 0, 0],
            nonce=0, gas_price=1, gas_limit=100000,
            to=b"\x42" * 20, value=1, chain_id=1, data=b"\x12\x34\x56\x78")

    def _metadata(self, wrong_hash=False, wrong_contract=False):
        import rlp
        from eth_utils import keccak
        from keepkeylib.signed_metadata import serialize_metadata, sign_metadata
        from keepkeylib import messages_ethereum_pb2 as eth
        digest = keccak(rlp.encode([0, 1, 100000, b"\x42" * 20, 1,
                                   b"\x12\x34\x56\x78", 1, 0, 0]))
        if wrong_hash:
            digest = b"\x99" * 32
        payload = serialize_metadata(
            chain_id=1, contract_address=(b"\x43" if wrong_contract else b"\x42") * 20,
            selector=b"\x12\x34\x56\x78", tx_hash=digest,
            method_name="Integration call", args=[], key_id=3, timestamp=0)
        blob = sign_metadata(payload, private_key=(1).to_bytes(32, "big"))
        response = self.client.call(eth.EthereumTxMetadata(signed_payload=blob, key_id=3))
        self.assertEqual(response.classification, 1)

    def test_metadata_is_additive_and_failed_match_falls_back(self):
        self.client.call(self.request)
        seen = []
        original = self.client.callback_ButtonRequest
        def capture(message):
            seen.append(message.code)
            return original(message)
        self.client.callback_ButtonRequest = capture
        baseline = self._sign_transaction()
        baseline_count = len(seen)
        seen.clear()
        self._metadata()
        self.assertEqual(self._sign_transaction(), baseline)
        self.assertGreater(len(seen), baseline_count)
        seen.clear()
        self._metadata(wrong_contract=True)
        self.assertEqual(self._sign_transaction(), baseline)
        self.assertEqual(len(seen), baseline_count)

    def test_cancel_metadata_aborts_signing(self):
        self.client.call(self.request)
        self._metadata()
        self.client.setup_debuglink(False, True)
        with self.assertRaises(CallException):
            self._sign_transaction()

    def test_approved_metadata_cannot_describe_a_different_transaction_hash(self):
        self.client.call(self.request)
        self._metadata(wrong_hash=True)
        with self.assertRaises(CallException):
            self._sign_transaction()

if __name__ == "__main__":
    unittest.main()
