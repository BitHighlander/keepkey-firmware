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

if __name__ == "__main__":
    unittest.main()
