"""Real-transport checks for additive transaction-bound Solana annotations."""
import hashlib
import struct
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from ecdsa import SigningKey, SECP256k1, util
from keepkeylib import mapping, messages_solana_pb2 as sol
from keepkeylib.client import CallException
import common
import test_runtime_provider as provider

spec = descriptor_pb2.FileDescriptorProto(name="staging_solana.proto", syntax="proto2")
message = spec.message_type.add(name="StagingSolanaSignTx")
for number, name, kind, label in [(1,"address_n",13,3),(3,"raw_tx",12,1),
                                 (5,"lut_account",12,3),(6,"lut_signature",12,1),
                                 (7,"lut_signer_key_id",13,1)]:
    message.field.add(name=name, number=number, type=kind, label=label)
pool = descriptor_pool.DescriptorPool()
pool.Add(spec)
SignTx = message_factory.MessageFactory(pool).GetPrototype(pool.FindMessageTypeByName("StagingSolanaSignTx"))
mapping.map_class_to_type[SignTx] = 752

class SolanaProvider(common.KeepKeyTest):
    def setUp(self):
        super().setUp()
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy("AdvancedMode", True)
        self.request = provider.LoadSigner(
            key_id=3, alias="Integration provider", persist=False,
            pubkey=bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))
        self.client.call(self.request)
        self.path = [0x8000002c, 0x800001f5, 0x80000000, 0x80000000]
        address = self.client.call(sol.SolanaGetAddress(address_n=self.path, show_display=False)).address
        value = 0
        for char in address:
            value = value * 58 + '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'.index(char)
        owner = value.to_bytes(32, 'big')
        # Static signer + system program; recipient comes from one writable LUT entry.
        self.raw = (b'\x80\x01\x00\x01\x02' + owner + bytes(32) + b'\xbb'*32 +
                    b'\x01\x01\x02\x00\x02\x0c' + struct.pack('<IQ',2,1000) +
                    b'\x01' + b'\x55'*32 + b'\x01\x00\x00')
        self.accounts = [b'\x22'*32]

    def sign(self, annotated=False, corrupt=False):
        msg = SignTx(address_n=self.path, raw_tx=self.raw)
        if annotated:
            preimage = (b'KeepKeySolanaTxAccounts/1' + hashlib.sha256(self.raw).digest() +
                        struct.pack('<I',len(self.accounts)) + b''.join(self.accounts))
            key = SigningKey.from_secret_exponent(1, curve=SECP256k1)
            signature = key.sign_digest_deterministic(hashlib.sha256(preimage).digest(), sigencode=util.sigencode_string)
            if corrupt:
                signature = bytes([signature[0]^1]) + signature[1:]
            msg.lut_account.extend(self.accounts)
            msg.lut_signature = signature
            msg.lut_signer_key_id = 3
        return self.client.call(msg).signature

    def test_context_is_additive_and_bad_signature_falls_back(self):
        seen = []
        original = self.client.callback_ButtonRequest
        def capture(message):
            seen.append(message.code)
            return original(message)
        self.client.callback_ButtonRequest = capture
        baseline = self.sign()
        original_flow = list(seen)
        seen.clear()
        self.assertEqual(baseline, self.sign(annotated=True))
        self.assertEqual(len(seen), len(original_flow) + 2)
        # Provider identity/account screens precede, and retain, blind review.
        self.assertEqual(seen[-len(original_flow):], original_flow)
        seen.clear()
        self.assertEqual(baseline, self.sign(annotated=True, corrupt=True))
        self.assertEqual(seen, original_flow)

    def test_cancel_provider_context_aborts(self):
        self.client.setup_debuglink(False, True)
        with self.assertRaises(CallException):
            self.sign(annotated=True)
