"""Stack 07 protocol regressions; run against an isolated full-feature emulator.

PYTHONPATH must include deps/python-keepkey and deps/python-keepkey/tests.
Uses only the public test mnemonic and a throwaway catalog signing key.
"""

import copy
import hashlib

import common
from keepkeylib import erc7730, erc7730_compiler, eip712_stream
from keepkeylib import messages_ethereum_pb2 as eth
from keepkeylib import messages_pb2 as proto
from keepkeylib.signed_metadata import TEST_PRIVATE_KEY, test_signer_compressed_pubkey as signer_pubkey


PATH = [0x8000002C, 0x8000003C, 0x80000000, 0, 0]
ADDRESS = bytes.fromhex("11" * 20)


class TestStack07CoinTableReuse(common.KeepKeyTest):
    def setUp(self):
        super().setUp()
        self.setup_mnemonic_nopin_nopassphrase()

    def test_cointable_response_reuses_decoded_request_without_truncation(self):
        inventory = self.client.call(proto.GetCoinTable())
        self.assertEqual(inventory.chunk_size, 24)
        count = 2 if inventory.num_coins == 2 else 24
        for end in ([2] if count == 2 else [10, 24]):
            page = self.client.call(proto.GetCoinTable(start=0, end=end))
            self.assertIsInstance(page, proto.CoinTable)
            self.assertEqual(page.chunk_size, 24)
            self.assertEqual(len(page.table), end)
            self.assertEqual(page.num_coins, inventory.num_coins)
        invalid = self.client.call_raw(proto.GetCoinTable(start=0, end=25))
        self.assertIsInstance(invalid, proto.Failure)
        recovered = self.client.call(proto.GetCoinTable(start=0, end=count))
        self.assertEqual(len(recovered.table), count)


class TestStack07Regressions(common.KeepKeyTest):
    def setUp(self):
        super().setUp()
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy("AdvancedMode", 1)

    def _preload(self, program):
        self.client.load_clearsign_signer(
            key_id=3, pubkey=signer_pubkey(), alias="Audit signer")
        cert = bytearray(139)
        cert[0] = 1
        cert[2:6] = (1).to_bytes(4, "big")
        cert[10:21] = b"Host alias\0"
        cert[42:75] = signer_pubkey()
        envelope = erc7730.sign_envelope(program, cert, TEST_PRIVATE_KEY)
        definition = erc7730.Definition(
            envelope, program[7], 1, ADDRESS,
            program[38:42] if program[7] == 1 else program[38:70])
        erc7730.preload(self.client, definition)
        self._drop_setup_screenshots()
        return envelope

    def _walk(self, start, envelope=b"", doc=None, change_pass=None, cancel_button=None):
        response = self.client.call_raw(start)
        buttons = 0
        calldata_passes = 0
        typed_passes = 0
        for _ in range(1000):
            if isinstance(response, proto.ButtonRequest):
                buttons += 1
                self.client.capture_oled()
                self.client.debug.press_yes() if buttons != cancel_button else self.client.debug.press_no()
                response = self.client.call_raw(proto.ButtonAck())
            elif isinstance(response, eth.EthereumClearSignDefinitionRequest):
                offset = response.offset
                response = self.client.call_raw(eth.EthereumClearSignDefinitionChunk(
                    definition_id=hashlib.sha256(envelope).digest(), offset=offset,
                    total_length=len(envelope), data=envelope[offset:offset + response.length]))
            elif isinstance(response, eth.EthereumTypedDataStructRequest):
                response = self.client.call_raw(eip712_stream.build_struct_ack(
                    eip712_stream.struct_members(doc, response.name)))
            elif isinstance(response, eth.EthereumTypedDataValueRequest):
                path = list(response.member_path)
                if path == [1, 0]:
                    typed_passes += 1
                current = copy.deepcopy(doc)
                if change_pass == typed_passes:
                    current["message"]["first"] += 1
                resolved = eip712_stream.resolve_member_path(current, path)
                value = (eip712_stream.encode_array_length(resolved[1])
                         if resolved[0] == "length" else
                         eip712_stream.encode_value(resolved[1], resolved[2]))
                response = self.client.call_raw(eth.EthereumTypedDataValueAck(value=value))
            elif isinstance(response, eth.EthereumTxRequest) and response.HasField("data_length"):
                calldata_passes += 1
                arguments = (43 if change_pass == calldata_passes else 42).to_bytes(32, "big")
                arguments += (7).to_bytes(32, "big")
                self.assertEqual(response.data_length, len(arguments))
                response = self.client.call_raw(eth.EthereumTxAck(data_chunk=arguments))
            else:
                return response, buttons, calldata_passes, typed_passes
        self.fail("protocol did not terminate")

    def _typed_fixture(self, fields=True):
        doc = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                    {"name": "salt", "type": "bytes32"}],
                "Mail": [{"name": "first", "type": "uint256"},
                         {"name": "second", "type": "uint256"}]},
            "primaryType": "Mail",
            "domain": {"name": "Audit app", "version": "1", "chainId": 1,
                       "verifyingContract": "0x" + ADDRESS.hex(), "salt": "0x" + "22" * 32},
            "message": {"first": 42, "second": 7}}
        descriptor = {"display": {"formats": {"Mail(uint256 first,uint256 second)": {
            "intent": "Audit action", "fields": [
                {"path": name, "label": label, "format": "raw"}
                for name, label in (("first", "First value"), ("second", "Second value"))
            ] if fields else []}}}}
        return doc, erc7730_compiler.compile_eip712(descriptor, doc)

    def _typed_start(self):
        return eth.EthereumSignTypedData(address_n=PATH, primary_type="Mail", metamask_v4_compat=True)

    def test_all_typed_fields_are_reviewed_and_signature_is_unchanged(self):
        doc, program = self._typed_fixture()
        baseline, baseline_buttons, _, _ = self._walk(self._typed_start(), doc=doc)
        self.assertIsInstance(baseline, eth.EthereumTypedDataSignature)
        envelope = self._preload(program)
        result, buttons, _, passes = self._walk(self._typed_start(), envelope, doc)
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        self.assertEqual(result.signature, baseline.signature)
        self.assertEqual(passes, 2)
        self.assertEqual(buttons, baseline_buttons + 7)  # identity/warning/intent, two fields, two replayed leaves

    def test_typed_replay_change_is_refused(self):
        doc, program = self._typed_fixture()
        envelope = self._preload(program)
        result, _, _, passes = self._walk(self._typed_start(), envelope, doc, change_pass=2)
        self.assertIsInstance(result, proto.Failure)
        self.assertEqual(passes, 2)

    def test_declining_source_intent_or_either_field_aborts(self):
        for declined in (8, 9, 10, 11, 14):
            doc, program = self._typed_fixture()
            envelope = self._preload(program)
            result, buttons, _, _ = self._walk(
                self._typed_start(), envelope, doc, cancel_button=declined)
            self.assertIsInstance(result, proto.Failure)
            self.assertEqual(buttons, declined)
            self.client.init_device()
            result, buttons, _, _ = self._walk(self._typed_start(), doc=doc)
            self.assertIsInstance(result, eth.EthereumTypedDataSignature)
            self.assertEqual(buttons, 7)

    def test_domain_name_version_and_salt_mismatches_are_refused(self):
        for field, changed in (("name", "Different app"), ("version", "2"), ("salt", "0x" + "33" * 32)):
            doc, program = self._typed_fixture()
            envelope = self._preload(program)
            doc["domain"][field] = changed
            result, _, _, passes = self._walk(self._typed_start(), envelope, doc)
            self.assertIsInstance(result, proto.Failure, field)
            self.assertEqual(passes, 0)

    def test_failed_certified_domain_clears_preload(self):
        doc, program = self._typed_fixture()
        envelope = self._preload(program)
        changed = copy.deepcopy(doc)
        changed["domain"]["chainId"] = 2
        result, _, _, _ = self._walk(self._typed_start(), envelope, changed)
        self.assertIsInstance(result, proto.Failure)
        result, buttons, _, _ = self._walk(self._typed_start(), doc=doc)
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        self.assertEqual(buttons, 7)

    def test_early_typed_failure_clears_preload(self):
        doc, program = self._typed_fixture()
        self._preload(program)
        result = self.client.call_raw(eth.EthereumSignTypedData(
            address_n=PATH, primary_type="", metamask_v4_compat=True))
        self.assertIsInstance(result, proto.Failure)
        result, buttons, _, _ = self._walk(self._typed_start(), doc=doc)
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        self.assertEqual(buttons, 7)

    def test_empty_message_requires_explicit_consent(self):
        doc, _ = self._typed_fixture()
        doc["types"]["Mail"] = []
        doc["message"] = {}
        result, buttons, _, _ = self._walk(self._typed_start(), doc=doc,
                                           cancel_button=6)
        self.assertIsInstance(result, proto.Failure)
        self.assertEqual(buttons, 6)
        result, buttons, _, _ = self._walk(self._typed_start(), doc=doc)
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        self.assertEqual(buttons, 6)

    def test_intent_only_typed_definition_still_requires_source_and_intent(self):
        doc, program = self._typed_fixture(fields=False)
        envelope = self._preload(program)
        result, buttons, _, _ = self._walk(self._typed_start(), envelope, doc)
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        self.assertEqual(buttons, 10)  # five domain leaves, three source/intent screens, two message leaves

    def test_calldata_signing_replay_change_is_refused(self):
        signature = "audit(uint256 first,uint256 second)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Audit action", "fields": [
                {"path": "first", "label": "First value", "format": "raw"},
                {"path": "second", "label": "Second value", "format": "raw"}]}}}}
        program = erc7730_compiler.compile_calldata(descriptor, signature, 1, ADDRESS)
        envelope = self._preload(program)
        start = eth.EthereumSignTx(address_n=PATH, nonce=b"", gas_price=b"\x01",
            gas_limit=b"\xff\xff", to=ADDRESS, value=b"", chain_id=1,
            data_length=68, data_initial_chunk=program[38:42])
        result, _, passes, _ = self._walk(start, envelope, change_pass=4)
        self.assertIsInstance(result, proto.Failure)
        self.assertEqual(passes, 4)

    def test_calldata_signing_replay_succeeds_with_arguments(self):
        signature = "audit(uint256 first,uint256 second)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Audit action", "fields": [
                {"path": "first", "label": "First value", "format": "raw"},
                {"path": "second", "label": "Second value", "format": "raw"}]}}}}
        program = erc7730_compiler.compile_calldata(descriptor, signature, 1, ADDRESS)
        start = eth.EthereumSignTx(address_n=PATH, nonce=b"", gas_price=b"\x01",
            gas_limit=b"\xff\xff", to=ADDRESS, value=b"", chain_id=1,
            data_length=68, data_initial_chunk=program[38:42])
        baseline, _, baseline_passes, _ = self._walk(start)
        self.assertIsInstance(baseline, eth.EthereumTxRequest)
        self.assertTrue(baseline.HasField("signature_r"))
        self.assertEqual(baseline_passes, 1)
        envelope = self._preload(program)
        result, _, passes, _ = self._walk(start, envelope)
        self.assertIsInstance(result, eth.EthereumTxRequest)
        self.assertEqual(result.signature_r, baseline.signature_r)
        self.assertEqual(result.signature_s, baseline.signature_s)
        self.assertEqual(passes, 4)

    def test_selector_only_call_signs_after_certified_intent(self):
        signature = "audit()"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Audit action", "fields": []}}}}
        program = erc7730_compiler.compile_calldata(descriptor, signature, 1, ADDRESS)
        start = eth.EthereumSignTx(address_n=PATH, nonce=b"", gas_price=b"\x01",
            gas_limit=b"\xff\xff", to=ADDRESS, value=b"", chain_id=1,
            data_length=4, data_initial_chunk=program[38:42])
        baseline, baseline_buttons, _, _ = self._walk(start)
        self.assertIsInstance(baseline, eth.EthereumTxRequest)
        self.assertTrue(baseline.HasField("signature_r"))
        envelope = self._preload(program)
        result, buttons, passes, _ = self._walk(start, envelope)
        self.assertIsInstance(result, eth.EthereumTxRequest)
        self.assertEqual(result.signature_r, baseline.signature_r)
        self.assertEqual(result.signature_s, baseline.signature_s)
        self.assertEqual(buttons, baseline_buttons + 3)
        self.assertEqual(passes, 0)

    def test_certified_approval_refused_before_annotation_screens(self):
        signature = "approve(address spender,uint256 amount)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Approve tokens", "fields": [
                {"path": "amount", "label": "Allowance", "format": "raw"}]}}}}
        program = erc7730_compiler.compile_calldata(descriptor, signature, 1, ADDRESS)
        envelope = self._preload(program)
        selector = program[38:42]
        start = eth.EthereumSignTx(address_n=PATH, nonce=b"", gas_price=b"\x01",
            gas_limit=b"\xff\xff", to=ADDRESS, value=b"", chain_id=1,
            data_length=68, data_initial_chunk=selector)
        result, buttons, _, _ = self._walk(start, envelope)
        self.assertIsInstance(result, proto.Failure)
        self.assertEqual(result.message, "ERC-7730 approval not supported")
        self.assertEqual(buttons, 0)

        # A finite approval with all 68 bytes supplied up front still reaches
        # the established ordinary review and signing path.
        data = selector + b"\x00" * 12 + ADDRESS + (42).to_bytes(32, "big")
        ordinary = eth.EthereumSignTx(address_n=PATH, nonce=b"", gas_price=b"\x01",
            gas_limit=b"\xff\xff", to=ADDRESS, value=b"", chain_id=1,
            data_length=68, data_initial_chunk=data)
        result, buttons, _, _ = self._walk(ordinary)
        self.assertIsInstance(result, eth.EthereumTxRequest)
        self.assertTrue(result.HasField("signature_r"))
        self.assertGreater(buttons, 0)
