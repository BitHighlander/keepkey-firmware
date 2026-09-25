"""Stack 07 protocol regressions; run against an isolated full-feature emulator.

PYTHONPATH must include deps/python-keepkey and deps/python-keepkey/tests.
Uses only the public test mnemonic and a throwaway catalog signing key.
"""

import copy
import hashlib
import os

import common
from keepkeylib import erc7730, erc7730_compiler, eip712_stream
from keepkeylib import messages_ethereum_pb2 as eth
from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as types
from keepkeylib.signed_metadata import TEST_PRIVATE_KEY, test_signer_compressed_pubkey as signer_pubkey


PATH = [0x8000002C, 0x8000003C, 0x80000000, 0, 0]
ADDRESS = bytes.fromhex("11" * 20)
OTHER_ADDRESS = bytes.fromhex("33" * 20)
# An unrelated throwaway key that is never loaded into any signer slot.
UNKNOWN_SIGNER_KEY = bytes.fromhex("42" * 32)

# The product under test is declared by the caller (python-keepkey-tests.sh),
# never inferred from the device: a regressed full build that answered like
# the bitcoin-only product must fail here, not select the smaller contract.
VARIANTS = {"full": ("Emulator", "KeepKey"),
            "bitcoin-only": ("EmulatorBTC", "KeepKeyBTC")}
BITCOIN_ONLY_SKIP = "Stack 07 EVM contracts are intentionally absent from bitcoin-only"


# Uncertified Mail fixture, ButtonRequest by ButtonRequest: five domain leaves
# ("EIP-712 Domain"; the bytes32 salt body pages once, so six requests), two
# message leaves ("Mail"), then the final "Sign Typed Data" screen, whose
# "from <address>?" body pages once (SignTx, then one continuation page).
MAIL_UNCERTIFIED_BUTTONS = 10
# Certified order: domain (1-6), message pass one (7-8), runtime signer (9),
# unverified-data warning (10), contract action (11), first field (12),
# replayed message leaves (13-14), second field (15), final screen (16-17).
MAIL_CERTIFIED_DECLINABLE = (9, 10, 11, 12, 15)
# Empty Mail: six domain requests, then the final screen (two requests).
EMPTY_MAIL_FINAL_SCREEN = 7
EMPTY_MAIL_BUTTONS = 8


def assert_single_final_sign_screen(test):
    """Exactly one SignTx request -- the final "Sign Typed Data" screen --
    and nothing after it except its own continuation page(s)."""
    codes = test.button_codes
    test.assertEqual(codes.count(types.ButtonRequest_SignTx), 1)
    final = codes.index(types.ButtonRequest_SignTx)
    test.assertTrue(all(code == types.ButtonRequest_Other
                        for code in codes[final + 1:]))
    return final


def expected_variant(test):
    variant = os.environ.get("KK_STACK07_FIRMWARE_VARIANT")
    if variant not in VARIANTS:
        test.fail("KK_STACK07_FIRMWARE_VARIANT must be full or bitcoin-only, got %r"
                  % variant)
    test.assertIn(test.client.features.firmware_variant, VARIANTS[variant])
    return variant


def assert_failure(test, result, code, message):
    test.assertIsInstance(result, proto.Failure)
    test.assertEqual((result.code, result.message), (code, message))


class TestStack07CoinTableReuse(common.KeepKeyTest):
    def setUp(self):
        super().setUp()
        self.setup_mnemonic_nopin_nopassphrase()

    def test_cointable_response_reuses_decoded_request_without_truncation(self):
        variant = expected_variant(self)
        inventory = self.client.call(proto.GetCoinTable())
        self.assertEqual(inventory.chunk_size, 24)
        if variant == "bitcoin-only":
            self.assertEqual(inventory.num_coins, 2)
            count, ends = 2, [2]
        else:
            self.assertGreater(inventory.num_coins, 24)
            count, ends = 24, [10, 24]
        for end in ends:
            page = self.client.call(proto.GetCoinTable(start=0, end=end))
            self.assertIsInstance(page, proto.CoinTable)
            self.assertEqual(page.chunk_size, 24)
            self.assertEqual(len(page.table), end)
            self.assertEqual(page.num_coins, inventory.num_coins)
        invalid = self.client.call_raw(proto.GetCoinTable(start=0, end=25))
        assert_failure(self, invalid, types.Failure_Other,
                       "Incorrect GetCoinTable parameters")
        recovered = self.client.call(proto.GetCoinTable(start=0, end=count))
        self.assertEqual(len(recovered.table), count)


class TestStack07Regressions(common.KeepKeyTest):
    def setUp(self):
        super().setUp()
        if expected_variant(self) == "bitcoin-only":
            self.skipTest(BITCOIN_ONLY_SKIP)
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy("AdvancedMode", 1)

    def _envelope(self, program, signer_key=TEST_PRIVATE_KEY, signer_pub=None):
        cert = bytearray(139)
        cert[0] = 1
        cert[2:6] = (1).to_bytes(4, "big")
        cert[10:21] = b"Host alias\0"
        cert[42:75] = signer_pub if signer_pub is not None else signer_pubkey()
        return erc7730.sign_envelope(program, cert, signer_key)

    def _definition(self, program, envelope):
        return erc7730.Definition(
            envelope, program[7], 1, ADDRESS,
            program[38:42] if program[7] == 1 else program[38:70])

    def _load_signer(self):
        self.client.load_clearsign_signer(
            key_id=3, pubkey=signer_pubkey(), alias="Audit signer")

    def _preload(self, program):
        self._load_signer()
        envelope = self._envelope(program)
        erc7730.preload(self.client, self._definition(program, envelope))
        self._drop_setup_screenshots()
        return envelope

    def _raw_preload(self, envelope):
        """Stream an envelope; return the first non-Ack response.

        Every refusal contract below is a refusal BEFORE any ButtonRequest,
        so a ButtonRequest here is returned (and fails the caller's Failure
        assertion) rather than acknowledged.
        """
        definition_id = hashlib.sha256(envelope).digest()
        offset = 0
        while offset < len(envelope):
            data = envelope[offset:offset + erc7730.MAX_CHUNK]
            response = self.client.call_raw(eth.EthereumClearSignDefinition(
                definition_id=definition_id, offset=offset,
                total_length=len(envelope), data=data))
            if not isinstance(response, eth.EthereumClearSignDefinitionAck):
                return response
            offset += len(data)
        return response

    def _walk(self, start, envelope=b"", doc=None, change_pass=None, cancel_button=None,
              arguments=None):
        response = self.client.call_raw(start)
        self.definition_requests = 0
        self.button_codes = []
        self.screens = []
        buttons = 0
        calldata_passes = 0
        typed_passes = 0
        for _ in range(1000):
            if isinstance(response, proto.ButtonRequest):
                buttons += 1
                self.button_codes.append(response.code)
                self.screens.append(self.client.debug.read_confirm_text())
                self.client.capture_oled()
                self.client.debug.press_yes() if buttons != cancel_button else self.client.debug.press_no()
                response = self.client.call_raw(proto.ButtonAck())
            elif isinstance(response, eth.EthereumClearSignDefinitionRequest):
                self.definition_requests += 1
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
                data = arguments
                if data is None:
                    data = (43 if change_pass == calldata_passes else 42).to_bytes(32, "big")
                    data += (7).to_bytes(32, "big")
                self.assertEqual(response.data_length, len(data))
                response = self.client.call_raw(eth.EthereumTxAck(data_chunk=data))
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
        self.assertEqual(baseline_buttons, MAIL_UNCERTIFIED_BUTTONS)
        self.assertEqual(buttons, baseline_buttons + 7)  # identity/warning/intent, two fields, two replayed leaves
        assert_single_final_sign_screen(self)

    def test_typed_replay_change_is_refused(self):
        doc, program = self._typed_fixture()
        envelope = self._preload(program)
        result, _, _, passes = self._walk(self._typed_start(), envelope, doc, change_pass=2)
        assert_failure(self, result, types.Failure_SyntaxError,
                       "Certified EIP-712 value was not found")
        self.assertEqual(passes, 2)

    def test_declining_source_intent_or_either_field_aborts(self):
        for declined in MAIL_CERTIFIED_DECLINABLE:
            doc, program = self._typed_fixture()
            envelope = self._preload(program)
            result, buttons, _, _ = self._walk(
                self._typed_start(), envelope, doc, cancel_button=declined)
            assert_failure(self, result, types.Failure_ActionCancelled,
                           "Signing cancelled by user")
            self.assertEqual(buttons, declined)
            self.client.init_device()
            result, buttons, _, _ = self._walk(self._typed_start(), doc=doc)
            self.assertIsInstance(result, eth.EthereumTypedDataSignature)
            self.assertEqual(buttons, MAIL_UNCERTIFIED_BUTTONS)

    def test_domain_name_version_and_salt_mismatches_are_refused(self):
        for field, changed in (("name", "Different app"), ("version", "2"), ("salt", "0x" + "33" * 32)):
            doc, program = self._typed_fixture()
            envelope = self._preload(program)
            doc["domain"][field] = changed
            result, buttons, _, passes = self._walk(self._typed_start(), envelope, doc)
            assert_failure(self, result, types.Failure_SyntaxError,
                           "ERC-7730 domain constraint does not match")
            self.assertEqual(passes, 0)

    def test_failed_certified_domain_clears_preload(self):
        doc, program = self._typed_fixture()
        envelope = self._preload(program)
        changed = copy.deepcopy(doc)
        changed["domain"]["chainId"] = 2
        result, _, _, _ = self._walk(self._typed_start(), envelope, changed)
        assert_failure(self, result, types.Failure_SyntaxError,
                       "ERC-7730 definition does not match typed data")
        self.assertEqual(self.definition_requests, 0)
        result, buttons, _, _ = self._walk(self._typed_start(), doc=doc)
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        self.assertEqual(buttons, MAIL_UNCERTIFIED_BUTTONS)

    def test_early_typed_failure_clears_preload(self):
        doc, program = self._typed_fixture()
        self._preload(program)
        result = self.client.call_raw(eth.EthereumSignTypedData(
            address_n=PATH, primary_type="", metamask_v4_compat=True))
        assert_failure(self, result, types.Failure_SyntaxError,
                       "EIP-712 primary type missing or too long")
        result, buttons, _, _ = self._walk(self._typed_start(), doc=doc)
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        self.assertEqual(buttons, MAIL_UNCERTIFIED_BUTTONS)

    def test_empty_message_requires_explicit_consent(self):
        doc, _ = self._typed_fixture()
        doc["types"]["Mail"] = []
        doc["message"] = {}
        result, buttons, _, _ = self._walk(self._typed_start(), doc=doc,
                                           cancel_button=EMPTY_MAIL_FINAL_SCREEN)
        # The stream's own empty-message screen is gone: the explicit consent
        # is the final "Sign EMPTY Mail" screen, and declining it signs nothing.
        assert_failure(self, result, types.Failure_ActionCancelled,
                       "Signing cancelled by user")
        self.assertEqual(buttons, EMPTY_MAIL_FINAL_SCREEN)
        self.assertEqual(self.button_codes[-1], types.ButtonRequest_SignTx)
        result, buttons, _, _ = self._walk(self._typed_start(), doc=doc)
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        self.assertEqual(buttons, EMPTY_MAIL_BUTTONS)
        assert_single_final_sign_screen(self)

    def test_intent_only_typed_definition_still_requires_source_and_intent(self):
        doc, program = self._typed_fixture(fields=False)
        envelope = self._preload(program)
        result, buttons, _, _ = self._walk(self._typed_start(), envelope, doc)
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        # six domain requests, three source/intent screens, two message
        # leaves, two final-screen requests
        self.assertEqual(buttons, 13)
        assert_single_final_sign_screen(self)

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
        assert_failure(self, result, types.Failure_SyntaxError,
                       "ERC-7730 calldata does not match definition")
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

    def test_non_ascii_intent_is_escaped_not_drawn_as_glyphs(self):
        # The OLED draws every non-ASCII byte as one identical glyph, so signer
        # strings are escaped like values. Drawn raw, 64 x U+00E9 (128 bytes)
        # pages exactly like 128 ASCII bytes; escaped it is 512 characters and
        # needs more screens. Equal counts would mean raw glyphs were shown.
        def certified_buttons(intent):
            signature = "audit()"
            descriptor = {"display": {"formats": {signature: {
                "intent": intent, "fields": []}}}}
            program = erc7730_compiler.compile_calldata(
                descriptor, signature, 1, ADDRESS)
            start = eth.EthereumSignTx(address_n=PATH, nonce=b"",
                gas_price=b"\x01", gas_limit=b"\xff\xff", to=ADDRESS,
                value=b"", chain_id=1, data_length=4,
                data_initial_chunk=program[38:42])
            baseline, baseline_buttons, _, _ = self._walk(start)
            result, buttons, passes, _ = self._walk(
                start, self._preload(program))
            self.assertIsInstance(result, eth.EthereumTxRequest)
            self.assertEqual(result.signature_r, baseline.signature_r)
            self.assertEqual(result.signature_s, baseline.signature_s)
            self.assertEqual(passes, 0)
            return buttons - baseline_buttons

        self.assertGreater(certified_buttons("\u00e9" * 64),
                           certified_buttons("e" * 128))

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
        assert_failure(self, result, types.Failure_SyntaxError,
                       "ERC-7730 approval not supported")
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

    def test_verifying_contract_mismatch_is_refused_before_certified_review(self):
        doc, program = self._typed_fixture()
        envelope = self._preload(program)
        doc["domain"]["verifyingContract"] = "0x" + OTHER_ADDRESS.hex()
        result, buttons, _, passes = self._walk(self._typed_start(), envelope, doc)
        # Firmware contract (eip712_pump, EIP712_REQ_DEFINITION): the catalog
        # identity is matched once the domain has been walked, so the ordinary
        # domain review precedes the refusal, but no certified definition byte
        # is requested and no message leaf is ever streamed or shown.
        assert_failure(self, result, types.Failure_SyntaxError,
                       "ERC-7730 definition does not match typed data")
        self.assertEqual(self.definition_requests, 0)
        self.assertEqual(passes, 0)

    def test_tampered_envelope_signature_is_refused_at_preload(self):
        _, program = self._typed_fixture()
        self._load_signer()
        envelope = bytearray(self._envelope(program))
        envelope[-2] ^= 0x01  # last byte of the 64-byte compact signature
        result = self._raw_preload(bytes(envelope))
        assert_failure(self, result, types.Failure_SyntaxError,
                       "Invalid certified ERC-7730 definition")

    def test_unknown_signer_is_refused_at_preload(self):
        from ecdsa import SigningKey, SECP256k1
        _, program = self._typed_fixture()
        self._load_signer()
        unknown_pub = SigningKey.from_string(
            UNKNOWN_SIGNER_KEY, curve=SECP256k1).get_verifying_key().to_string(
                "compressed")
        self.assertNotEqual(unknown_pub, signer_pubkey())
        envelope = self._envelope(program, UNKNOWN_SIGNER_KEY, unknown_pub)
        result = self._raw_preload(envelope)
        assert_failure(self, result, types.Failure_SyntaxError,
                       "Invalid certified ERC-7730 definition")

    def test_advanced_mode_off_refuses_preload(self):
        _, program = self._typed_fixture()
        self._load_signer()
        envelope = self._envelope(program)
        self.client.apply_policy("AdvancedMode", 0)
        result = self._raw_preload(envelope)
        assert_failure(self, result, types.Failure_Other,
                       "AdvancedMode required for ERC-7730")

    def test_domain_only_signature_refuses_certified_preload(self):
        doc, program = self._typed_fixture()
        envelope = self._preload(program)
        result, _, _, passes = self._walk(eth.EthereumSignTypedData(
            address_n=PATH, primary_type="EIP712Domain",
            metamask_v4_compat=True), envelope, doc)
        assert_failure(self, result, types.Failure_SyntaxError,
                       "ERC-7730 cannot describe a domain-only signature")
        self.assertNotIn(types.ButtonRequest_SignTx, self.button_codes)
        self.assertEqual(passes, 0)

    def test_dirty_approval_spender_word_is_refused_before_any_screen(self):
        clean = (bytes.fromhex("095ea7b3") + bytes(12) + ADDRESS +
                 (42).to_bytes(32, "big"))
        for offset in (4, 15):  # first and last padding byte of the spender word
            data = bytearray(clean)
            data[offset] = 0x01
            start = eth.EthereumSignTx(address_n=PATH, nonce=b"",
                gas_price=b"\x01", gas_limit=b"\xff\xff", to=ADDRESS,
                value=b"", chain_id=1, data_length=68,
                data_initial_chunk=bytes(data))
            # call_raw: the refusal must be the FIRST response, i.e. no
            # ButtonRequest precedes it.
            result = self.client.call_raw(start)
            assert_failure(self, result, types.Failure_SyntaxError,
                           "Malformed ERC20 approval")
        result, buttons, _, _ = self._walk(eth.EthereumSignTx(
            address_n=PATH, nonce=b"", gas_price=b"\x01",
            gas_limit=b"\xff\xff", to=ADDRESS, value=b"", chain_id=1,
            data_length=68, data_initial_chunk=clean))
        self.assertIsInstance(result, eth.EthereumTxRequest)
        self.assertTrue(result.HasField("signature_r"))
        self.assertGreater(buttons, 0)

    def test_preload_survives_get_features_and_is_discarded_by_initialize(self):
        signature = "audit(uint256 first,uint256 second)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Audit action", "fields": [
                {"path": "first", "label": "First value", "format": "raw"},
                {"path": "second", "label": "Second value", "format": "raw"}]}}}}
        program = erc7730_compiler.compile_calldata(descriptor, signature, 1, ADDRESS)
        start = eth.EthereumSignTx(address_n=PATH, nonce=b"", gas_price=b"\x01",
            gas_limit=b"\xff\xff", to=ADDRESS, value=b"", chain_id=1,
            data_length=68, data_initial_chunk=program[38:42])
        baseline, baseline_buttons, baseline_passes, _ = self._walk(start)
        self.assertTrue(baseline.HasField("signature_r"))
        self.assertEqual((baseline_passes, self.definition_requests), (1, 0))

        # GetFeatures and Ping pass through without touching the preload.
        envelope = self._preload(program)
        self.assertIsInstance(self.client.call_raw(proto.GetFeatures()),
                              proto.Features)
        self.assertIsInstance(self.client.call_raw(proto.Ping(message="x")),
                              proto.Success)
        result, _, passes, _ = self._walk(start, envelope)
        self.assertEqual(result.signature_r, baseline.signature_r)
        self.assertEqual(passes, 4)
        self.assertGreater(self.definition_requests, 0)

        # Initialize discards it: the same transaction takes the ordinary,
        # uncertified path and signs exactly as the baseline did.
        envelope = self._preload(program)
        self.client.init_device()
        result, buttons, passes, _ = self._walk(start, envelope)
        self.assertIsInstance(result, eth.EthereumTxRequest)
        self.assertEqual((result.signature_r, result.signature_s),
                         (baseline.signature_r, baseline.signature_s))
        self.assertEqual((passes, self.definition_requests), (1, 0))
        self.assertEqual(buttons, baseline_buttons)

    # Phase 0 of the ERC-7730 formatter plan: the preload verifier and the
    # runtime share one capability table, so a program the runtime cannot
    # finish is refused before the first screen instead of after the user has
    # approved the signer, intent and earlier fields.
    def _audit_start(self, program, data_length=68):
        return eth.EthereumSignTx(address_n=PATH, nonce=b"", gas_price=b"\x01",
            gas_limit=b"\xff\xff", to=ADDRESS, value=b"", chain_id=1,
            data_length=data_length, data_initial_chunk=program[38:42])

    def test_program_outside_capability_table_is_refused_at_preload(self):
        signature = "audit(uint256 first,uint256 second)"
        # Shapes the runtime does not execute yet (Phase D).
        fields = {
            "group": {"label": "Group", "fields": [
                {"path": "first", "label": "First value", "format": "raw"}]},
            "condition": {"path": "first", "label": "First value",
                          "format": "raw", "visible": {"ifNotIn": [0]}},
        }
        self._load_signer()
        for name, field in sorted(fields.items()):
            descriptor = {"display": {"formats": {signature: {
                "intent": "Audit action", "fields": [
                    field,
                    {"path": "second", "label": "Second value",
                     "format": "raw"}]}}}}
            with self.assertRaises(erc7730_compiler.DeviceCannotExecute):
                erc7730_compiler.compile_calldata(
                    descriptor, signature, 1, ADDRESS)
            program = erc7730_compiler.compile_calldata(
                descriptor, signature, 1, ADDRESS, executable_only=False)
            result = self._raw_preload(self._envelope(program))
            assert_failure(self, result, types.Failure_SyntaxError,
                           "Invalid certified ERC-7730 definition")
            # Nothing is left preloaded: the transaction takes the ordinary,
            # uncertified path and never asks for a definition.
            result, _, passes, _ = self._walk(self._audit_start(program))
            self.assertIsInstance(result, eth.EthereumTxRequest, msg=name)
            self.assertTrue(result.HasField("signature_r"), msg=name)
            self.assertEqual((name, passes, self.definition_requests),
                             (name, 1, 0))

    def test_path_outside_abi_is_refused_at_preload(self):
        signature = "audit(uint256 first,uint256 second)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Audit action", "fields": [
                {"path": "second", "label": "Second value",
                 "format": "raw"}]}}}}
        program = bytearray(erc7730_compiler.compile_calldata(
            descriptor, signature, 1, ADDRESS))
        # The single value path is (source 1, one step, index 1). Point it at
        # a third argument the function does not have.
        step = program.index(bytes([1, 1, 0xff, 0xff, 1, 0, 0, 0, 1]))
        program[step + 8] = 2
        self._load_signer()
        result = self._raw_preload(self._envelope(bytes(program)))
        assert_failure(self, result, types.Failure_SyntaxError,
                       "Invalid certified ERC-7730 definition")

    def test_raw_field_screens_show_exact_text(self):
        signature = "audit(uint256 first,uint256 second)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Audit action", "fields": [
                {"path": "first", "label": "First value", "format": "raw"},
                {"path": "second", "label": "Second value",
                 "format": "raw"}]}}}}
        program = erc7730_compiler.compile_calldata(
            descriptor, signature, 1, ADDRESS)
        envelope = self._preload(program)
        result, _, passes, _ = self._walk(self._audit_start(program), envelope)
        self.assertIsInstance(result, eth.EthereumTxRequest)
        self.assertEqual(passes, 4)
        certified = [screen for screen in self.screens if screen[0] in (
            "Runtime signer", "Unverified data", "Contract action",
            "Signer field")]
        self.assertEqual(certified[1:], [
            ("Unverified data", "NOT verified by KeepKey"),
            ("Contract action", "Audit action"),
            ("Signer field", "First value:\n42"),
            ("Signer field", "Second value:\n7"),
        ])
        self.assertEqual(certified[0][0], "Runtime signer")
        self.assertTrue(certified[0][1].startswith("Audit signer ("),
                        certified[0][1])

    # Phase A: tokenAmount, addressName, @.from/@.to and signed constants.
    # Asset facts come only from the firmware token table; an address is always
    # shown in full; the signer's message sits beside the value.
    USDC = bytes.fromhex("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
    NATIVE = bytes.fromhex("ee" * 20)

    def _field_screens(self, descriptor, signature, arguments):
        program = erc7730_compiler.compile_calldata(
            descriptor, signature, 1, ADDRESS)
        envelope = self._preload(program)
        start = self._audit_start(program, 4 + len(arguments))
        result, _, _, _ = self._walk(start, envelope, arguments=arguments)
        self.assertIsInstance(result, eth.EthereumTxRequest)
        self.assertTrue(result.HasField("signature_r"))
        # A body that pages is one confirmation under several ButtonRequests,
        # each reporting the same text: count it once.
        fields = []
        for title, body in self.screens:
            if title == "Signer field" and (not fields or fields[-1] != body):
                fields.append(body)
        return fields

    @staticmethod
    def _word(value):
        if isinstance(value, bytes):
            return bytes(12) + value
        return value.to_bytes(32, "big")

    def _token_screen(self, token, amount, params=None):
        signature = "send(address token,uint256 amount)"
        fields = [{"path": "amount", "label": "Amount", "format": "tokenAmount",
                   "params": dict({"tokenPath": "token"}, **(params or {}))}]
        descriptor = {"display": {"formats": {signature: {
            "intent": "Send", "fields": fields}}}}
        return self._field_screens(descriptor, signature,
                                   self._word(token) + self._word(amount))

    def test_token_amount_uses_the_firmware_token_table(self):
        self.assertEqual(self._token_screen(self.USDC, 1500000),
                         ["Amount:\n1.5 USDC"])

    def test_token_named_by_calldata_wins_over_the_hosts_claim(self):
        # The transaction goes to ADDRESS and a host might call it USDC; the
        # calldata names another token, which the firmware table does not know.
        self.assertEqual(self._token_screen(OTHER_ADDRESS, 42), [
            "Amount:\n42\nunknown token\n0x" + OTHER_ADDRESS.hex()])

    def test_signer_label_cannot_name_an_unknown_token(self):
        signature = "send(uint256 amount)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Send", "fields": [{
                "path": "amount", "label": "USDC amount",
                "format": "tokenAmount",
                "params": {"token": "0x" + OTHER_ADDRESS.hex()}}]}}}}
        self.assertEqual(
            self._field_screens(descriptor, signature, self._word(42)),
            ["USDC amount:\n42\nunknown token\n0x" + OTHER_ADDRESS.hex()])

    def test_threshold_message_is_shown_beside_the_exact_amount(self):
        params = {"threshold": 1000000, "message": "Large amount"}
        self.assertEqual(self._token_screen(self.USDC, 1500000, params),
                         ["Amount:\nLarge amount\n1.5 USDC"])
        self.assertEqual(self._token_screen(self.USDC, 999999, params),
                         ["Amount:\n0.999999 USDC"])

    def test_native_alias_shows_the_chains_native_asset(self):
        params = {"nativeCurrencyAddress": ["0x" + self.NATIVE.hex()]}
        self.assertEqual(
            self._token_screen(self.NATIVE, 1500000000000000000, params),
            ["Amount:\n1.5 ETH"])
        # An address outside the alias set is not the native asset.
        self.assertEqual(
            self._token_screen(OTHER_ADDRESS, 1500000000000000000, params),
            ["Amount:\n1500000000000000000\nunknown token\n0x" +
             OTHER_ADDRESS.hex()])

    def test_address_name_marks_only_the_signing_account(self):
        signer = self.client.ethereum_get_address(PATH)
        if not isinstance(signer, bytes):
            signer = bytes.fromhex(signer[2:])
        signature = "pay(address recipient)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Pay", "fields": [{
                "path": "recipient", "label": "Recipient",
                "format": "addressName"}]}}}}
        from keepkeylib.signed_metadata import keccak256

        def checksummed(address):
            digest = keccak256(address.hex().encode("ascii")).hex()
            return "0x" + "".join(
                c.upper() if c.isalpha() and int(digest[i], 16) >= 8 else c
                for i, c in enumerate(address.hex()))

        self.assertEqual(
            self._field_screens(descriptor, signature, self._word(signer)),
            ["Recipient:\n" + checksummed(signer) + "\n(this wallet)"])
        near = bytes(signer[:19]) + bytes([signer[19] ^ 1])
        self.assertEqual(
            self._field_screens(descriptor, signature, self._word(near)),
            ["Recipient:\n" + checksummed(near)])

    def test_containers_and_signed_constants(self):
        signature = "audit(uint256 first,uint256 second)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Audit action", "fields": [
                {"path": "@.to", "label": "Contract", "format": "addressName"},
                {"value": "Audit protocol", "label": "Protocol"}]}}}}
        self.assertEqual(
            self._field_screens(descriptor, signature,
                                self._word(42) + self._word(7)),
            ["Contract:\n0x" + ADDRESS.hex(), "Protocol:\nAudit protocol"])

    # Phase B: the interpolated intent is shown as numbered parts after the
    # plain intent. Each value part is formatted exactly as its field is.
    def test_interpolated_intent_parts_show_the_same_values_as_fields(self):
        signature = "send(address token,uint256 amount)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Send tokens",
            "interpolatedIntent": "Send {amount} now",
            "fields": [{"path": "amount", "label": "Amount",
                        "format": "tokenAmount",
                        "params": {"tokenPath": "token"}}]}}}}
        program = erc7730_compiler.compile_calldata(
            descriptor, signature, 1, ADDRESS)
        envelope = self._preload(program)
        arguments = self._word(self.USDC) + self._word(1500000)
        result, _, _, _ = self._walk(self._audit_start(program, 68), envelope,
                                     arguments=arguments)
        self.assertIsInstance(result, eth.EthereumTxRequest)
        self.assertTrue(result.HasField("signature_r"))
        shown = []
        for screen in self.screens:
            if screen[0] in ("Contract action", "Intent 1/3", "Intent 2/3",
                             "Intent 3/3", "Signer field") and (
                                 not shown or shown[-1] != screen):
                shown.append(screen)
        self.assertEqual(shown, [
            ("Contract action", "Send tokens"),
            ("Intent 1/3", "Send"),
            ("Intent 2/3", "1.5 USDC"),
            ("Intent 3/3", "now"),
            ("Signer field", "Amount:\n1.5 USDC"),
        ])

    # Phase C: amount, date, duration, unit, enum and nftName. Signer-supplied
    # units and enum labels appear beside the raw value, never instead.
    def _one_field(self, field, arguments, signature="act(uint256 a,address b)",
                   metadata=None):
        descriptor = {"display": {"formats": {signature: {
            "intent": "Act", "fields": [field]}}}}
        if metadata:
            descriptor["metadata"] = metadata
        return self._field_screens(descriptor, signature, arguments)

    def test_phase_c_formatters_show_exact_text(self):
        pad = self._word(OTHER_ADDRESS)
        cases = [
            ({"path": "a", "label": "Value", "format": "amount"},
             1500000000000000000, "Value:\n1.5 ETH"),
            ({"path": "a", "label": "When", "format": "date",
              "params": {"encoding": "timestamp"}},
             1700000000, "When:\n2023-11-14 22:13:20 UTC\n(1700000000)"),
            ({"path": "a", "label": "At", "format": "date",
              "params": {"encoding": "blockheight"}},
             19000000, "At:\nBlock 19000000"),
            ({"path": "a", "label": "Lock", "format": "duration"},
             93784, "Lock:\n1d 2h 3m 4s\n(93784 s)"),
            ({"path": "a", "label": "Weight", "format": "unit",
              "params": {"base": "kg", "decimals": 3}},
             93784, "Weight:\n93.784 kg\n(93784)"),
        ]
        for field, value, expected in cases:
            self.assertEqual(
                (field["format"],
                 self._one_field(field, self._word(value) + pad)),
                (field["format"], [expected]))

    def test_enum_labels_are_the_signers_claim_beside_the_value(self):
        field = {"path": "a", "label": "Side", "format": "enum",
                 "params": {"$ref": "$.metadata.enums.side"}}
        metadata = {"enums": {"side": {"0": "Buy", "1": "Sell"}}}
        pad = self._word(OTHER_ADDRESS)
        self.assertEqual(self._one_field(field, self._word(1) + pad,
                                         metadata=metadata),
                         ["Side:\nSell (1)"])
        self.assertEqual(self._one_field(field, self._word(5) + pad,
                                         metadata=metadata),
                         ["Side:\n5 (unmapped)"])

    def test_nft_shows_the_collection_address(self):
        field = {"path": "a", "label": "Item", "format": "nftName",
                 "params": {"collectionPath": "b"}}
        self.assertEqual(
            self._one_field(field, self._word(42) + self._word(self.USDC)),
            ["Item:\nToken ID 42\nCollection\n"
             "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"])
