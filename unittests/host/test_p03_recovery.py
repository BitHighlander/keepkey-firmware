"""Block 3 wire checks for on-device BIP-85 disclosure."""

import common
from keepkeylib import messages_pb2 as proto


class TestP03Recovery(common.KeepKeyTest):
    def test_omitted_wordlist_flag_still_rejects_non_bip39_word(self):
        # The wire flag is ignored: a host that omits enforce_wordlist (the
        # proto default, false) must not be able to store a non-BIP-39 seed.
        response = self.client.call_raw(proto.RecoveryDevice(
            word_count=12, pin_protection=False,
            passphrase_protection=False, use_character_cipher=True))
        self.assertIsInstance(response, proto.ButtonRequest)
        self.client.debug.press_yes()
        response = self.client.call_raw(proto.ButtonAck())
        for letter in 'zzzz':
            self.assertIsInstance(response, proto.CharacterRequest)
            cipher = self.client.debug.read_recovery_cipher()
            response = self.client.call_raw(proto.CharacterAck(
                character=cipher[ord(letter) - ord('a')]))
        response = self.client.call_raw(proto.CharacterAck(character=' '))
        self.assertIsInstance(response, proto.Failure)
        self.assertIn('Word not found', response.message)
        self.client.init_device()
        self.assertFalse(self.client.features.initialized)

    def test_enforced_wordlist_rejects_non_bip39_word(self):
        response = self.client.call_raw(proto.RecoveryDevice(
            word_count=12, pin_protection=False,
            passphrase_protection=False, enforce_wordlist=True,
            use_character_cipher=True))
        self.assertIsInstance(response, proto.ButtonRequest)
        self.client.debug.press_yes()
        response = self.client.call_raw(proto.ButtonAck())
        for letter in 'zzzz':
            self.assertIsInstance(response, proto.CharacterRequest)
            cipher = self.client.debug.read_recovery_cipher()
            response = self.client.call_raw(proto.CharacterAck(
                character=cipher[ord(letter) - ord('a')]))
        response = self.client.call_raw(proto.CharacterAck(character=' '))
        self.assertIsInstance(response, proto.Failure)
        self.assertIn('Word not found', response.message)

    def _start_recovery(self, dry_run):
        response = self.client.call_raw(proto.RecoveryDevice(
            word_count=12, pin_protection=False,
            passphrase_protection=False, enforce_wordlist=True,
            dry_run=dry_run, use_character_cipher=True))
        self.assertIsInstance(response, proto.ButtonRequest)
        self.client.debug.press_yes()
        return self.client.call_raw(proto.ButtonAck())

    def _enter_words(self, response, words):
        # Types the first four letters of each word through the cipher, as the
        # host does, and finishes with done. Returns early on a Failure.
        for index, word in enumerate(words):
            for letter in word[:4]:
                self.assertIsInstance(response, proto.CharacterRequest)
                cipher = self.client.debug.read_recovery_cipher()
                response = self.client.call_raw(proto.CharacterAck(
                    character=cipher[ord(letter) - ord('a')]))
            if index + 1 < len(words):
                response = self.client.call_raw(proto.CharacterAck(character=' '))
                if isinstance(response, proto.Failure):
                    return response
        self.assertIsInstance(response, proto.CharacterRequest)
        return self.client.call_raw(proto.CharacterAck(done=True))

    def test_non_word_failure_names_the_word(self):
        response = self._enter_words(
            self._start_recovery(dry_run=False),
            ['abandon', 'zzzz'] + ['abandon'] * 10)
        self.assertIsInstance(response, proto.Failure)
        self.assertIn('Word not found', response.message)
        self.assertIn('(word 2)', response.message)

    def test_non_word_last_word_is_named_not_blamed_on_cipher(self):
        # The last word ends with done, not a space, so it skips the per-word
        # check and is caught at finalize.
        response = self._enter_words(
            self._start_recovery(dry_run=False), ['abandon'] * 11 + ['zzzz'])
        self.assertIsInstance(response, proto.Failure)
        self.assertIn('Word not found', response.message)
        self.assertIn('(word 12)', response.message)
        self.client.init_device()
        self.assertFalse(self.client.features.initialized)

    def test_recovery_checksum_failure_is_named(self):
        # Twelve real words whose checksum is wrong.
        response = self._enter_words(
            self._start_recovery(dry_run=False), ['stick'] * 12)
        self.assertIsInstance(response, proto.Failure)
        self.assertIn('Invalid mnemonic', response.message)
        self.assertIn('checksum failed', response.message)
        self.client.init_device()
        self.assertFalse(self.client.features.initialized)

    def test_dry_run_checksum_failure_is_named(self):
        self.setup_mnemonic_nopin_nopassphrase()
        response = self._enter_words(
            self._start_recovery(dry_run=True), ['stick'] * 12)
        self.assertIsInstance(response, proto.ButtonRequest)
        self.client.debug.press_yes()
        response = self.client.call_raw(proto.ButtonAck())
        self.assertIsInstance(response, proto.Failure)
        self.assertIn('checksum failed', response.message)
        self.assertIn('does not match', response.message)

    def test_dry_run_valid_other_wallet_is_not_a_checksum_failure(self):
        self.setup_mnemonic_nopin_nopassphrase()
        response = self._enter_words(
            self._start_recovery(dry_run=True), ['all'] * 12)
        self.assertIsInstance(response, proto.ButtonRequest)
        self.client.debug.press_yes()
        response = self.client.call_raw(proto.ButtonAck())
        self.assertIsInstance(response, proto.Failure)
        self.assertIn('valid, but does not match', response.message)
        self.assertNotIn('checksum', response.message)

    def test_bip85_18_word_flow_completes(self):
        self.setup_mnemonic_allallall()
        response = self.client.call(proto.GetBip85Mnemonic(word_count=18, index=0))
        self.assertIsInstance(response, proto.Success)

    def test_bip85_24_word_and_second_index_flows_complete(self):
        self.setup_mnemonic_allallall()
        for words, index in ((24, 0), (12, 1)):
            response = self.client.call(
                proto.GetBip85Mnemonic(word_count=words, index=index))
            self.assertIsInstance(response, proto.Success)

    def test_bip85_invalid_parameters_fail_before_private_display(self):
        self.setup_mnemonic_allallall()
        for words, index in ((15, 0), (12, 0x80000000)):
            response = self.client.call_raw(
                proto.GetBip85Mnemonic(word_count=words, index=index))
            self.assertIsInstance(response, proto.Failure)
            state = self.client.debug._call(proto.DebugLinkGetState())
            self.assertTrue(state.HasField('layout'))

    def test_bip85_child_words_stay_off_debuglink_through_completion(self):
        self.setup_mnemonic_allallall()
        home_layout = self.client.debug._call(proto.DebugLinkGetState()).layout
        response = self.client.call_raw(
            proto.GetBip85Mnemonic(word_count=12, index=0))
        self.assertIsInstance(response, proto.ButtonRequest)
        self.client.debug.press_yes()
        response = self.client.call_raw(proto.ButtonAck())

        # This is the first child-word page, before its ButtonAck.
        self.assertIsInstance(response, proto.ButtonRequest)
        self.assertEqual(
            [], self.client.debug._call(proto.DebugLinkGetState()).ListFields())
        pages = 1
        while isinstance(response, proto.ButtonRequest):
            self.assertLess(pages, 10)
            self.client.debug.press_yes()
            response = self.client.call_raw(proto.ButtonAck())
            if isinstance(response, proto.ButtonRequest):
                pages += 1
                self.assertEqual(
                    [], self.client.debug._call(
                        proto.DebugLinkGetState()).ListFields())

        self.assertGreater(pages, 1)
        self.assertIsInstance(response, proto.Success)
        state = self.client.debug._call(proto.DebugLinkGetState())
        self.assertTrue(state.HasField('layout'))
        self.assertEqual(home_layout, state.layout)

    def test_bip85_cancel_clears_private_page_before_debug_resumes(self):
        self.setup_mnemonic_allallall()
        home_layout = self.client.debug._call(proto.DebugLinkGetState()).layout
        response = self.client.call_raw(
            proto.GetBip85Mnemonic(word_count=24, index=1))
        self.assertIsInstance(response, proto.ButtonRequest)
        self.client.debug.press_yes()
        response = self.client.call_raw(proto.ButtonAck())
        self.assertIsInstance(response, proto.ButtonRequest)
        self.assertEqual(
            [], self.client.debug._call(proto.DebugLinkGetState()).ListFields())

        self.client.debug.press_no()
        response = self.client.call_raw(proto.ButtonAck())
        self.assertIsInstance(response, proto.Failure)
        state = self.client.debug._call(proto.DebugLinkGetState())
        self.assertTrue(state.HasField('layout'))
        self.assertEqual(home_layout, state.layout)
