"""P02 wire regressions; run with the pinned python-keepkey tests on PYTHONPATH."""
import common
from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as types


class TestP02Transport(common.KeepKeyTest):
    def assert_terminal_rejection(self, request, expected_prompt, wrong_reply):
        self.setup_mnemonic_pin_passphrase()
        self.client.clear_session()
        response = self.client.call_raw(request)
        self.assertIsInstance(response, expected_prompt)
        response = self.client.call_raw(wrong_reply)
        self.assertIsInstance(response, proto.Failure)
        self.assertEqual(response.code, types.Failure_UnexpectedMessage)
        # An unwinding handler must not enqueue another Failure or Success.
        response = self.client.call_raw(proto.Initialize())
        self.assertIsInstance(response, proto.Features)

    def test_pin_wait_rejects_button_ack(self):
        self.assert_terminal_rejection(
            proto.Ping(pin_protection=True), proto.PinMatrixRequest,
            proto.ButtonAck())

    def test_passphrase_wait_rejects_button_ack(self):
        self.assert_terminal_rejection(
            proto.Ping(passphrase_protection=True), proto.PassphraseRequest,
            proto.ButtonAck())

    def test_button_wait_rejects_passphrase_ack(self):
        self.assert_terminal_rejection(
            proto.Ping(button_protection=True), proto.ButtonRequest,
            proto.PassphraseAck(passphrase='must-not-be-cached'))

    def test_button_wait_rejects_normal_request(self):
        self.assert_terminal_rejection(
            proto.Ping(button_protection=True), proto.ButtonRequest,
            proto.GetFeatures())

    def test_short_packet_terminates_button_wait(self):
        response = self.client.call_raw(proto.Ping(button_protection=True))
        self.assertIsInstance(response, proto.ButtonRequest)
        self.client.transport.socket.send(b'?##' + b'\x00' * 9)
        response = self.client.transport.read_blocking()
        self.assertIsInstance(response, proto.Failure)
        self.assertEqual(response.code, types.Failure_UnexpectedMessage)
        response = self.client.call_raw(proto.Initialize())
        self.assertIsInstance(response, proto.Features)
