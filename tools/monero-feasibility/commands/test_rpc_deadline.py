#!/usr/bin/env python3
"""Transport deadline regressions without loading firmware or sleeping."""
import unittest
from unittest.mock import Mock, call

import test_wire as wire


def session(responses):
    value = wire.Session.__new__(wire.Session)
    value.capture = Mock()
    value.send = Mock()
    value.debug_state = Mock(return_value={3: [b"123456789"]})
    value.approve_button = Mock(return_value={"title": "Public review fixture"})
    responses = iter(responses)

    def receive(timeout):
        delay, response = next(responses)
        return response if delay <= timeout else None

    value.receive = Mock(side_effect=receive)
    return value


class RpcDeadlines(unittest.TestCase):
    def test_valid_plan_budget_covers_authentication_validation_and_approval(self):
        value = session([(0, (18, b"", 1)), (6, (26, b"", 1)),
                         (8, (65001, b"signed-public-fixture", 1))])
        result, events, screens = value.rpc(65000, b"public-plan", pin="1234",
                                            timeout=60, context="valid-plan")
        self.assertEqual(result[0], 65001)
        self.assertEqual(events, [18, 26, 65001])
        self.assertEqual(len(screens), 1)
        self.assertEqual(value.receive.call_args_list, [call(60), call(60), call(60)])
        value.send.assert_any_call(19, wire.fb(1, "1234"))
        value.approve_button.assert_called_once()

    def test_invalid_control_keeps_short_default_and_reports_scenario(self):
        value = session([(6, (3, b"", 1))])
        with self.assertRaisesRegex(RuntimeError,
                                    r"message 65000 \(deadline 5s; scenario malformed-plan\)"):
            value.rpc(65000, b"malformed", context="malformed-plan")
        value.receive.assert_called_once_with(5)
        value.approve_button.assert_not_called()

    def test_explicit_budget_remains_bounded_and_identifies_valid_plan(self):
        value = session([(61, (26, b"", 1))])
        with self.assertRaisesRegex(RuntimeError,
                                    r"message 65000 \(deadline 60s; scenario initialize-review-open\)"):
            value.rpc(65000, b"public-plan", approve=None, timeout=60,
                      context="initialize-review-open")
        value.receive.assert_called_once_with(60)

    def test_other_messages_keep_the_short_default(self):
        value = session([(0, (17, b"public-features", 1))])
        result, _, _ = value.rpc(55)
        self.assertEqual(result[0], 17)
        value.receive.assert_called_once_with(5)


if __name__ == "__main__":
    unittest.main()
