#!/usr/bin/env python3
"""Pure host review targeting regressions; no native emulator or sockets."""
import unittest

from host_emulator import rejection_target


class ReviewTargetTests(unittest.TestCase):
    def test_fee_targets_the_paginated_page_showing_the_exact_fee(self):
        fee = 1808400000
        self.assertFalse(rejection_target({
            "title": "Monero transaction 1/2",
            "body": "Mainnet\nm/44'/128'/0'\n1 inputs, 2 outputs\n",
        }, "fee", fee))
        fee_page = {"title": "Monero transaction 2/2", "body": "Fee 0.001808400000 XMR"}
        self.assertTrue(rejection_target(fee_page, "fee", fee))
        self.assertFalse(rejection_target(fee_page, "fee", fee + 1))
        self.assertFalse(rejection_target({
            "title": "Sign Monero tx", "body": fee_page["body"],
        }, "fee", fee))

    def test_output_targets_first_output_details(self):
        self.assertTrue(rejection_target({
            "title": "Output details 1/2",
            "body": "Monero Mainnet\nOutput 1/2: Change\nAmount 10.998191600000 XMR\n",
        }, "output", 1808400000))
        self.assertFalse(rejection_target({
            "title": "Output details", "body": "Output 2/2: Recipient\nAmount 1.000000000000 XMR",
        }, "output", 1808400000))

    def test_final_targets_the_final_confirmation(self):
        self.assertTrue(rejection_target({
            "title": "Sign Monero tx", "body": "All 2 outputs reviewed.\nFee 0.001808400000 XMR\nSign this transaction?",
        }, "final", 1808400000))
        self.assertFalse(rejection_target({
            "title": "Monero transaction 2/2", "body": "Fee 0.001808400000 XMR",
        }, "final", 1808400000))


if __name__ == "__main__":
    unittest.main()
