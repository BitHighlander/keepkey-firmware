import common
from keepkeylib.client import CallException
from keepkeylib import types_pb2 as types

PATH = [0x8000002c, 0x8000003c, 0x80000000, 0, 0]
ROUTER = bytes.fromhex('7a250d5630b4cf539739df2c5dacb4c659f2488d')
DAI = bytes.fromhex('6b175474e89094c44da98b954eedeac495271d0f')
PAIR = bytes.fromhex('a478c2975ab1ea89e8196811f51a7b7ade33eb11')
def word(n): return n.to_bytes(32, 'big')
def addr(a): return bytes(12) + a

class TestLiquidityConsent(common.KeepKeyTest):
    def setUp(self):
        super().setUp()
        self.setup_mnemonic_allallall()
        self.recipient = self.client.ethereum_get_address(PATH)
        self.seen = 0
        self.reject_at = None
        original = self.client.callback_ButtonRequest
        def callback(msg):
            self.seen += 1
            self.client.button = self.seen != self.reject_at
            return original(msg)
        self.client.callback_ButtonRequest = callback

    def sign(self, kind):
        if kind == 'approve':
            data = bytes.fromhex('095ea7b3') + addr(ROUTER) + word(10**18)
            to, value = PAIR, 0
        else:
            selector = 'f305d719' if kind == 'add' else '02751cec'
            data = bytes.fromhex(selector) + addr(DAI) + word(10**18) + word(10**17) + word(10**15) + addr(self.recipient) + word(2000000000)
            to, value = ROUTER, 10**16 if kind == 'add' else 0
        return self.client.ethereum_sign_tx(n=PATH, nonce=1, gas_price=10**9, gas_limit=300000, value=value, to=to, chain_id=1, data=data)

    def test_valid_add_remove_and_finite_lp_approval_without_advanced_mode(self):
        for kind, screens in [('add', 7), ('remove', 6), ('approve', 3)]:
            with self.subTest(kind=kind):
                self.seen = 0
                v, r, s = self.sign(kind)
                self.assertIn(v, (37, 38))
                self.assertEqual(len(r), 32)
                self.assertEqual(len(s), 32)
                self.assertEqual(self.seen, screens)

    def test_cancel_each_specialized_screen_then_retry(self):
        for kind, screens in [('add', 7), ('remove', 6), ('approve', 3)]:
            for screen in range(1, screens + 1):
                with self.subTest(kind=kind, screen=screen):
                    self.seen = 0
                    self.reject_at = screen
                    with self.assertRaises(CallException) as caught:
                        self.sign(kind)
                    self.assertEqual(caught.exception.args[0], types.Failure_ActionCancelled)
                    self.assertEqual(self.seen, screen)
                    self.reject_at = None
                    self.seen = 0
                    v, r, s = self.sign(kind)
                    self.assertIn(v, (37, 38))
                    self.assertEqual(self.seen, screens)
