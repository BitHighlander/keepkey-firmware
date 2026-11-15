#!/usr/bin/env python3
"""Device-signed Monero transactions on a private regtest chain.

Starts its own offline `monerod --regtest`, three stock wallet RPCs (a
faucet, a watch-only wallet of the emulator, the recipient) and a KeepKey
emulator on a private UDP port. The emulator's wallet is funded, the stock
watch-only wallet builds each unsigned transfer, the emulator signs it
through keepkeylib.monero_stream, and the private daemon must accept it,
mine it and credit the recipient:

  1. to a standard address
  2. to a subaddress, spending the change of 1 and two more outputs
  3. to an integrated address, spending the change of 2
  4. spending a block reward mined to the emulator's address
  5. from account 1 (three inputs on three subaddresses; the change returns
     to subaddress (1, 0))

Nothing leaves 127.0.0.1; the chain is a fresh fakechain; no USB device is
opened. The wallets are the published test mnemonics (the emulator:
"abandon ... about"; the recipient: "alcohol woman ...").

    pyk-venv/bin/python tools/monero-e2e/regtest_e2e.py \\
        --bin-dir <monerod and monero-wallet-rpc v0.18.5.4> \\
        --kkemu <build>/bin/kkemu --adapter <monero-plan-adapter> \\
        --output <empty directory> [--fixtures plans.json]
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request

HERE = Path(__file__).resolve().parent
PYK = HERE.parent.parent / 'deps' / 'python-keepkey'
sys.path[:0] = [str(PYK), str(PYK / 'tests')]
os.environ['KK_FORCE_UDP'] = '1'    # never a USB device

from keepkeylib import monero_stream                       # noqa: E402
from keepkeylib import messages_monero_pb2 as monero_proto  # noqa: E402
from keepkeylib.client import CallException                # noqa: E402
from keepkeylib.client import KeepKeyDebuglinkClient       # noqa: E402
from keepkeylib.transport_udp import UDPTransport          # noqa: E402
import monero_fixtures as xmr                              # noqa: E402

XMR = 10 ** 12
MNEMONIC = ' '.join(['abandon'] * 11) + ' about'
RECIPIENT = ('alcohol', 0)          # monero_fixtures: address and view key
PAYMENT_ID = '0123456789abcdef'
# The published reference vectors of both test wallets. From them only the
# emulator wallet's spend secret is used, to record each input's one-time
# secret in the fixtures: with it the daemon-less tests can hand their
# transactions to Monero Core.
REFERENCE = HERE.parent / 'monero-feasibility' / 'evidence' / \
    '2026-11-04-interoperability' / 'host.json'


class Rpc:
    def __init__(self, name, port):
        self.name, self.url = name, 'http://127.0.0.1:%d' % port
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}))

    def post(self, path, params, timeout=180):
        request = urllib.request.Request(
            self.url + path, json.dumps(params).encode(),
            {'Content-Type': 'application/json'})
        with self.opener.open(request, timeout=timeout) as response:
            return json.loads(response.read())

    def call(self, method, params=None, timeout=180):
        reply = self.post('/json_rpc', {'jsonrpc': '2.0', 'id': '0',
                                        'method': method,
                                        'params': params or {}}, timeout)
        if 'error' in reply:
            raise RuntimeError('%s.%s: %s' % (self.name, method,
                                              reply['error']))
        return reply['result']


def free_ports(count):
    sockets = [socket.socket() for _ in range(count)]
    try:
        for s in sockets:
            s.bind(('127.0.0.1', 0))
        return [s.getsockname()[1] for s in sockets]
    finally:
        for s in sockets:
            s.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--bin-dir', type=Path, required=True)
    parser.add_argument('--kkemu', type=Path, required=True)
    parser.add_argument('--adapter', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--udp-port', type=int, default=22100)
    parser.add_argument('--fixtures', type=Path,
                        help='write the signed plans as test fixtures')
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        parser.error('the output directory must be empty')

    processes, checks, report = [], [], {'transactions': []}
    report['sha256'] = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (args.bin_dir / 'monerod',
                     args.bin_dir / 'monero-wallet-rpc', args.kkemu,
                     args.adapter)}

    def start(name, command, cwd=out, env=None):
        log = open(out / (name + '.process.log'), 'w')
        processes.append(subprocess.Popen(
            [str(c) for c in command], cwd=cwd, env=env,
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT))
        return processes[-1]

    def ready(rpc, method, process):
        for _ in range(600):
            if process.poll() is not None:
                raise RuntimeError(rpc.name + ' stopped during startup')
            try:
                return rpc.call(method, timeout=2)
            except (OSError, ValueError, RuntimeError):
                time.sleep(.1)
        raise RuntimeError(rpc.name + ' did not start')

    def check(name, ok, **detail):
        checks.append({'check': name, 'ok': bool(ok), **detail})
        print('  %s %s' % ('ok  ' if ok else 'FAIL', name), flush=True)
        if not ok:
            raise RuntimeError('check failed: %s %s' % (name, detail))

    try:
        # ---- the private chain and the stock wallets ----
        ports = dict(zip(['daemon', 'p2p', 'faucet', 'watch', 'recipient'],
                         free_ports(5)))
        daemon = Rpc('daemon', ports['daemon'])
        (out / 'daemon-data').mkdir()
        process = start('daemon', [
            args.bin_dir / 'monerod', '--regtest', '--offline',
            '--fixed-difficulty', '1', '--data-dir', out / 'daemon-data',
            '--p2p-bind-ip', '127.0.0.1', '--p2p-bind-port', ports['p2p'],
            '--rpc-bind-ip', '127.0.0.1', '--rpc-bind-port', ports['daemon'],
            '--rpc-ssl', 'disabled', '--no-zmq', '--non-interactive',
            '--no-igd', '--disable-dns-checkpoints', '--check-updates',
            'disabled', '--log-level', '0', '--log-file', out / 'daemon.log'])
        info = ready(daemon, 'get_info', process)
        check('fresh private fakechain',
              info['height'] == 1 and info['nettype'] == 'fakechain',
              height=info['height'], nettype=info['nettype'])
        report['daemon_version'] = info.get('version')
        wallets = {}
        for name in ('faucet', 'watch', 'recipient'):
            (out / (name + '-wallet')).mkdir()
            process = start(name, [
                args.bin_dir / 'monero-wallet-rpc',
                '--wallet-dir', out / (name + '-wallet'),
                '--rpc-bind-ip', '127.0.0.1', '--rpc-bind-port', ports[name],
                '--disable-rpc-login', '--rpc-ssl', 'disabled',
                '--daemon-ssl', 'disabled', '--trusted-daemon',
                '--allow-mismatched-daemon-version', '--daemon-address',
                '127.0.0.1:%d' % ports['daemon'], '--log-level', '0',
                '--shared-ringdb-dir', out / (name + '-ringdb'),
                '--log-file', out / (name + '.log')])
            wallets[name] = Rpc(name, ports[name])
            ready(wallets[name], 'get_version', process)
        faucet, watch, recipient = (wallets[n] for n in
                                    ('faucet', 'watch', 'recipient'))
        faucet.call('create_wallet', {'filename': 'faucet', 'password': '',
                                      'language': 'English'})
        faucet_address = faucet.call('get_address',
                                     {'account_index': 0})['address']

        def mine(blocks):
            daemon.call('generateblocks', {'wallet_address': faucet_address,
                                           'amount_of_blocks': blocks})

        def balance(wallet, account=0):
            wallet.call('refresh', {'start_height': 0})
            return wallet.call('get_balance', {'account_index': account})

        # The recipient is view-only too: it only has to see what it gets.
        recipient_address = xmr.ADDRESSES[RECIPIENT][(0, 0)]
        recipient.call('generate_from_keys', {
            'filename': 'recipient', 'address': recipient_address,
            'viewkey': xmr.VIEW_KEYS[RECIPIENT], 'spendkey': '',
            'password': '', 'language': 'English', 'restore_height': 0})
        recipient_sub = xmr.ADDRESSES[RECIPIENT][(0, 1)]
        integrated = recipient.call(
            'make_integrated_address',
            {'payment_id': PAYMENT_ID})['integrated_address']

        # ---- the emulator ----
        (out / 'emu').mkdir()
        start('kkemu', [args.kkemu], cwd=out / 'emu',
              env=dict(os.environ, KEEPKEY_UDP_PORT=str(args.udp_port)))
        time.sleep(2)
        client = KeepKeyDebuglinkClient(
            UDPTransport('127.0.0.1:%d' % args.udp_port))
        client.set_debuglink(UDPTransport('127.0.0.1:%d' %
                                          (args.udp_port + 1)))
        client.wipe_device()
        client.load_device_by_mnemonic(
            mnemonic=MNEMONIC, pin='', passphrase_protection=False,
            label='regtest', language='english')
        features = client.features
        report['firmware'] = '%d.%d.%d' % (
            features.major_version, features.minor_version,
            features.patch_version)
        path = xmr.path(0)
        key = client.monero_get_watch_key(path)
        address = key.address.decode()
        view_key = key.watch_key.hex()
        own = {index: client.monero_get_address(
            path, account=index[0], minor=index[1]).decode()
            for index in [(0, 1), (0, 2), (1, 0), (1, 1), (1, 2)]}
        check('the emulator is the abandon wallet',
              address == xmr.ADDRESSES[('abandon', 0)][(0, 0)] and
              own[(0, 1)] == xmr.ADDRESSES[('abandon', 0)][(0, 1)] and
              own[(1, 0)] == xmr.ADDRESSES[('abandon', 0)][(1, 0)])
        watch.call('generate_from_keys', {
            'filename': 'watch', 'address': address, 'viewkey': view_key,
            'spendkey': '', 'password': '', 'language': 'English',
            'restore_height': 0})

        def adapter(op, outputs_hex, unsigned=None):
            request = {'op': op, 'address': address, 'view_key': view_key,
                       'outputs_data_hex': outputs_hex}
            if unsigned is not None:
                request['unsigned_txset'] = unsigned
            done = subprocess.run([str(args.adapter)],
                                  input=json.dumps(request).encode(),
                                  stdout=subprocess.PIPE, timeout=120)
            reply = json.loads(done.stdout)
            if reply.get('status') != 'pass':
                raise RuntimeError('plan adapter: %s' % reply.get('error'))
            return reply

        def sync_key_images():
            """Device key-image sync (1804-1809) into the watch wallet, so
            it knows which outputs are spent. Returns the output export."""
            exported = watch.call('export_outputs',
                                  {'all': True})['outputs_data_hex']
            owned = adapter('outputs', exported)['outputs']
            details, items = [], []
            for o in owned:
                additional = [bytes.fromhex(k)
                              for k in o['additional_tx_public_keys']]
                details.append(monero_proto.MoneroTransferDetails(
                    out_key=bytes.fromhex(o['out_key']),
                    tx_pub_key=bytes.fromhex(o['tx_public_key']),
                    additional_tx_pub_keys=additional,
                    internal_output_index=o['output_index'],
                    sub_addr_major=o['subaddress_major'],
                    sub_addr_minor=o['subaddress_minor']))
                items.append(xmr.keccak256(
                    bytes.fromhex(o['out_key'] + o['tx_public_key']) +
                    b''.join(additional) + xmr.varint(o['output_index'])))
            client.monero_key_image_export_init(
                num=len(owned), hash=xmr.keccak256(b''.join(items)),
                address_n=path, network_type=0)
            sealed = []
            for at in range(0, len(details), 4):
                sealed += client.monero_key_image_sync_step(
                    details[at:at + 4]).kis
            enc_key = client.monero_key_image_sync_final().enc_key
            proofs = []
            for item in sealed:
                plain = xmr.decrypt(enc_key, item.iv, item.blob)
                proofs.append({'key_image': plain[:32].hex(),
                               'signature': plain[32:].hex()})
            watch.call('import_key_images',
                       {'offset': 0, 'signed_key_images': proofs})
            return exported

        spend_secret = next(
            case['spend_secret']
            for case in json.loads(REFERENCE.read_text())['reference']['cases']
            if case['label'] == 'abandon-account0-sub0-0-output0')

        def input_secret(item):
            """x of an input's real output, from the published test keys."""
            a = int.from_bytes(bytes.fromhex(view_key), 'little')
            b = int.from_bytes(bytes.fromhex(spend_secret), 'little')
            want = item['ring'][item['real_index']]['public_key']
            keys = [item['tx_public_key']]
            if item['output_index'] < len(item['additional_tx_public_keys']):
                keys.append(
                    item['additional_tx_public_keys'][item['output_index']])
            major, minor = item['subaddress_major'], item['subaddress_minor']
            sub = 0
            if major or minor:
                sub = int.from_bytes(xmr.keccak256(
                    b'SubAddr\0' + bytes.fromhex(view_key) +
                    major.to_bytes(4, 'little') +
                    minor.to_bytes(4, 'little')), 'little')
            for tx_key in keys:
                derivation = xmr._encode(xmr._mul(
                    xmr._decode(bytes.fromhex(tx_key)), 8 * a))
                x = (int.from_bytes(xmr.keccak256(
                    derivation + xmr.varint(item['output_index'])), 'little')
                    + b + sub) % xmr.L
                if xmr._encode(xmr._mul(xmr.G, x)).hex() == want:
                    return x.to_bytes(32, 'little').hex()
            raise RuntimeError('input is not the test wallet\'s')

        # ---- funding. The first faucet transaction pays the primary address
        # and four subaddresses, so each output hangs on an additional
        # transaction key. The second pays one subaddress alone: its
        # transaction key is r*D and there are no additional keys. ----
        mine(100)
        check('faucet has mature block rewards',
              balance(faucet)['unlocked_balance'] > 20 * XMR)
        funding = faucet.call('transfer', {
            'destinations': [{'address': address, 'amount': 12 * XMR},
                             {'address': own[(0, 1)], 'amount': 3 * XMR},
                             {'address': own[(1, 0)], 'amount': 1 * XMR},
                             {'address': own[(1, 1)], 'amount': 1 * XMR},
                             {'address': own[(1, 2)], 'amount': 1 * XMR}],
            'ring_size': 16, 'priority': 1})
        funding_sub = faucet.call('transfer', {
            'destinations': [{'address': own[(0, 2)], 'amount': 2 * XMR}],
            'ring_size': 16, 'priority': 1})
        mine(11)
        expected_watch = {0: 17 * XMR, 1: 3 * XMR}
        check('emulator wallet funded: 17 XMR in account 0, 3 in account 1',
              all(balance(watch, account)['unlocked_balance'] == amount
                  for account, amount in expected_watch.items()))
        report['funding'] = [
            {'tx_hash': funding['tx_hash'],
             'amounts': [12 * XMR, 3 * XMR] + 3 * [XMR]},
            {'tx_hash': funding_sub['tx_hash'], 'amounts': [2 * XMR]}]

        received = 0
        cases = [('standard', 0, recipient_address, 1 * XMR),
                 # more than any two outputs: all three, the change included
                 ('subaddress', 0, recipient_sub, 31 * XMR // 2),
                 ('integrated', 0, integrated, XMR // 4),
                 # more than everything else: must spend the block reward
                 ('coinbase', 0, recipient_address, 20 * XMR),
                 # more than two of its outputs: three inputs
                 ('account1', 1, recipient_address, 5 * XMR // 2)]
        previous = None
        fixtures = []
        for name, account, destination, amount in cases:
            print('transaction: %s' % name, flush=True)
            if name == 'coinbase':
                # A block reward straight to the emulator's wallet, as a
                # miner is paid; spendable after 60 blocks.
                daemon.call('generateblocks', {'wallet_address': address,
                                               'amount_of_blocks': 1})
                mine(60)
                reward = balance(watch)['unlocked_balance'] - \
                    expected_watch[0]
                check('coinbase: a block reward was mined to the emulator',
                      reward > amount, reward=reward)
                expected_watch[0] += reward
                previous = [t['tx_hash'] for t in watch.call(
                    'incoming_transfers', {'transfer_type': 'available',
                                           'account_index': 0})['transfers']
                    if t['amount'] == reward][0]
            exported = sync_key_images()
            transfer = watch.call('transfer', {
                'destinations': [{'address': destination, 'amount': amount}],
                'account_index': account, 'ring_size': 16, 'priority': 1,
                'unlock_time': 0, 'do_not_relay': True})
            check(name + ': stock watch-only wallet built an unsigned '
                  'transfer', bool(transfer.get('unsigned_txset')))
            (out / (name + '.unsigned_txset.hex')).write_text(
                transfer['unsigned_txset'] + '\n')
            plan = adapter('plan', exported, transfer['unsigned_txset'])
            del plan['status']
            (out / (name + '.plan.json')).write_text(
                json.dumps(plan, indent=1) + '\n')
            check(name + ': plan fee is the wallet\'s',
                  plan['fee'] == transfer['fee'] and plan['fee'] > 0)

            # Which transaction each real input came from.
            owned = {t['pubkey']: t['tx_hash'] for t in watch.call(
                'incoming_transfers', {'transfer_type': 'all',
                                       'account_index': account})['transfers']}
            spends = [owned[i['ring'][i['real_index']]['public_key']]
                      for i in plan['inputs']]
            if previous and not account:
                check(name + (': spends the block reward' if name ==
                              'coinbase' else ': spends the change of the '
                              'previous device-signed transaction'),
                      previous in spends, inputs=len(spends))

            with xmr.Screens(client) as screens:
                signed = monero_stream.sign(client, path, plan)
            shown = [(title, ''.join(body.split()))
                     for title, body in screens.confirmations()]
            check(name + ': device showed the complete recipient address',
                  any(destination in body for title, body in shown
                      if title.startswith('Monero send')))
            (out / (name + '.tx.hex')).write_text(signed.blob.hex() + '\n')
            tx_hash = signed.tx_hash.hex()

            relay = daemon.post('/send_raw_transaction', {
                'tx_as_hex': signed.blob.hex(), 'do_not_relay': False})
            check(name + ': private daemon accepted the transaction',
                  relay.get('status') == 'OK' and not relay.get('reason'),
                  reply=relay)
            mine(11)
            mined = daemon.post('/get_transactions', {
                'txs_hashes': [tx_hash], 'decode_as_json': False})['txs']
            check(name + ': exact signed bytes mined',
                  len(mined) == 1 and not mined[0]['in_pool'] and
                  bytes.fromhex(mined[0]['as_hex']) == signed.blob,
                  block=mined[0].get('block_height'))
            spent = daemon.post('/is_key_image_spent', {
                'key_images': [k.hex() for k in signed.key_images]})
            check(name + ': input key images spent on chain',
                  spent['spent_status'] == [1] * len(signed.key_images))

            received += amount
            credited = balance(recipient)['balance']
            payment = recipient.call('get_transfer_by_txid',
                                     {'txid': tx_hash})['transfer']
            check(name + ': stock recipient wallet credited',
                  credited == received and
                  payment['amount'] == amount and payment['type'] == 'in' and
                  payment['address'] == (recipient_address if name ==
                                         'integrated' else destination),
                  amount=payment['amount'], address=payment['address'])
            if name == 'integrated':
                check('integrated: recipient decrypted the payment ID',
                      payment['payment_id'] == PAYMENT_ID)
            expected_watch[account] -= amount + plan['fee']
            sync_key_images()
            after = balance(watch, account)
            change = [t for t in watch.call('incoming_transfers', {
                'transfer_type': 'available',
                'account_index': account})['transfers']
                if t['tx_hash'] == tx_hash]
            check(name + ': watch wallet sees the change',
                  after['balance'] == expected_watch[account] and
                  [t['amount'] for t in change] == [plan['change']['amount']]
                  and change[0]['subaddr_index'] == {'major': account,
                                                     'minor': 0},
                  balance=after['balance'])

            report['transactions'].append({
                'name': name, 'account': account, 'tx_hash': tx_hash,
                'bytes': len(signed.blob),
                'block_height': mined[0]['block_height'],
                'inputs': len(plan['inputs']), 'fee': plan['fee'],
                'recipient': destination, 'amount': amount,
                'change': plan['change']['amount'],
                'key_images': [k.hex() for k in signed.key_images],
                'spends_outputs_of': spends, 'review': shown})
            fixtures.append({
                'name': name, 'plan': plan, 'recipient': destination,
                'amount': amount, 'regtest_tx_hash': tx_hash,
                'key_images': sorted(k.hex() for k in signed.key_images),
                'input_secrets': [input_secret(i) for i in plan['inputs']]})
            previous = tx_hash

        check('inputs on the primary address, on subaddresses of both '
              'accounts, with and without additional transaction keys',
              {(i['subaddress_major'], i['subaddress_minor'],
                bool(i['additional_tx_public_keys']))
               for f in fixtures for i in f['plan']['inputs']} ==
              {(0, 0, True), (0, 1, True), (0, 2, False), (0, 0, False),
               (1, 0, True), (1, 1, True), (1, 2, True)})

        # ---- send-max. The stock wallet's sweep leaves no change: the
        # second output is a 0-amount dummy to a random address. Firmware
        # 7.17 signs only with one change output back to the wallet, so it
        # must refuse this one cleanly: before any screen, with no session
        # left behind. ----
        print('send-max (sweep_all)', flush=True)
        exported = sync_key_images()
        sweep = watch.call('sweep_all', {
            'address': recipient_address, 'account_index': 1,
            'ring_size': 16, 'priority': 1, 'do_not_relay': True})
        plan = adapter('plan', exported, sweep['unsigned_txset'])
        refusal = None
        with xmr.Screens(client) as screens:
            try:
                monero_stream.sign(client, path, plan)
            except CallException as error:
                refusal = error.args[1]
        report['sweep'] = {
            'outputs': [o['amount'] for o in plan['outputs']],
            'change': plan['change']['amount'], 'refusal': refusal}
        check('sweep: refused at TxInit before any screen',
              refusal == 'Monero change must return to this wallet' and
              not screens.confirmations(), **report['sweep'])
        check('sweep: the device is idle and still answers',
              not daemon.post('/get_transaction_pool', {}).get(
                  'transactions') and
              client.monero_get_address(path).decode() == address)

        report['status'] = 'pass'
        if args.fixtures:
            args.fixtures.write_text(json.dumps(fixtures, indent=1) + '\n')
    except Exception as error:
        report['status'] = 'error'
        report['error'] = str(error)
        raise
    finally:
        for process in reversed(processes):
            process.terminate()
        for process in processes:
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
        report['checks'] = checks
        (out / 'result.json').write_text(json.dumps(report, indent=1) + '\n')
    print(json.dumps({'status': report['status'], 'checks': len(checks),
                      'transactions': [t['tx_hash']
                                       for t in report['transactions']]}))


if __name__ == '__main__':
    main()
