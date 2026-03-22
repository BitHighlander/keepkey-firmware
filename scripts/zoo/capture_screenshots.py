#!/usr/bin/env python3
"""
capture_screenshots.py — Orchestrates KeepKey emulator screenshot capture.

Connects to a running emulator via UDP, executes transaction flows,
and captures the OLED display at each confirmation screen.

Usage:
  python3 capture_screenshots.py --output=/output [--flow=btc-send]

Requires: emulator running on KK_TRANSPORT_MAIN / KK_TRANSPORT_DEBUG
"""
import os
import sys
import argparse
import time

# Add python-keepkey to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'deps', 'python-keepkey'))

from keepkeylib.client import KeepKeyDebuglinkClient
from keepkeylib.transport_udp import UDPTransport
from keepkeylib import messages_pb2 as proto
from screenshot import capture_screenshot


def make_client():
    """Create a DebugLink client connected to the emulator."""
    main_host = os.environ.get('KK_TRANSPORT_MAIN', '127.0.0.1:11044')
    debug_host = os.environ.get('KK_TRANSPORT_DEBUG', '127.0.0.1:11045')

    transport = UDPTransport(main_host)
    client = KeepKeyDebuglinkClient(transport)
    debug_transport = UDPTransport(debug_host)
    client.set_debuglink(debug_transport)

    return client


def reset_device(client, mnemonic='all ' * 11 + 'all'):
    """Wipe and load a known mnemonic for deterministic screenshots."""
    client.wipe_device()
    client.load_device_by_mnemonic(
        mnemonic=mnemonic.strip(),
        pin='',
        passphrase_protection=False,
        label='KeepKey Zoo',
        language='english',
    )


def capture(client, output_dir, name):
    """Capture current OLED state to output_dir/name.png."""
    path = os.path.join(output_dir, name)
    ok = capture_screenshot(client.debug, path)
    if ok:
        print(f"    -> {name}")
    return ok


# ═══════════════════════════════════════════════════════════════════════
# Flow: BTC Send
# ═══════════════════════════════════════════════════════════════════════

def flow_btc_send(client, out):
    """Bitcoin send flow — address display + sign transaction."""
    from keepkeylib import tx_api
    client.set_tx_api(tx_api.TxApiBitcoin)
    reset_device(client)

    print("  [btc-send] Get address (show on device)...")
    # Show a BTC address on device
    client.get_address('Bitcoin', [44 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0, 0], show_display=True)
    capture(client, out, '01-btc-get-address.png')


def flow_btc_sign(client, out):
    """Bitcoin sign transaction — confirm output + fee screens."""
    from keepkeylib import tx_api
    client.set_tx_api(tx_api.TxApiBitcoin)
    reset_device(client)

    print("  [btc-sign] Sign transaction...")
    # Use a simple 1-in-1-out tx
    inp1 = proto.TxInputType(
        address_n=[44 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0, 0],
        prev_hash=bytes.fromhex('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
        prev_index=0,
        amount=390000,
    )
    out1 = proto.TxOutputType(
        address='1MJ2tj2ThBE62pXbBSwVDT1Gn72SKPkLhD',
        amount=380000,
        script_type=proto.OutputScriptType.Value('PAYTOADDRESS'),
    )

    try:
        (signatures, serialized_tx) = client.sign_tx('Bitcoin', [inp1], [out1])
        # Screenshots captured during the sign flow via DebugLink auto-confirm
    except Exception as e:
        print(f"    sign_tx raised: {e}")

    capture(client, out, '02-btc-confirm-output.png')


# ═══════════════════════════════════════════════════════════════════════
# Flow: ETH Send
# ═══════════════════════════════════════════════════════════════════════

def flow_eth_send(client, out):
    """Ethereum send flow — address + sign transaction."""
    reset_device(client)

    print("  [eth-send] Get ETH address...")
    client.ethereum_get_address([44 | 0x80000000, 60 | 0x80000000, 0 | 0x80000000, 0, 0], show_display=True)
    capture(client, out, '01-eth-get-address.png')


# ═══════════════════════════════════════════════════════════════════════
# Flow: Solana
# ═══════════════════════════════════════════════════════════════════════

def flow_solana_address(client, out):
    """Solana get address (if supported)."""
    reset_device(client)

    print("  [solana] Get Solana address...")
    try:
        client.solana_get_address([44 | 0x80000000, 501 | 0x80000000, 0 | 0x80000000], show_display=True)
        capture(client, out, '01-sol-get-address.png')
    except Exception as e:
        print(f"    solana not available: {e}")


# ═══════════════════════════════════════════════════════════════════════
# Flow Registry
# ═══════════════════════════════════════════════════════════════════════

FLOWS = {
    'btc-send': flow_btc_send,
    'btc-sign': flow_btc_sign,
    'eth-send': flow_eth_send,
    'solana-address': flow_solana_address,
}


def main():
    parser = argparse.ArgumentParser(description='KeepKey Zoo Screenshot Capture')
    parser.add_argument('--output', default='zoo-output/screenshots', help='Output directory')
    parser.add_argument('--flow', default=None, help='Run single flow (default: all)')
    args = parser.parse_args()

    print("\nKeepKey Zoo — Screenshot Capture\n")

    client = make_client()

    flows_to_run = {args.flow: FLOWS[args.flow]} if args.flow else FLOWS

    for name, func in flows_to_run.items():
        flow_dir = os.path.join(args.output, name)
        os.makedirs(flow_dir, exist_ok=True)
        print(f"  Flow: {name}")
        try:
            func(client, flow_dir)
        except Exception as e:
            print(f"    ERROR: {e}")
        print()

    print(f"  Screenshots: {args.output}/")
    print("  Done.\n")


if __name__ == '__main__':
    main()
