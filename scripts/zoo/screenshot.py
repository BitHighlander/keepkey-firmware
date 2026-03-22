"""
screenshot.py — Capture and decode KeepKey emulator OLED screenshots.

The DebugLinkGetState response contains a 2048-byte `layout` field
packed as 1 bit per pixel (256 wide x 64 tall). Each byte holds 8
vertical pixels, LSB = topmost row within that byte.

Byte index: x + (y // 8) * 256
Bit within byte: y % 8
"""
import os
from PIL import Image


OLED_W = 256
OLED_H = 64
LAYOUT_SIZE = OLED_W * OLED_H // 8  # 2048 bytes


def decode_layout(layout_bytes):
    """Decode 2048-byte bitfield into a 256x64 PIL Image."""
    im = Image.new("RGB", (OLED_W, OLED_H), (0, 0, 0))
    pix = im.load()

    for x in range(OLED_W):
        for y in range(OLED_H):
            byte_idx = x + (y // 8) * OLED_W
            if byte_idx < len(layout_bytes):
                if (layout_bytes[byte_idx] >> (y % 8)) & 1:
                    pix[x, y] = (255, 255, 255)

    return im


def capture_screenshot(debug_client, filename):
    """Capture current OLED state via DebugLink and save as PNG.

    Args:
        debug_client: DebugLink instance (has read_state() or _call())
        filename: Output PNG path
    """
    from keepkeylib import messages_pb2 as proto

    state = debug_client._call(proto.DebugLinkGetState())

    if not state.HasField('layout') or len(state.layout) < LAYOUT_SIZE:
        print(f"  WARNING: layout field empty or too small ({len(state.layout) if state.HasField('layout') else 0} bytes)")
        return False

    im = decode_layout(state.layout)

    os.makedirs(os.path.dirname(filename) or '.', exist_ok=True)
    im.save(filename)
    return True
