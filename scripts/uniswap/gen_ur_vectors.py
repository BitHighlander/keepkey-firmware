#!/usr/bin/env python3
"""Regenerate unittests/firmware/uniswap_ur_vectors.h from real Universal Router calls.

An independent Python decoder (no shared code with lib/firmware/uniswap_ur.c): the
C unit tests pass only when the two implementations agree on real calldata.

  gen_ur_vectors.py fetch DIR        # save recent Base router txs (base.blockscout.com) into DIR
  gen_ur_vectors.py header DIR > unittests/firmware/uniswap_ur_vectors.h
  gen_ur_vectors.py pack DIR > unittests/firmware/uniswap_ur_sample.bin
"""
import glob, json, os, sys, urllib.request

# UR 2.0, UR 1.2, and UR 2.1.2 (the router the Uniswap app sends to on Base).
ROUTERS = ["0x6fF5693b99212Da76ad316178A184AB56D299b43", "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
           "0xd6145b2D3F379919E8CdEda7B97e37c4b2Ca9c40"]
KIND = {0x00: 'UR_V3_SWAP_EXACT_IN', 0x01: 'UR_V3_SWAP_EXACT_OUT', 0x0a: 'UR_PERMIT2_PERMIT',
        0x0b: 'UR_WRAP_ETH', 0x0c: 'UR_UNWRAP_WETH', 0x04: 'UR_SWEEP',
        0x06: 'UR_PAY_PORTION', 0x08: 'UR_V2_SWAP_EXACT_IN', 0x09: 'UR_V2_SWAP_EXACT_OUT'}


def w(b, i):
    return int.from_bytes(b[i:i + 32], 'big')


def dyn(b, base, off):
    o = base + off
    n = w(b, o)
    return b[o + 32:o + 32 + n]


def decode(raw):
    """[(cmd, fields...)] for an execute(bytes,bytes[],uint256) call."""
    b = bytes.fromhex(raw[10:])
    cmds = dyn(b, 0, w(b, 0))
    arr = w(b, 32)
    out = []
    for k in range(w(b, arr)):
        inp = dyn(b, arr + 32, w(b, arr + 32 + 32 * k))
        c = cmds[k] & 0x3f
        if c in (0x00, 0x01):
            path = dyn(inp, 0, w(inp, 96))
            toks = [path[0:20].hex()] + [path[i + 3:i + 23].hex() for i in range(20, len(path) - 22, 23)]
            if c == 0x01:
                toks = toks[::-1]
            out.append((c, toks[0], toks[-1], w(inp, 32), w(inp, 64)))
        elif c == 0x0a:
            out.append((c, inp[12:32].hex(), '', w(inp, 32), None))
        elif c in (0x0b, 0x0c):
            out.append((c, '', '', w(inp, 32), None))
        elif c in (0x08, 0x09):
            # (recipient, amount, limit, address[] path, payerIsUser); the V2
            # path runs input -> output for both directions.
            o = w(inp, 96)
            n = w(inp, o)
            path = [inp[o + 32 + 32 * j + 12:o + 64 + 32 * j].hex() for j in range(n)]
            out.append((c, path[0], path[-1], w(inp, 32), w(inp, 64)))
        elif c in (0x04, 0x06):
            # SWEEP (token, recipient, amountMin); PAY_PORTION (token, recipient, bips)
            out.append((c, inp[12:32].hex(), '', w(inp, 64), None))
        else:
            out.append((c,))
    return out


def fetch(d, pages=8):
    """Save `pages` explorer pages (50 txs each) per router as DIR/<router>-<n>.json."""
    import urllib.parse
    os.makedirs(d, exist_ok=True)
    for r in ROUTERS:
        params = {'filter': 'to'}
        for n in range(pages):
            url = 'https://base.blockscout.com/api/v2/addresses/%s/transactions?%s' % (r, urllib.parse.urlencode(params))
            req = urllib.request.Request(url, headers={'user-agent': 'keepkey-ur-vectors/1'})
            body = urllib.request.urlopen(req, timeout=30).read()
            open(os.path.join(d, '%s-%d.json' % (r, n)), 'wb').write(body)
            nxt = json.loads(body).get('next_page_params')
            if not nxt:
                break
            params = dict(nxt, filter='to')


# Pinned: signed_metadata.cpp builds its end-to-end review on the first; the
# second is a Permit2 swap between reviewed Base tokens (USDC -> USDbC) that
# KeepKey Desktop's certified-attach tests need.
ALWAYS = ('0xd873988f8c2a7ef53ce52a0bc890a029e0bde5e731ad30c17e4991fb080dbbab',
          '0x81fa9e1f87d0b269986082edbdaebbf6c0b005918f389f6762601b47139d27e1')


def header(d, limit=250, v4_limit=10):
    """Deterministic subset: pinned calls, then app-shaped (permit/wrap), then the rest."""
    ok, v4, seen = [], [], set()
    for f in sorted(glob.glob(os.path.join(d, '0x*.json'))):
        for it in json.load(open(f)).get('items', []):
            raw, h = it.get('raw_input') or '', it.get('hash')
            if not raw.startswith(('0x3593564c', '0x24856bc3')) or h in seen:
                continue
            seen.add(h)
            steps = decode(raw)
            if any(s[0] == 0x10 for s in steps):
                v4.append(raw)
            elif all(s[0] in KIND for s in steps):
                ok.append((h, (it.get('to') or {}).get('hash', '').lower()[2:], int(it.get('value') or 0), raw, steps))
    def rank(v):
        app = any(st[0] in (0x0a, 0x0b) for st in v[4])
        rare = any(st[0] in (0x04, 0x06, 0x08, 0x09) for st in v[4])
        return (v[0] not in ALWAYS, not rare, not app, v[0])
    ok = sorted(ok, key=rank)[:limit]
    v4 = sorted(v4)[:v4_limit]
    p = print
    p('// Generated from real Base Universal Router calls (base.blockscout.com, 2026-10-03)')
    p('// by an independent Python decoder (scripts/uniswap/gen_ur_vectors.py). Do not regenerate')
    p('// from the C decoder: the point is two implementations agreeing.')
    p('#include <cstdint>\n#include <string>\n#include <vector>\nnamespace urv {')
    p('struct Step { int kind; std::string token_in, token_out, amount, limit; };')
    p('struct Vec { std::string tx, router, value, calldata; std::vector<Step> steps; };')
    p('inline const std::vector<Vec>& accepted() { static const std::vector<Vec> v = {')
    for h, to, val, raw, steps in ok:
        out = []
        for s in steps:
            lim = '' if s[4] is None else '%064x' % s[4]
            out.append('{%s,"%s","%s","%064x","%s"}' % (KIND[s[0]], s[1], s[2], s[3], lim))
        p('  {"%s", "%s", "%064x", "%s", {%s}},' % (h, to, val, raw[2:], ','.join(out)))
    p('}; return v; }')
    p('inline const std::vector<std::string>& v4_rejected() { static const std::vector<std::string> v = {')
    for raw in v4:
        p('  "%s",' % raw[2:])
    p('}; return v; }\n}  // namespace urv')


def pack(d):
    """Every execute() call in DIR as compact binary records, sorted by tx hash:
    hash(32) | status(1: 1 ok, 0 reverted) | length(4, big-endian) | calldata.
    The differential test (uniswap_ur.cpp) and v4_classify.py read it."""
    recs = {}
    for f in glob.glob(os.path.join(d, '0x*.json')):
        for it in json.load(open(f)).get('items', []):
            raw = it.get('raw_input') or ''
            if raw.startswith(('0x3593564c', '0x24856bc3')):
                recs[it['hash'].lower()] = (it.get('status') == 'ok', bytes.fromhex(raw[2:]))
    out = sys.stdout.buffer
    for h in sorted(recs):
        ok, cd = recs[h]
        out.write(bytes.fromhex(h[2:]) + bytes([ok]) + len(cd).to_bytes(4, 'big') + cd)


if __name__ == '__main__':
    {'fetch': fetch, 'header': header, 'pack': pack}[sys.argv[1]](sys.argv[2])
